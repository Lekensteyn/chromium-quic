// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/general_loss_algorithm.h"

#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace {

// The minimum delay before a packet will be considered lost,
// regardless of SRTT.  Half of the minimum TLP, since the loss algorithm only
// triggers when a nack has been receieved for the packet.
static const size_t kMinLossDelayMs = 5;

// Default fraction of an RTT the algorithm waits before determining a packet is
// lost due to early retransmission by time based loss detection.
static const int kDefaultLossDelayFraction = 4;
// Default fraction of an RTT when doing adaptive loss detection.
static const int kDefaultAdaptiveLossDelayFraction = 16;

}  // namespace

GeneralLossAlgorithm::GeneralLossAlgorithm()
    : loss_type_(kNack),
      loss_detection_timeout_(QuicTime::Zero()),
      largest_sent_on_spurious_retransmit_(0),
      reordering_fraction_(kDefaultLossDelayFraction) {}

GeneralLossAlgorithm::GeneralLossAlgorithm(LossDetectionType loss_type)
    : loss_type_(loss_type),
      loss_detection_timeout_(QuicTime::Zero()),
      largest_sent_on_spurious_retransmit_(0),
      reordering_fraction_(loss_type == kAdaptiveTime
                               ? kDefaultAdaptiveLossDelayFraction
                               : kDefaultLossDelayFraction) {}

LossDetectionType GeneralLossAlgorithm::GetLossDetectionType() const {
  return loss_type_;
}

void GeneralLossAlgorithm::SetLossDetectionType(LossDetectionType loss_type) {
  loss_type_ = loss_type;
  if (loss_type_ == kAdaptiveTime) {
    reordering_fraction_ = kDefaultAdaptiveLossDelayFraction;
  }
}

// Uses nack counts to decide when packets are lost.
void GeneralLossAlgorithm::DetectLosses(
    const QuicUnackedPacketMap& unacked_packets,
    QuicTime time,
    const RttStats& rtt_stats,
    QuicPacketNumber largest_newly_acked,
    SendAlgorithmInterface::CongestionVector* packets_lost) {
  QuicPacketNumber largest_observed = unacked_packets.largest_observed();
  if (FLAGS_quic_loss_recovery_use_largest_acked) {
    largest_observed = largest_newly_acked;
  }
  loss_detection_timeout_ = QuicTime::Zero();
  QuicTime::Delta max_rtt = QuicTime::Delta::Max(
      FLAGS_quic_adaptive_loss_recovery ? rtt_stats.previous_srtt()
                                        : rtt_stats.smoothed_rtt(),
      rtt_stats.latest_rtt());
  QuicTime::Delta loss_delay =
      QuicTime::Delta::Max(QuicTime::Delta::FromMilliseconds(kMinLossDelayMs),
                           max_rtt.Multiply(1 + 1.0f / reordering_fraction_));
  QuicPacketNumber packet_number = unacked_packets.GetLeastUnacked();
  for (QuicUnackedPacketMap::const_iterator it = unacked_packets.begin();
       it != unacked_packets.end() && packet_number <= largest_observed;
       ++it, ++packet_number) {
    if (!it->in_flight) {
      continue;
    }

    if (FLAGS_quic_simplify_loss_detection && loss_type_ == kNack) {
      // FACK based loss detection.
      if (largest_observed - packet_number >=
          kNumberOfNacksBeforeRetransmission) {
        packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
        continue;
      }
    }

    // Only early retransmit(RFC5827) when the last packet gets acked and
    // there are retransmittable packets in flight.
    // This also implements a timer-protected variant of FACK.
    if ((FLAGS_quic_simplify_loss_detection &&
         !it->retransmittable_frames.empty() &&
         unacked_packets.largest_sent_packet() == largest_observed) ||
        (loss_type_ == kTime || loss_type_ == kAdaptiveTime)) {
      QuicTime when_lost = it->sent_time.Add(loss_delay);
      if (time < when_lost) {
        loss_detection_timeout_ = when_lost;
        break;
      }
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }
    if (!FLAGS_quic_simplify_loss_detection) {
      // FACK based loss detection.
      QUIC_BUG_IF(it->nack_count == 0 && it->sent_time.IsInitialized())
          << "All packets less than largest observed should have been nacked."
          << " packet_number:" << packet_number
          << " largest_observed:" << largest_observed;
      if (it->nack_count >= kNumberOfNacksBeforeRetransmission) {
        packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
        continue;
      }
    }

    // NACK-based loss detection allows for a max reordering window of 1 RTT.
    if (it->sent_time.Add(rtt_stats.smoothed_rtt()) <
        unacked_packets.GetTransmissionInfo(largest_observed).sent_time) {
      packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      continue;
    }

    if (!FLAGS_quic_simplify_loss_detection &&
        !it->retransmittable_frames.empty() &&
        unacked_packets.largest_sent_packet() == largest_observed) {
      // Early retransmit marks the packet as lost once 1.25RTTs have passed
      // since the packet was sent and otherwise sets an alarm.
      if (time >= it->sent_time.Add(loss_delay)) {
        packets_lost->push_back(std::make_pair(packet_number, it->bytes_sent));
      } else {
        // Set the timeout for the earliest retransmittable packet where early
        // retransmit applies.
        loss_detection_timeout_ = it->sent_time.Add(loss_delay);
        break;
      }
    }
  }
}

QuicTime GeneralLossAlgorithm::GetLossTimeout() const {
  return loss_detection_timeout_;
}

void GeneralLossAlgorithm::SpuriousRetransmitDetected(
    const QuicUnackedPacketMap& unacked_packets,
    QuicTime time,
    const RttStats& rtt_stats,
    QuicPacketNumber spurious_retransmission) {
  if (loss_type_ != kAdaptiveTime || reordering_fraction_ == 1) {
    return;
  }
  if (spurious_retransmission <= largest_sent_on_spurious_retransmit_) {
    return;
  }
  largest_sent_on_spurious_retransmit_ = unacked_packets.largest_sent_packet();
  // Calculate the extra time needed so this wouldn't have been declared lost.
  // Extra time needed is based on how long it's been since the spurious
  // retransmission was sent, because the SRTT and latest RTT may have changed.
  QuicTime::Delta extra_time_needed = time.Subtract(
      unacked_packets.GetTransmissionInfo(spurious_retransmission).sent_time);
  // Increase the reordering fraction until enough time would be allowed.
  QuicTime::Delta max_rtt =
      QuicTime::Delta::Max(rtt_stats.previous_srtt(), rtt_stats.latest_rtt());
  QuicTime::Delta proposed_extra_time(QuicTime::Delta::Zero());
  do {
    proposed_extra_time = max_rtt.Multiply(1.0f / reordering_fraction_);
    reordering_fraction_ >>= 1;
  } while (proposed_extra_time < extra_time_needed && reordering_fraction_ > 1);
}

}  // namespace net
