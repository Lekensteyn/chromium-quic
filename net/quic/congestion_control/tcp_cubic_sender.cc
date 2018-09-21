// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/tcp_cubic_sender.h"

#include <algorithm>

#include "base/metrics/histogram.h"
#include "net/quic/congestion_control/rtt_stats.h"

using std::max;
using std::min;

namespace net {

namespace {
// Constants based on TCP defaults.
// The minimum cwnd based on RFC 3782 (TCP NewReno) for cwnd reductions on a
// fast retransmission.  The cwnd after a timeout is still 1.
const QuicTcpCongestionWindow kMinimumCongestionWindow = 2;
const int64 kHybridStartLowWindow = 16;
const QuicByteCount kMaxSegmentSize = kDefaultTCPMSS;
const QuicByteCount kDefaultReceiveWindow = 64000;
const int64 kInitialCongestionWindow = 10;
const int kMaxBurstLength = 3;
};  // namespace

TcpCubicSender::TcpCubicSender(
    const QuicClock* clock,
    const RttStats* rtt_stats,
    bool reno,
    QuicTcpCongestionWindow max_tcp_congestion_window,
    QuicConnectionStats* stats)
    : hybrid_slow_start_(clock),
      cubic_(clock, stats),
      rtt_stats_(rtt_stats),
      reno_(reno),
      congestion_window_count_(0),
      receive_window_(kDefaultReceiveWindow),
      bytes_in_flight_(0),
      prr_out_(0),
      prr_delivered_(0),
      ack_count_since_loss_(0),
      bytes_in_flight_before_loss_(0),
      update_end_sequence_number_(true),
      end_sequence_number_(0),
      largest_sent_sequence_number_(0),
      largest_acked_sequence_number_(0),
      largest_sent_at_last_cutback_(0),
      congestion_window_(kInitialCongestionWindow),
      slowstart_threshold_(max_tcp_congestion_window),
      max_tcp_congestion_window_(max_tcp_congestion_window) {
}

TcpCubicSender::~TcpCubicSender() {
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.FinalTcpCwnd", congestion_window_);
}

void TcpCubicSender::SetFromConfig(const QuicConfig& config, bool is_server) {
  if (is_server) {
    // Set the initial window size.
    congestion_window_ = config.server_initial_congestion_window();
  }
}

void TcpCubicSender::OnIncomingQuicCongestionFeedbackFrame(
    const QuicCongestionFeedbackFrame& feedback,
    QuicTime feedback_receive_time) {
  receive_window_ = feedback.tcp.receive_window;
}

void TcpCubicSender::OnPacketAcked(
    QuicPacketSequenceNumber acked_sequence_number, QuicByteCount acked_bytes) {
  DCHECK_GE(bytes_in_flight_, acked_bytes);
  bytes_in_flight_ -= acked_bytes;
  prr_delivered_ += acked_bytes;
  ++ack_count_since_loss_;
  largest_acked_sequence_number_ = max(acked_sequence_number,
                                       largest_acked_sequence_number_);
  MaybeIncreaseCwnd(acked_sequence_number);
  if (end_sequence_number_ == acked_sequence_number) {
    DVLOG(1) << "Start update end sequence number @" << acked_sequence_number;
    update_end_sequence_number_ = true;
  }
}

void TcpCubicSender::OnPacketLost(QuicPacketSequenceNumber sequence_number,
                                  QuicTime /*ack_receive_time*/) {
  // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
  // already sent should be treated as a single loss event, since it's expected.
  if (sequence_number <= largest_sent_at_last_cutback_) {
    DVLOG(1) << "Ignoring loss for largest_missing:" << sequence_number
             << " because it was sent prior to the last CWND cutback.";
    return;
  }

  // Initialize proportional rate reduction(RFC 6937) variables.
  prr_out_ = 0;
  bytes_in_flight_before_loss_ = bytes_in_flight_;
  // Since all losses are triggered by an incoming ack currently, and acks are
  // registered before losses by the SentPacketManager, initialize the variables
  // as though one ack was received directly after the loss.  This is too low
  // for stretch acks, but we expect missing packets to be immediately acked.
  // This ensures 1 or 2 packets are immediately able to be sent, depending upon
  // whether we're in PRR or PRR-SSRB mode.
  prr_delivered_ = kMaxPacketSize;
  ack_count_since_loss_ = 1;

  // In a normal TCP we would need to know the lowest missing packet to detect
  // if we receive 3 missing packets. Here we get a missing packet for which we
  // enter TCP Fast Retransmit immediately.
  if (reno_) {
    congestion_window_ = congestion_window_ >> 1;
  } else {
    congestion_window_ =
        cubic_.CongestionWindowAfterPacketLoss(congestion_window_);
  }
  slowstart_threshold_ = congestion_window_;
  // Enforce TCP's minimimum congestion window of 2*MSS.
  if (congestion_window_ < kMinimumCongestionWindow) {
    congestion_window_ = kMinimumCongestionWindow;
  }
  largest_sent_at_last_cutback_ = largest_sent_sequence_number_;
  // reset packet count from congestion avoidance mode. We start
  // counting again when we're out of recovery.
  congestion_window_count_ = 0;
  DVLOG(1) << "Incoming loss; congestion window: " << congestion_window_
           << " slowstart threshold: " << slowstart_threshold_;
}

bool TcpCubicSender::OnPacketSent(QuicTime /*sent_time*/,
                                  QuicPacketSequenceNumber sequence_number,
                                  QuicByteCount bytes,
                                  HasRetransmittableData is_retransmittable) {
  // Only update bytes_in_flight_ for data packets.
  if (is_retransmittable != HAS_RETRANSMITTABLE_DATA) {
    return false;
  }

  bytes_in_flight_ += bytes;
  prr_out_ += bytes;
  if (largest_sent_sequence_number_ < sequence_number) {
    // TODO(rch): Ensure that packets are really sent in order.
    // DCHECK_LT(largest_sent_sequence_number_, sequence_number);
    largest_sent_sequence_number_ = sequence_number;
  }
  if (update_end_sequence_number_) {
    end_sequence_number_ = sequence_number;
    if (AvailableSendWindow() == 0) {
      update_end_sequence_number_ = false;
      DVLOG(1) << "Stop update end sequence number @" << sequence_number;
    }
  }
  return true;
}

void TcpCubicSender::OnPacketAbandoned(QuicPacketSequenceNumber sequence_number,
                                       QuicByteCount abandoned_bytes) {
  DCHECK_GE(bytes_in_flight_, abandoned_bytes);
  bytes_in_flight_ -= abandoned_bytes;
}

QuicTime::Delta TcpCubicSender::TimeUntilSend(
    QuicTime /* now */,
    HasRetransmittableData has_retransmittable_data) {
  if (has_retransmittable_data == NO_RETRANSMITTABLE_DATA) {
    // For TCP we can always send an ACK immediately.
    // We also allow tail loss probes to be sent immediately, in keeping with
    // tail loss probe (draft-dukkipati-tcpm-tcp-loss-probe-01).
    return QuicTime::Delta::Zero();
  }
  if (AvailableSendWindow() > 0) {
    // During PRR-SSRB, limit outgoing packets to 1 extra MSS per ack, instead
    // of sending the entire available window. This prevents burst retransmits
    // when more packets are lost than the CWND reduction.
    //   limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
    if (InRecovery() &&
        prr_delivered_ + ack_count_since_loss_ * kMaxSegmentSize < prr_out_) {
      return QuicTime::Delta::Infinite();
    }
    return QuicTime::Delta::Zero();
  }
  // Implement Proportional Rate Reduction (RFC6937)
  // Checks a simplified version of the PRR formula that doesn't use division:
  // AvailableSendWindow =
  //   CEIL(prr_delivered * ssthresh / BytesInFlightAtLoss) - prr_sent
  if (InRecovery() &&
      prr_delivered_ * slowstart_threshold_ * kMaxSegmentSize >
          prr_out_ * bytes_in_flight_before_loss_) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::Infinite();
}

QuicByteCount TcpCubicSender::AvailableSendWindow() {
  if (bytes_in_flight_ > SendWindow()) {
    return 0;
  }
  return SendWindow() - bytes_in_flight_;
}

QuicByteCount TcpCubicSender::SendWindow() {
  // What's the current send window in bytes.
  return min(receive_window_, GetCongestionWindow());
}

QuicBandwidth TcpCubicSender::BandwidthEstimate() const {
  return QuicBandwidth::FromBytesAndTimeDelta(GetCongestionWindow(),
                                              rtt_stats_->SmoothedRtt());
}

QuicTime::Delta TcpCubicSender::RetransmissionDelay() const {
  if (!rtt_stats_->HasUpdates()) {
    return QuicTime::Delta::Zero();
  }
  return QuicTime::Delta::FromMicroseconds(
      rtt_stats_->SmoothedRtt().ToMicroseconds() +
      4 * rtt_stats_->mean_deviation().ToMicroseconds());
}

QuicByteCount TcpCubicSender::GetCongestionWindow() const {
  return congestion_window_ * kMaxSegmentSize;
}

bool TcpCubicSender::IsCwndLimited() const {
  const QuicByteCount congestion_window_bytes = congestion_window_ *
      kMaxSegmentSize;
  if (bytes_in_flight_ >= congestion_window_bytes) {
    return true;
  }
  const QuicByteCount tcp_max_burst = kMaxBurstLength * kMaxSegmentSize;
  const QuicByteCount left = congestion_window_bytes - bytes_in_flight_;
  return left <= tcp_max_burst;
}

bool TcpCubicSender::InRecovery() const {
  return largest_acked_sequence_number_ <= largest_sent_at_last_cutback_ &&
      largest_acked_sequence_number_ != 0;
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
void TcpCubicSender::MaybeIncreaseCwnd(
    QuicPacketSequenceNumber acked_sequence_number) {
  if (!IsCwndLimited()) {
    // We don't update the congestion window unless we are close to using the
    // window we have available.
    return;
  }
  if (acked_sequence_number <= largest_sent_at_last_cutback_) {
    // We don't increase the congestion window during recovery.
    return;
  }
  if (congestion_window_ < slowstart_threshold_) {
    // Slow start.
    if (hybrid_slow_start_.EndOfRound(acked_sequence_number)) {
      hybrid_slow_start_.Reset(end_sequence_number_);
    }
    // congestion_window_cnt is the number of acks since last change of snd_cwnd
    if (congestion_window_ < max_tcp_congestion_window_) {
      // TCP slow start, exponential growth, increase by one for each ACK.
      ++congestion_window_;
    }
    DVLOG(1) << "Slow start; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
    return;
  }
  if (congestion_window_ >= max_tcp_congestion_window_) {
    return;
  }
  // Congestion avoidance
  if (reno_) {
    // Classic Reno congestion avoidance provided for testing.

    ++congestion_window_count_;
    if (congestion_window_count_ >= congestion_window_) {
      ++congestion_window_;
      congestion_window_count_ = 0;
    }

    DVLOG(1) << "Reno; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_
             << " congestion window count: " << congestion_window_count_;
  } else {
    congestion_window_ = min(max_tcp_congestion_window_,
                             cubic_.CongestionWindowAfterAck(
                                 congestion_window_, rtt_stats_->min_rtt()));
    DVLOG(1) << "Cubic; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
  }
}

void TcpCubicSender::OnRetransmissionTimeout(bool packets_retransmitted) {
  bytes_in_flight_ = 0;
  largest_sent_at_last_cutback_ = 0;
  if (packets_retransmitted) {
    cubic_.Reset();
    congestion_window_ = kMinimumCongestionWindow;
  }
}

void TcpCubicSender::UpdateRtt(QuicTime::Delta rtt) {
  // Hybrid start triggers when cwnd is larger than some threshold.
  if (congestion_window_ <= slowstart_threshold_ &&
      congestion_window_ >= kHybridStartLowWindow) {
    if (!hybrid_slow_start_.started()) {
      // Time to start the hybrid slow start.
      hybrid_slow_start_.Reset(end_sequence_number_);
    }
    hybrid_slow_start_.Update(rtt, rtt_stats_->min_rtt());
    if (hybrid_slow_start_.Exit()) {
      slowstart_threshold_ = congestion_window_;
    }
  }
}

}  // namespace net
