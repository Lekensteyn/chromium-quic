// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/fix_rate_sender.h"

#include <math.h>

#include "base/logging.h"
#include "base/time.h"
#include "net/quic/quic_protocol.h"

namespace {
  const int kInitialBitrate = 100000;  // In bytes per second.
  const uint64 kWindowSizeUs = 10000;  // 10 ms.
}

namespace net {

FixRateSender::FixRateSender(QuicClock* clock)
    : bitrate_in_bytes_per_s_(kInitialBitrate),
      fix_rate_leaky_bucket_(clock, kInitialBitrate),
      paced_sender_(clock, kInitialBitrate),
      bytes_in_flight_(0) {
  DLOG(INFO) << "FixRateSender";
}

void FixRateSender::OnIncomingCongestionInfo(
    const CongestionInfo& congestion_info) {
  DCHECK(congestion_info.type == kFixRate) <<
      "Invalid incoming CongestionFeedbackType:" << congestion_info.type;
  if (congestion_info.type == kFixRate) {
    bitrate_in_bytes_per_s_ =
        congestion_info.fix_rate.bitrate_in_bytes_per_second;
    fix_rate_leaky_bucket_.SetDrainingRate(bitrate_in_bytes_per_s_);
    paced_sender_.UpdateBandwidthEstimate(bitrate_in_bytes_per_s_);
  }
  // Silently ignore invalid messages in release mode.
}

void FixRateSender::OnIncomingAck(
    QuicPacketSequenceNumber /*acked_sequence_number*/,
    size_t bytes_acked, uint64 /*rtt_us*/) {
  bytes_in_flight_ -= bytes_acked;
}

void FixRateSender::OnIncomingLoss(int /*number_of_lost_packets*/) {
  // Ignore losses for fix rate sender.
}

void FixRateSender::SentPacket(QuicPacketSequenceNumber /*sequence_number*/,
                               size_t bytes,
                               bool retransmit) {
  fix_rate_leaky_bucket_.Add(bytes);
  paced_sender_.SentPacket(bytes);
  if (!retransmit) {
    bytes_in_flight_ += bytes;
  }
}

int FixRateSender::TimeUntilSend(bool /*retransmit*/) {
  if (CongestionWindow() > fix_rate_leaky_bucket_.BytesPending()) {
    if (CongestionWindow() <= bytes_in_flight_) {
      return kUnknownWaitTime;  // We need an ack before we send more.
    }
    return paced_sender_.TimeUntilSend(0);
  }
  uint64 time_remaining_us = fix_rate_leaky_bucket_.TimeRemaining();
  if (time_remaining_us == 0) {
    return kUnknownWaitTime;  // We need an ack before we send more.
  }
  return paced_sender_.TimeUntilSend(time_remaining_us);
}

size_t FixRateSender::CongestionWindow() {
  size_t window_size = bitrate_in_bytes_per_s_ * kWindowSizeUs /
      base::Time::kMicrosecondsPerSecond;
  // Make sure window size is not less than a packet.
  return std::max(kMaxPacketSize, window_size);
}

size_t FixRateSender::AvailableCongestionWindow() {
  size_t congestion_window = CongestionWindow();
  if (bytes_in_flight_ >= congestion_window) {
    return 0;
  }
  size_t available_congestion_window = congestion_window - bytes_in_flight_;
  return paced_sender_.AvailableWindow(available_congestion_window);
}

int FixRateSender::BandwidthEstimate() {
  return bitrate_in_bytes_per_s_;
}

}  // namespace net
