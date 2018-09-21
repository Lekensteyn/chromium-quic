// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/paced_sender.h"

#include "net/quic/quic_protocol.h"

namespace net {

// To prevent too aggressive pacing we allow the following packet burst size.
const int64 kMinPacketBurstSize = 2;
// Max estimated time between calls to TimeUntilSend and
// AvailableCongestionWindow.
const int64 kMaxSchedulingDelayUs = 2000;

PacedSender::PacedSender(const QuicClock* clock, QuicBandwidth estimate)
    : leaky_bucket_(clock, estimate),
      pace_(estimate) {
}

void PacedSender::UpdateBandwidthEstimate(QuicBandwidth estimate) {
  leaky_bucket_.SetDrainingRate(estimate);
  pace_ = estimate;
}

void PacedSender::SentPacket(QuicByteCount bytes) {
  leaky_bucket_.Add(bytes);
}

QuicTime::Delta PacedSender::TimeUntilSend(QuicTime::Delta time_until_send) {
  if (time_until_send.ToMicroseconds() >= kMaxSchedulingDelayUs) {
    return time_until_send;
  }
  // Pace the data.
  QuicByteCount pacing_window = pace_.ToBytesPerPeriod(
      QuicTime::Delta::FromMicroseconds(kMaxSchedulingDelayUs));
  QuicByteCount min_window_size = kMinPacketBurstSize *  kMaxPacketSize;
  pacing_window = std::max(pacing_window, min_window_size);

  if (pacing_window > leaky_bucket_.BytesPending()) {
    // We have not filled our pacing window yet.
    return time_until_send;
  }
  return leaky_bucket_.TimeRemaining();
}

QuicByteCount PacedSender::AvailableWindow(
    QuicByteCount available_congestion_window) {
  QuicByteCount accuracy_window = pace_.ToBytesPerPeriod(
      QuicTime::Delta::FromMicroseconds(kMaxSchedulingDelayUs));
  QuicByteCount min_burst_window = kMinPacketBurstSize * kMaxPacketSize;
  DLOG(INFO) << "Available congestion window:" << available_congestion_window
      << " accuracy window:" << accuracy_window
      << " min burst window:" << min_burst_window;

  // Should we limit the window to pace the data?
  if (available_congestion_window > min_burst_window &&
      available_congestion_window > accuracy_window) {
    // Max window depends on estimated bandwidth; higher bandwidth => larger
    // burst we also consider our timing accuracy. An accuracy of 1 ms will
    // allow us to send up to 19.2Mbit/s with 2 packets per burst.
    available_congestion_window = std::max(min_burst_window, accuracy_window);
    QuicByteCount bytes_pending = leaky_bucket_.BytesPending();
    if (bytes_pending > available_congestion_window) {
      return 0;
    }
    available_congestion_window -= bytes_pending;
  }
  return available_congestion_window;
}

}  // namespace net
