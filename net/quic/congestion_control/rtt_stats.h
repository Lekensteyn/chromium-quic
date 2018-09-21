// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A convenience class to store rtt samples and calculate smoothed rtt.

#ifndef NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_
#define NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_

#include <algorithm>

#include "base/basictypes.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class NET_EXPORT_PRIVATE RttStats {
 public:
  RttStats();

  // Returns true if any RTT measurements have been made.
  bool HasUpdates() const;

  // Updates the RTT from an incoming ack which is received |send_delta| after
  // the packet is sent and the peer reports the ack being delayed |ack_delay|.
  void UpdateRtt(QuicTime::Delta send_delta, QuicTime::Delta ack_delay);

  // Forces RttStats to sample a new recent min rtt within the next
  // |num_samples| UpdateRtt calls.
  void SampleNewRecentMinRtt(uint32 num_samples);

  QuicTime::Delta SmoothedRtt() const;

  int64 initial_rtt_us() const {
    return initial_rtt_us_;
  }

  // Sets an initial RTT to be used for SmoothedRtt before any RTT updates.
  void set_initial_rtt_us(int64 initial_rtt_us) {
    initial_rtt_us_ = initial_rtt_us;
  }

  QuicTime::Delta latest_rtt() const {
    return latest_rtt_;
  }

  // Returns the min_rtt for the entire connection.
  QuicTime::Delta min_rtt() const {
    return min_rtt_;
  }

  // Returns the min_rtt since SampleNewRecentMinRtt has been called, or the
  // min_rtt for the entire connection if SampleNewMinRtt was never called.
  QuicTime::Delta recent_min_rtt() const {
    return recent_min_rtt_;
  }

  QuicTime::Delta mean_deviation() const {
    return mean_deviation_;
  }

 private:
  QuicTime::Delta latest_rtt_;
  QuicTime::Delta min_rtt_;
  QuicTime::Delta recent_min_rtt_;
  QuicTime::Delta smoothed_rtt_;
  // Mean RTT deviation during this session.
  // Approximation of standard deviation, the error is roughly 1.25 times
  // larger than the standard deviation, for a normally distributed signal.
  QuicTime::Delta mean_deviation_;
  int64 initial_rtt_us_;

  QuicTime::Delta new_min_rtt_;
  uint32 num_min_rtt_samples_remaining_;

  DISALLOW_COPY_AND_ASSIGN(RttStats);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_RTT_STATS_H_
