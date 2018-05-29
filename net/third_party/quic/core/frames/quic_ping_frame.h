// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_THIRD_PARTY_QUIC_CORE_FRAMES_QUIC_PING_FRAME_H_
#define NET_THIRD_PARTY_QUIC_CORE_FRAMES_QUIC_PING_FRAME_H_

#include "net/third_party/quic/core/frames/quic_control_frame.h"

namespace quic {

// A ping frame contains no payload, though it is retransmittable,
// and ACK'd just like other normal frames.
struct QUIC_EXPORT_PRIVATE QuicPingFrame : public QuicControlFrame {
  QuicPingFrame();
  explicit QuicPingFrame(QuicControlFrameId control_frame_id);

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os,
      const QuicPingFrame& ping_frame);
};

}  // namespace quic

#endif  // NET_THIRD_PARTY_QUIC_CORE_FRAMES_QUIC_PING_FRAME_H_
