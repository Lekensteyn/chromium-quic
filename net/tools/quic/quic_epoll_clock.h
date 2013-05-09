// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_EPOLL_CLOCK_H_
#define NET_TOOLS_QUIC_QUIC_EPOLL_CLOCK_H_

#include "base/compiler_specific.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_time.h"

namespace net {

class EpollServer;

namespace tools {

// Clock to efficiently retrieve an approximately accurate time from an
// EpollServer.
class QuicEpollClock : public QuicClock {
 public:
  explicit QuicEpollClock(EpollServer* epoll_server);
  virtual ~QuicEpollClock();

  // Returns the approximate current time as a QuicTime object.
  virtual QuicTime ApproximateNow() const OVERRIDE;

  // Returns the current time as a QuicTime object.
  // Note: this use significant resources please use only if needed.
  virtual QuicTime Now() const OVERRIDE;

  // WallNow returns the current wall-time - a time is consistent across
  // different clocks.
  virtual QuicWallTime WallNow() const OVERRIDE;

 protected:
  EpollServer* epoll_server_;
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_EPOLL_CLOCK_H_
