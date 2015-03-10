// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/mock_epoll_server.h"

namespace net {
namespace tools {
namespace test {

FakeTimeEpollServer::FakeTimeEpollServer(): now_in_usec_(0) {
}

FakeTimeEpollServer::~FakeTimeEpollServer() {
}

int64 FakeTimeEpollServer::NowInUsec() const {
  return now_in_usec_;
}

MockEpollServer::MockEpollServer() : until_in_usec_(-1) {
}

MockEpollServer::~MockEpollServer() {
}

int MockEpollServer::KernelWait(int timeout_in_ms) {
  int num_events = 0;
  int max_events = events_size_;
  struct epoll_event* events = events_;

  while (!event_queue_.empty() &&
         num_events < max_events &&
         event_queue_.begin()->first <= NowInUsec() &&
         ((until_in_usec_ == -1) ||
          (event_queue_.begin()->first < until_in_usec_))
        ) {
    int64 event_time_in_usec = event_queue_.begin()->first;
    events[num_events] = event_queue_.begin()->second;
    if (event_time_in_usec > NowInUsec()) {
      set_now_in_usec(event_time_in_usec);
    }
    event_queue_.erase(event_queue_.begin());
    ++num_events;
  }
  if (num_events == 0) {  // then we'd have waited 'till the timeout.
    if (until_in_usec_ < 0) {  // then we don't care what the final time is.
      if (timeout_in_ms > 0) {
        AdvanceBy(timeout_in_ms * 1000);
      }
    } else {  // except we assume that we don't wait for the timeout
      // period if until_in_usec_ is a positive number.
      set_now_in_usec(until_in_usec_);
      // And reset until_in_usec_ to signal no waiting (as
      // the AdvanceByExactly* stuff is meant to be one-shot,
      // as are all similar EpollServer functions)
      until_in_usec_ = -1;
    }
  }
  if (until_in_usec_ >= 0) {
    CHECK(until_in_usec_ >= NowInUsec());
  }
  return num_events;
}

// this is nearly a cut-and-paste from 'linux_epoll_server'
// except that since we never turned the abstract flag bits into
// their kernel-equivalent bits, we don't need to undo that.
void MockEpollServer::ScanKernelEvents(int nfds) {
  for (int i = 0; i < nfds; ++i) {
    HandleEvent(events_[i].data.fd, events_[i].events);
  }
}

}  // namespace test
}  // namespace tools
}  // namespace net
