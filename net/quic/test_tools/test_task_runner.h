// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Common utilities for Quic tests

#ifndef NET_QUIC_TEST_TOOLS_TEST_TASK_RUNNER_H_
#define NET_QUIC_TEST_TOOLS_TEST_TASK_RUNNER_H_

#include "base/task_runner.h"

#include <vector>

#include "base/time.h"

#include "base/stl_util.h"
#include "net/base/net_errors.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/socket/socket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace test {

struct PostedTask {
  PostedTask(const tracked_objects::Location& location,
             const base::Closure& closure,
             base::TimeDelta delta,
             base::TimeTicks time);
  ~PostedTask();

  tracked_objects::Location location;
  base::Closure closure;
  base::TimeDelta delta;
  base::TimeTicks time;
};

class TestTaskRunner : public base::TaskRunner {
 public:
  explicit TestTaskRunner(MockClock* clock);

  virtual bool RunsTasksOnCurrentThread() const OVERRIDE;
  virtual bool PostDelayedTask(const tracked_objects::Location& location,
                               const base::Closure& closure,
                               base::TimeDelta delta) OVERRIDE;

  std::vector<PostedTask>::iterator FindNextTask();

  void RunNextTask();

  std::vector<PostedTask>* tasks() {
    return &tasks_;
  }

  // Returns the nth task in the queue.
  PostedTask GetTask(size_t n);

 protected:
  virtual ~TestTaskRunner();

 private:
  MockClock* clock_;
  std::vector<PostedTask> tasks_;
  DISALLOW_COPY_AND_ASSIGN(TestTaskRunner);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_TEST_TASK_RUNNER_H_
