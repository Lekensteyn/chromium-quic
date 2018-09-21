// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/congestion_control/fix_rate_receiver.h"
#include "net/quic/congestion_control/fix_rate_sender.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/quic_protocol.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {
  const int rtt_us = 30000;
}

namespace net {

class FixRateTest : public ::testing::Test {
 protected:
  void SetUp() {
    sender_.reset(new FixRateSender(&clock_));
    receiver_.reset(new FixRateReceiver());
    clock_.AdvanceTime(0.002);  // Make sure clock does not start at 0.
  }
  MockClock clock_;
  scoped_ptr<FixRateSender> sender_;
  scoped_ptr<FixRateReceiver> receiver_;
};

TEST_F(FixRateTest, ReceiverAPI) {
  CongestionInfo info;
  receiver_->SetBitrate(300000);  // Bytes per second.
  receiver_->RecordIncomingPacket(1, 1, 1, false);
  ASSERT_TRUE(receiver_->GenerateCongestionInfo(&info));
  EXPECT_EQ(kFixRate, info.type);
  EXPECT_EQ(300000u, info.fix_rate.bitrate_in_bytes_per_second);
}

TEST_F(FixRateTest, SenderAPI) {
  CongestionInfo info;
  info.type = kFixRate;
  info.fix_rate.bitrate_in_bytes_per_second = 300000;
  sender_->OnIncomingCongestionInfo(info);
  EXPECT_EQ(300000, sender_->BandwidthEstimate());
  EXPECT_EQ(0, sender_->TimeUntilSend(false));
  EXPECT_EQ(kMaxPacketSize * 2, sender_->AvailableCongestionWindow());
  sender_->SentPacket(1, kMaxPacketSize, false);
  EXPECT_EQ(3000-kMaxPacketSize, sender_->AvailableCongestionWindow());
  EXPECT_EQ(0, sender_->TimeUntilSend(false));
  sender_->SentPacket(2, kMaxPacketSize, false);
  sender_->SentPacket(3, 600, false);
  EXPECT_EQ(10000, sender_->TimeUntilSend(false));
  EXPECT_EQ(0u, sender_->AvailableCongestionWindow());
  clock_.AdvanceTime(0.002);
  EXPECT_EQ(kUnknownWaitTime, sender_->TimeUntilSend(false));
  clock_.AdvanceTime(0.008);
  sender_->OnIncomingAck(1, kMaxPacketSize, rtt_us);
  sender_->OnIncomingAck(2, kMaxPacketSize, rtt_us);
  sender_->OnIncomingAck(3, 600, rtt_us);
  EXPECT_EQ(0, sender_->TimeUntilSend(false));
}

TEST_F(FixRateTest, FixRatePacing) {
  const int packet_size = 1200;
  CongestionInfo info;
  receiver_->SetBitrate(240000);  // Bytes per second.
  ASSERT_TRUE(receiver_->GenerateCongestionInfo(&info));
  sender_->OnIncomingCongestionInfo(info);
  double acc_advance_time = 0.0;
  QuicPacketSequenceNumber sequence_number = 0;
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(0, sender_->TimeUntilSend(false));
    EXPECT_EQ(kMaxPacketSize * 2u, sender_->AvailableCongestionWindow());
    sender_->SentPacket(sequence_number++, packet_size, false);
    EXPECT_EQ(0, sender_->TimeUntilSend(false));
    sender_->SentPacket(sequence_number++, packet_size, false);
    double advance_time = sender_->TimeUntilSend(false) / 1000000.0;
    clock_.AdvanceTime(advance_time);
    sender_->OnIncomingAck(sequence_number - 1, packet_size, rtt_us);
    sender_->OnIncomingAck(sequence_number - 2, packet_size, rtt_us);
    acc_advance_time += advance_time;
  }
  EXPECT_EQ(1000, floor((acc_advance_time * 1000) + 0.5));
}

}  // namespace net
