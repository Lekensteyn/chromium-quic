// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/general_loss_algorithm.h"

#include <algorithm>

#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_unacked_packet_map.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::vector;

namespace net {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class GeneralLossAlgorithmTest : public ::testing::Test {
 protected:
  GeneralLossAlgorithmTest() {
    rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                         QuicTime::Delta::Zero(), clock_.Now());
  }

  ~GeneralLossAlgorithmTest() override { STLDeleteElements(&packets_); }

  void SendDataPacket(QuicPacketNumber packet_number) {
    packets_.push_back(new QuicEncryptedPacket(nullptr, kDefaultLength));
    SerializedPacket packet(kDefaultPathId, packet_number,
                            PACKET_1BYTE_PACKET_NUMBER, packets_.back(), 0,
                            new RetransmittableFrames(), false, false);
    unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, clock_.Now(),
                                   1000, true);
  }

  void VerifyLosses(QuicPacketNumber largest_observed,
                    QuicPacketNumber* losses_expected,
                    size_t num_losses) {
    unacked_packets_.IncreaseLargestObserved(largest_observed);
    PacketNumberSet lost_packets = loss_algorithm_.DetectLostPackets(
        unacked_packets_, clock_.Now(), largest_observed, rtt_stats_);
    EXPECT_EQ(num_losses, lost_packets.size());
    for (size_t i = 0; i < num_losses; ++i) {
      EXPECT_TRUE(ContainsKey(lost_packets, losses_expected[i]));
    }
  }

  vector<QuicEncryptedPacket*> packets_;
  QuicUnackedPacketMap unacked_packets_;
  GeneralLossAlgorithm loss_algorithm_;
  RttStats rtt_stats_;
  MockClock clock_;
};

TEST_F(GeneralLossAlgorithmTest, NackRetransmit1Packet) {
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // No loss on one ack.
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.NackPacket(1, 1);
  VerifyLosses(2, nullptr, 0);
  // No loss on two acks.
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.NackPacket(1, 2);
  VerifyLosses(3, nullptr, 0);
  // Loss on three acks.
  unacked_packets_.RemoveFromInFlight(4);
  unacked_packets_.NackPacket(1, 3);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// A stretch ack is an ack that covers more than 1 packet of previously
// unacknowledged data.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketWith1StretchAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in a single StretchAck.
  unacked_packets_.NackPacket(1, 3);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// Ack a packet 3 packets ahead, causing a retransmit.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketSingleAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in an AckFrame with three missing packets.
  unacked_packets_.NackPacket(1, 3);
  unacked_packets_.NackPacket(2, 2);
  unacked_packets_.NackPacket(3, 1);
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmit1Packet) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.NackPacket(1, 1);
  VerifyLosses(2, nullptr, 0);
  EXPECT_EQ(clock_.Now().Add(rtt_stats_.smoothed_rtt().Multiply(1.25)),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(rtt_stats_.latest_rtt().Multiply(1.25));
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmitAllPackets) {
  const size_t kNumSentPackets = 5;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    // Advance the time 1/4 RTT between 3 and 4.
    if (i == 3) {
      clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.25));
    }
  }

  // Early retransmit when the final packet gets acked and 1.25 RTTs have
  // elapsed since the packets were sent.
  unacked_packets_.RemoveFromInFlight(kNumSentPackets);
  // This simulates a single ack following multiple missing packets with FACK.
  for (size_t i = 1; i < kNumSentPackets; ++i) {
    unacked_packets_.NackPacket(i, kNumSentPackets - i);
  }
  QuicPacketNumber lost[] = {1, 2};
  VerifyLosses(kNumSentPackets, lost, arraysize(lost));
  // The time has already advanced 1/4 an RTT, so ensure the timeout is set
  // 1.25 RTTs after the earliest pending packet(3), not the last(4).
  EXPECT_EQ(clock_.Now().Add(rtt_stats_.smoothed_rtt()),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  QuicPacketNumber lost2[] = {1, 2, 3};
  VerifyLosses(kNumSentPackets, lost2, arraysize(lost2));
  EXPECT_EQ(clock_.Now().Add(rtt_stats_.smoothed_rtt().Multiply(0.25)),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.25));
  QuicPacketNumber lost3[] = {1, 2, 3, 4};
  VerifyLosses(kNumSentPackets, lost3, arraysize(lost3));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, DontEarlyRetransmitNeuteredPacket) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // Neuter packet 1.
  unacked_packets_.RemoveRetransmittability(1);

  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.NackPacket(1, 1);
  VerifyLosses(2, nullptr, 0);
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, AlwaysLosePacketSent1RTTEarlier) {
  // Transmit 1 packet and then wait an rtt plus 1ms.
  SendDataPacket(1);
  clock_.AdvanceTime(
      rtt_stats_.smoothed_rtt().Add(QuicTime::Delta::FromMilliseconds(1)));

  // Transmit 2 packets.
  SendDataPacket(2);
  SendDataPacket(3);

  // Wait another RTT and ack 2.
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.NackPacket(1, 1);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
}

// Time-based loss detection tests.
TEST_F(GeneralLossAlgorithmTest, NoLossFor500Nacks) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  unacked_packets_.RemoveFromInFlight(2);
  for (size_t i = 1; i < 500; ++i) {
    unacked_packets_.NackPacket(1, i);
    VerifyLosses(2, nullptr, 0);
  }
  EXPECT_EQ(rtt_stats_.smoothed_rtt().Multiply(1.25),
            loss_algorithm_.GetLossTimeout().Subtract(clock_.Now()));
}

TEST_F(GeneralLossAlgorithmTest, NoLossUntilTimeout) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.1));
  }
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost until 1.25 RTTs pass.
  unacked_packets_.NackPacket(1, 1);
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  // Expect the timer to be set to 0.25 RTT's in the future.
  EXPECT_EQ(rtt_stats_.smoothed_rtt().Multiply(0.25),
            loss_algorithm_.GetLossTimeout().Subtract(clock_.Now()));
  unacked_packets_.NackPacket(1, 5);
  VerifyLosses(2, nullptr, 0);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.25));
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, NoLossWithoutNack) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.1));
  }
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost without a nack.
  unacked_packets_.RemoveFromInFlight(1);
  VerifyLosses(1, nullptr, 0);
  // The timer should still not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.25));
  VerifyLosses(1, nullptr, 0);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  VerifyLosses(1, nullptr, 0);

  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, MultipleLossesAtOnce) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at once and then go forward an RTT.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost until 1.25 RTTs pass.
  for (size_t i = 1; i < kNumSentPackets; ++i) {
    unacked_packets_.NackPacket(i, 1);
  }
  unacked_packets_.RemoveFromInFlight(10);
  VerifyLosses(10, nullptr, 0);
  // Expect the timer to be set to 0.25 RTT's in the future.
  EXPECT_EQ(rtt_stats_.smoothed_rtt().Multiply(0.25),
            loss_algorithm_.GetLossTimeout().Subtract(clock_.Now()));
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt().Multiply(0.25));
  QuicPacketNumber lost[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  VerifyLosses(10, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

}  // namespace
}  // namespace test
}  // namespace net
