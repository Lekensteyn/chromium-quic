// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_sent_packet_manager.h"

#include "base/stl_util.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::vector;
using testing::_;
using testing::Return;
using testing::StrictMock;

namespace net {
namespace test {
namespace {

class QuicSentPacketManagerTest : public ::testing::TestWithParam<bool> {
 protected:
  QuicSentPacketManagerTest()
      : manager_(true, &clock_, &stats_, kFixRate),
        send_algorithm_(new StrictMock<MockSendAlgorithm>) {
    QuicSentPacketManagerPeer::SetSendAlgorithm(&manager_, send_algorithm_);
    // Disable tail loss probes for most tests.
    QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 0);
    // Advance the time 1s so the send times are never QuicTime::Zero.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
  }

  virtual ~QuicSentPacketManagerTest() {
    STLDeleteElements(&packets_);
  }

  void VerifyUnackedPackets(QuicPacketSequenceNumber* packets,
                            size_t num_packets) {
    if (num_packets == 0) {
      EXPECT_FALSE(manager_.HasUnackedPackets());
      EXPECT_EQ(0u, manager_.GetNumRetransmittablePackets());
      return;
    }

    EXPECT_TRUE(manager_.HasUnackedPackets());
    EXPECT_EQ(packets[0], manager_.GetLeastUnackedSentPacket());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(manager_.IsUnacked(packets[i])) << packets[i];
    }
  }

  void VerifyRetransmittablePackets(QuicPacketSequenceNumber* packets,
                                    size_t num_packets) {
    SequenceNumberSet unacked = manager_.GetUnackedPackets();
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(ContainsKey(unacked, packets[i])) << packets[i];
    }
    size_t num_retransmittable = 0;
    for (SequenceNumberSet::const_iterator it = unacked.begin();
         it != unacked.end(); ++it) {
      if (manager_.HasRetransmittableFrames(*it)) {
        ++num_retransmittable;
      }
    }
    EXPECT_EQ(num_packets, manager_.GetNumRetransmittablePackets());
    EXPECT_EQ(num_packets, num_retransmittable);
  }

  void VerifyAckedPackets(QuicPacketSequenceNumber* expected,
                          size_t num_expected,
                          const SequenceNumberSet& actual) {
    if (num_expected == 0) {
      EXPECT_TRUE(actual.empty());
      return;
    }

    EXPECT_EQ(num_expected, actual.size());
    for (size_t i = 0; i < num_expected; ++i) {
      EXPECT_TRUE(ContainsKey(actual, expected[i])) << expected[i];
    }
  }

  void RetransmitPacket(QuicPacketSequenceNumber old_sequence_number,
                        QuicPacketSequenceNumber new_sequence_number) {
    QuicSentPacketManagerPeer::MarkForRetransmission(
        &manager_, old_sequence_number, NACK_RETRANSMISSION);
    EXPECT_TRUE(manager_.HasPendingRetransmissions());
    QuicSentPacketManager::PendingRetransmission next_retransmission =
        manager_.NextPendingRetransmission();
    EXPECT_EQ(old_sequence_number, next_retransmission.sequence_number);
    EXPECT_EQ(NACK_RETRANSMISSION, next_retransmission.transmission_type);
    manager_.OnRetransmittedPacket(old_sequence_number, new_sequence_number);
    EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(
        &manager_, new_sequence_number));
  }

  void RetransmitAndSendPacket(QuicPacketSequenceNumber old_sequence_number,
                               QuicPacketSequenceNumber new_sequence_number) {
    RetransmitPacket(old_sequence_number, new_sequence_number);
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, new_sequence_number, _, _, _))
        .WillOnce(Return(true));
    manager_.OnPacketSent(new_sequence_number, clock_.Now(),
                          1000, NACK_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA);
  }

  SerializedPacket CreateDataPacket(QuicPacketSequenceNumber sequence_number) {
    return CreatePacket(sequence_number, true);
  }

  SerializedPacket CreatePacket(QuicPacketSequenceNumber sequence_number,
                                bool retransmittable) {
    packets_.push_back(QuicPacket::NewDataPacket(
        NULL, 1000, false, PACKET_8BYTE_GUID, false,
        PACKET_6BYTE_SEQUENCE_NUMBER));
    return SerializedPacket(
        sequence_number, PACKET_6BYTE_SEQUENCE_NUMBER,
        packets_.back(), 0u,
        retransmittable ? new RetransmittableFrames() : NULL);
  }

  SerializedPacket CreateFecPacket(QuicPacketSequenceNumber sequence_number) {
    packets_.push_back(QuicPacket::NewFecPacket(
        NULL, 1000, false, PACKET_8BYTE_GUID, false,
        PACKET_6BYTE_SEQUENCE_NUMBER));
    return SerializedPacket(sequence_number, PACKET_6BYTE_SEQUENCE_NUMBER,
                            packets_.back(), 0u, NULL);
  }

  void SendDataPacket(QuicPacketSequenceNumber sequence_number) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, sequence_number, _, _, _))
                    .Times(1).WillOnce(Return(true));
    SerializedPacket packet(CreateDataPacket(sequence_number));
    manager_.OnSerializedPacket(packet);
    manager_.OnPacketSent(sequence_number, clock_.Now(),
                          packet.packet->length(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }

  void SendCryptoPacket(QuicPacketSequenceNumber sequence_number) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, sequence_number, _, _, _))
                    .Times(1).WillOnce(Return(true));
    SerializedPacket packet(CreateDataPacket(sequence_number));
    packet.retransmittable_frames->AddStreamFrame(
        new QuicStreamFrame(1, false, 0, IOVector()));
    manager_.OnSerializedPacket(packet);
    manager_.OnPacketSent(sequence_number, clock_.ApproximateNow(),
                          packet.packet->length(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }

  // Based on QuicConnection's WritePendingRetransmissions.
  void RetransmitNextPacket(
      QuicPacketSequenceNumber retransmission_sequence_number) {
    EXPECT_TRUE(manager_.HasPendingRetransmissions());
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, retransmission_sequence_number, _, _, _))
                    .Times(1).WillOnce(Return(true));
    const QuicSentPacketManager::PendingRetransmission pending =
        manager_.NextPendingRetransmission();
    manager_.OnRetransmittedPacket(
        pending.sequence_number, retransmission_sequence_number);
    manager_.OnPacketSent(retransmission_sequence_number,
                          clock_.ApproximateNow(), 1000,
                          pending.transmission_type, HAS_RETRANSMITTABLE_DATA);
  }

  QuicSentPacketManager manager_;
  vector<QuicPacket*> packets_;
  MockClock clock_;
  QuicConnectionStats stats_;
  MockSendAlgorithm* send_algorithm_;
};

TEST_F(QuicSentPacketManagerTest, IsUnacked) {
  VerifyUnackedPackets(NULL, 0);

  SerializedPacket serialized_packet(CreateDataPacket(1));

  manager_.OnSerializedPacket(serialized_packet);

  QuicPacketSequenceNumber unacked[] = { 1 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketSequenceNumber retransmittable[] = { 1 };
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, IsUnAckedRetransmit) {
  SendDataPacket(1);
  RetransmitPacket(1, 2);

  EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(&manager_, 2));
  QuicPacketSequenceNumber unacked[] = { 1, 2 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketSequenceNumber retransmittable[] = { 2 };
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Ack 2 but not 1.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 2;
  received_info.missing_packets.insert(1);
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(2, _)).Times(1);
  manager_.OnIncomingAck(received_info, QuicTime::Zero());

  // Packet 1 is unacked, pending, but not retransmittable.
  QuicPacketSequenceNumber unacked[] = { 1 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(NULL, 0);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckBeforeSend) {
  SendDataPacket(1);
  QuicSentPacketManagerPeer::MarkForRetransmission(
      &manager_, 1, NACK_RETRANSMISSION);
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  // Ack 1.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 1;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(1, _)).Times(1);
  manager_.OnIncomingAck(received_info, QuicTime::Zero());

  // There should no longer be a pending retransmission.
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // No unacked packets remain.
  VerifyUnackedPackets(NULL, 0);
  VerifyRetransmittablePackets(NULL, 0);
  EXPECT_EQ(0u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPrevious) {
  SendDataPacket(1);
  RetransmitPacket(1, 2);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(1, _));
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 1;
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  // 2 remains unacked, but no packets have retransmittable data.
  QuicPacketSequenceNumber unacked[] = { 2 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(NULL, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
  EXPECT_EQ(1u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPreviousThenNackRetransmit) {
  SendDataPacket(1);
  RetransmitPacket(1, 2);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, 2, _, _, _))
      .WillOnce(Return(true));
  manager_.OnPacketSent(2, clock_.ApproximateNow(), 1000,
                        NACK_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // First, ACK packet 1 which makes packet 2 non-retransmittable.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(1, _));
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 1;
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  SendDataPacket(3);
  SendDataPacket(4);
  SendDataPacket(5);
  clock_.AdvanceTime(rtt);

  // Next, NACK packet 2 three times.
  received_info.largest_observed = 3;
  received_info.missing_packets.insert(2);
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(3, _));
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  received_info.largest_observed = 4;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(4, _));
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  received_info.largest_observed = 5;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(5, _));
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(2, _));
  EXPECT_CALL(*send_algorithm_, OnPacketLost(2, _));
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  // No packets remain unacked.
  VerifyUnackedPackets(NULL, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(NULL, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, RetransmitTwiceThenAckPreviousBeforeSend) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Fire the RTO, which will mark 2 for retransmission (but will not send it).
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  // Ack 1 but not 2, before 2 is able to be sent.
  // Since 1 has been retransmitted, it has already been lost, and so the
  // send algorithm is not informed that it has been ACK'd.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 1;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(QuicTime::Delta::Zero()));
  EXPECT_TRUE(manager_.OnIncomingAck(received_info, clock_.ApproximateNow()));

  // Since 2 was marked for retransmit, when 1 is acked, 2 is discarded.
  VerifyUnackedPackets(NULL, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(NULL, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, RetransmitTwiceThenAckFirst) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2 or 3.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(1, _));
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 1;
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  // 2 and 3 remain unacked, but no packets have retransmittable data.
  QuicPacketSequenceNumber unacked[] = { 2, 3 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(NULL, 0);

  // Ensure packet 2 is lost when 4 and 5 are sent and acked.
  SendDataPacket(4);
  received_info.largest_observed = 4;
  received_info.missing_packets.insert(2);
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(3, _));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(4, _));
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  QuicPacketSequenceNumber unacked2[] = { 2 };
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  SendDataPacket(5);
  received_info.largest_observed = 5;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(5, _));
  EXPECT_CALL(*send_algorithm_, OnPacketLost(2, _));
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(2, _));
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  VerifyUnackedPackets(NULL, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  EXPECT_EQ(1u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, TruncatedAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  RetransmitAndSendPacket(3, 4);
  RetransmitAndSendPacket(4, 5);

  // Truncated ack with 4 NACKs, so the first packet is lost.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 4;
  received_info.missing_packets.insert(1);
  received_info.missing_packets.insert(2);
  received_info.missing_packets.insert(3);
  received_info.missing_packets.insert(4);
  received_info.is_truncated = true;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketLost(1, _));
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(1, _));
  manager_.OnIncomingAck(received_info, QuicTime::Zero());

  // High water mark will be raised.
  QuicPacketSequenceNumber unacked[] = { 2, 3, 4 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketSequenceNumber retransmittable[] = { 4 };
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, AckPreviousTransmissionThenTruncatedAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  RetransmitAndSendPacket(3, 4);
  manager_.OnSerializedPacket(CreateDataPacket(5));
  manager_.OnSerializedPacket(CreateDataPacket(6));
  manager_.OnSerializedPacket(CreateDataPacket(7));
  manager_.OnSerializedPacket(CreateDataPacket(8));
  manager_.OnSerializedPacket(CreateDataPacket(9));

  // Ack previous transmission
  {
    ReceivedPacketInfo received_info;
    received_info.largest_observed = 2;
    received_info.missing_packets.insert(1);
    EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
    EXPECT_CALL(*send_algorithm_, OnPacketAcked(2, _));
    manager_.OnIncomingAck(received_info, QuicTime::Zero());
    EXPECT_TRUE(manager_.IsUnacked(4));
  }

  // Truncated ack with 4 NACKs
  {
    ReceivedPacketInfo received_info;
    received_info.largest_observed = 6;
    received_info.missing_packets.insert(3);
    received_info.missing_packets.insert(4);
    received_info.missing_packets.insert(5);
    received_info.missing_packets.insert(6);
    received_info.is_truncated = true;
    EXPECT_CALL(*send_algorithm_, OnPacketAcked(1, _));
    EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(3, _));
    EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(4, _));
    manager_.OnIncomingAck(received_info, QuicTime::Zero());
  }

  // High water mark will be raised.
  QuicPacketSequenceNumber unacked[] = { 5, 6, 7, 8, 9 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketSequenceNumber retransmittable[] = { 5, 6, 7, 8, 9 };
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedSentPacket) {
  EXPECT_EQ(0u, manager_.GetLeastUnackedSentPacket());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedSentPacketUnacked) {
  SerializedPacket serialized_packet(CreateDataPacket(1));

  manager_.OnSerializedPacket(serialized_packet);
  EXPECT_EQ(1u, manager_.GetLeastUnackedSentPacket());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedSentPacketUnackedFec) {
  SerializedPacket serialized_packet(CreateFecPacket(1));

  manager_.OnSerializedPacket(serialized_packet);
  EXPECT_EQ(1u, manager_.GetLeastUnackedSentPacket());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedSentPacketDiscardUnacked) {
  SerializedPacket serialized_packet(CreateDataPacket(1));

  manager_.OnSerializedPacket(serialized_packet);
  manager_.DiscardUnackedPacket(1u);
  EXPECT_EQ(0u, manager_.GetLeastUnackedSentPacket());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedPacketAndDiscard) {
  VerifyUnackedPackets(NULL, 0);

  SerializedPacket serialized_packet(CreateFecPacket(1));
  manager_.OnSerializedPacket(serialized_packet);
  EXPECT_EQ(1u, manager_.GetLeastUnackedSentPacket());

  SerializedPacket serialized_packet2(CreateFecPacket(2));
  manager_.OnSerializedPacket(serialized_packet2);
  EXPECT_EQ(1u, manager_.GetLeastUnackedSentPacket());

  SerializedPacket serialized_packet3(CreateFecPacket(3));
  manager_.OnSerializedPacket(serialized_packet3);
  EXPECT_EQ(1u, manager_.GetLeastUnackedSentPacket());

  QuicPacketSequenceNumber unacked[] = { 1, 2, 3 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(NULL, 0);

  manager_.DiscardUnackedPacket(1);
  EXPECT_EQ(2u, manager_.GetLeastUnackedSentPacket());

  // Ack 2.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 2;
  manager_.OnIncomingAck(received_info, QuicTime::Zero());

  EXPECT_EQ(3u, manager_.GetLeastUnackedSentPacket());

  // Discard the 3rd packet and ensure there are no FEC packets.
  manager_.DiscardUnackedPacket(3);
  EXPECT_FALSE(manager_.HasUnackedPackets());
}

TEST_F(QuicSentPacketManagerTest, GetSentTime) {
  VerifyUnackedPackets(NULL, 0);

  SerializedPacket serialized_packet(CreateFecPacket(1));
  manager_.OnSerializedPacket(serialized_packet);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, 1, _, _, _))
                  .Times(1).WillOnce(Return(true));
  manager_.OnPacketSent(
      1, QuicTime::Zero(), 0, NOT_RETRANSMISSION, NO_RETRANSMITTABLE_DATA);

  SerializedPacket serialized_packet2(CreateFecPacket(2));
  QuicTime sent_time = QuicTime::Zero().Add(QuicTime::Delta::FromSeconds(1));
  manager_.OnSerializedPacket(serialized_packet2);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, 2, _, _, _))
                  .Times(1).WillOnce(Return(true));
  manager_.OnPacketSent(
      2, sent_time, 0, NOT_RETRANSMISSION, NO_RETRANSMITTABLE_DATA);

  QuicPacketSequenceNumber unacked[] = { 1, 2 };
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(NULL, 0);

  EXPECT_TRUE(manager_.HasUnackedPackets());
  EXPECT_EQ(QuicTime::Zero(),
            QuicSentPacketManagerPeer::GetSentTime(&manager_, 1));
  EXPECT_EQ(sent_time, QuicSentPacketManagerPeer::GetSentTime(&manager_, 2));
}

TEST_F(QuicSentPacketManagerTest, NackRetransmit1Packet) {
  const size_t kNumSentPackets = 4;
  // Transmit 4 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Nack the first packet 3 times with increasing largest observed.
  ReceivedPacketInfo received_info;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  received_info.missing_packets.insert(1);
  for (QuicPacketSequenceNumber i = 1; i <= 3; ++i) {
    received_info.largest_observed = i + 1;
    EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
    EXPECT_CALL(*send_algorithm_, OnPacketAcked(i + 1, _)).Times(1);
    if (i == 3) {
      EXPECT_CALL(*send_algorithm_, OnPacketLost(1, _)).Times(1);
      EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(1, _)).Times(1);
    }
    manager_.OnIncomingAck(received_info, clock_.Now());
    EXPECT_EQ(
        i == 3 ? 1u : 0u,
        QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
    EXPECT_EQ(i, QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  }
  EXPECT_EQ(1u, stats_.packets_lost);
}

// A stretch ack is an ack that covers more than 1 packet of previously
// unacknowledged data.
TEST_F(QuicSentPacketManagerTest, NackRetransmit1PacketWith1StretchAck) {
  const size_t kNumSentPackets = 4;
  // Transmit 4 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in a single StretchAck.
  ReceivedPacketInfo received_info;
  received_info.delta_time_largest_observed =
        QuicTime::Delta::FromMilliseconds(5);
  received_info.missing_packets.insert(1);
  received_info.largest_observed = kNumSentPackets;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(_, _)).Times(3);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(1, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(1, _)).Times(1);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(
      1u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  EXPECT_EQ(3u, QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  EXPECT_EQ(1u, stats_.packets_lost);
}

// Ack a packet 3 packets ahead, causing a retransmit.
TEST_F(QuicSentPacketManagerTest, NackRetransmit1PacketSingleAck) {
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in an AckFrame with three missing packets.
  ReceivedPacketInfo received_info;
  received_info.delta_time_largest_observed =
        QuicTime::Delta::FromMilliseconds(5);
  received_info.missing_packets.insert(1);
  received_info.missing_packets.insert(2);
  received_info.missing_packets.insert(3);
  received_info.largest_observed = 4;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(4, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(1, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(1, _)).Times(1);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(
      1u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  EXPECT_EQ(3u, QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  EXPECT_EQ(1u, stats_.packets_lost);
}

TEST_F(QuicSentPacketManagerTest, EarlyRetransmit1Packet) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Early retransmit when the final packet gets acked and the first is nacked.
  ReceivedPacketInfo received_info;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  received_info.missing_packets.insert(1);
  received_info.largest_observed = kNumSentPackets;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(kNumSentPackets, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(1, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(1, _)).Times(1);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(
      1u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  EXPECT_EQ(1u, QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  EXPECT_EQ(1u, stats_.packets_lost);
}

TEST_F(QuicSentPacketManagerTest, EarlyRetransmitAllPackets) {
  const size_t kNumSentPackets = 5;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Early retransmit all packets when the final packet arrives, since we do
  // not expect to receive any more acks.
  ReceivedPacketInfo received_info;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  received_info.missing_packets.insert(1);
  received_info.missing_packets.insert(2);
  received_info.missing_packets.insert(3);
  received_info.missing_packets.insert(4);
  received_info.largest_observed = kNumSentPackets;
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(5, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(_, _)).Times(4);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(4);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(
      4u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  EXPECT_EQ(4u, QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  EXPECT_EQ(4u, stats_.packets_lost);
}

TEST_F(QuicSentPacketManagerTest, NackRetransmit2Packets) {
  const size_t kNumSentPackets = 25;
  // Transmit 25 packets.
  for (QuicPacketSequenceNumber i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first 19 packets 3 times, which does not trigger early retransmit.
  const size_t kLargestObserved = 20;
  ReceivedPacketInfo received_info;
  received_info.largest_observed = kLargestObserved;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  for (size_t i = 1; i < kLargestObserved; ++i) {
    received_info.missing_packets.insert(i);
  }
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_,
              OnPacketAcked(kLargestObserved, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(_, _)).Times(17);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(17);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(
      17u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  for (size_t i = 1; i < kLargestObserved; ++i) {
    EXPECT_EQ(kLargestObserved - i,
              QuicSentPacketManagerPeer::GetNackCount(&manager_, i));
  }
}

TEST_F(QuicSentPacketManagerTest, NackRetransmit2PacketsAlternateAcks) {
  const size_t kNumSentPackets = 30;
  // Transmit 15 packets of data and 15 ack packets.  The send algorithm will
  // inform the congestion manager not to save the acks by returning false.
  for (QuicPacketSequenceNumber i = 1; i <= kNumSentPackets; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
                    .Times(1).WillOnce(Return(i % 2 == 0 ? false : true));
    SerializedPacket packet(CreatePacket(i, i % 2 == 1));
    manager_.OnSerializedPacket(packet);
    manager_.OnPacketSent(
        i, clock_.Now(), 1000, NOT_RETRANSMISSION,
        i % 2 == 0 ? NO_RETRANSMITTABLE_DATA : HAS_RETRANSMITTABLE_DATA);
  }

  // Nack the first 29 packets 3 times.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = kNumSentPackets;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  for (size_t i = 1; i < kNumSentPackets; ++i) {
    received_info.missing_packets.insert(i);
  }
  // We never actually get an ack call, since the kNumSentPackets packet was
  // not saved.
  EXPECT_CALL(*send_algorithm_, OnPacketLost(_, _)).Times(14);
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(14);
  manager_.OnIncomingAck(received_info, clock_.Now());
  ASSERT_EQ(
      14u, QuicSentPacketManagerPeer::GetPendingRetransmissionCount(&manager_));
  // Only non-ack packets have a nack count.
  for (size_t i = 1; i < kNumSentPackets; i += 2) {
    EXPECT_EQ(kNumSentPackets - i,
              QuicSentPacketManagerPeer::GetNackCount(&manager_, i));
  }

  // Ensure only the odd packets were retransmitted, since the others were not
  // retransmittable(ie: acks).
  for (size_t i = 0; i < 13; ++i) {
    EXPECT_EQ(1 + 2 * i, manager_.NextPendingRetransmission().sequence_number);
    manager_.OnRetransmittedPacket(1 + 2 * i, kNumSentPackets + 1 + i);
  }
}

TEST_F(QuicSentPacketManagerTest, NackTwiceThenAck) {
  // Transmit 4 packets.
  for (QuicPacketSequenceNumber i = 1; i <= 4; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 2 times, then ack it.
  ReceivedPacketInfo received_info;
  received_info.missing_packets.insert(1);
  for (size_t i = 1; i <= 3; ++i) {
    if (i == 3) {
      received_info.missing_packets.clear();
    }
    received_info.largest_observed = i + 1;
    received_info.delta_time_largest_observed =
        QuicTime::Delta::FromMilliseconds(5);
    EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
    EXPECT_CALL(*send_algorithm_,
                OnPacketAcked(_, _)).Times(i == 3 ? 2 : 1);
    manager_.OnIncomingAck(received_info, clock_.Now());
    EXPECT_FALSE(manager_.HasPendingRetransmissions());
    // The nack count remains at 2 when the packet is acked.
    EXPECT_EQ(i == 3 ? 2u : i,
              QuicSentPacketManagerPeer::GetNackCount(&manager_, 1));
  }
}

TEST_F(QuicSentPacketManagerTest, Rtt) {
  QuicPacketSequenceNumber sequence_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(15);
  SendDataPacket(sequence_number);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

  EXPECT_CALL(*send_algorithm_, UpdateRtt(expected_rtt));
  EXPECT_CALL(*send_algorithm_,
              OnPacketAcked(sequence_number, _)).Times(1);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = sequence_number;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(5);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(expected_rtt, QuicSentPacketManagerPeer::rtt(&manager_));
}

TEST_F(QuicSentPacketManagerTest, RttWithInvalidDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // delta_time_largest_observed is larger than the local time elapsed
  // and is hence invalid.
  QuicPacketSequenceNumber sequence_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(sequence_number);
  clock_.AdvanceTime(expected_rtt);

  EXPECT_CALL(*send_algorithm_, UpdateRtt(expected_rtt));
  EXPECT_CALL(*send_algorithm_,
              OnPacketAcked(sequence_number, _)).Times(1);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = sequence_number;
  received_info.delta_time_largest_observed =
      QuicTime::Delta::FromMilliseconds(11);
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(expected_rtt, QuicSentPacketManagerPeer::rtt(&manager_));
}

TEST_F(QuicSentPacketManagerTest, RttWithInfiniteDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // delta_time_largest_observed is infinite, and is hence invalid.
  QuicPacketSequenceNumber sequence_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(sequence_number);
  clock_.AdvanceTime(expected_rtt);

  EXPECT_CALL(*send_algorithm_, UpdateRtt(expected_rtt));
  EXPECT_CALL(*send_algorithm_,
              OnPacketAcked(sequence_number, _)).Times(1);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = sequence_number;
  received_info.delta_time_largest_observed = QuicTime::Delta::Infinite();
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(expected_rtt, QuicSentPacketManagerPeer::rtt(&manager_));
}

TEST_F(QuicSentPacketManagerTest, RttZeroDelta) {
  // Expect that the RTT is the time between send and receive since the
  // delta_time_largest_observed is zero.
  QuicPacketSequenceNumber sequence_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(sequence_number);
  clock_.AdvanceTime(expected_rtt);

  EXPECT_CALL(*send_algorithm_, UpdateRtt(expected_rtt));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(sequence_number, _))
      .Times(1);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = sequence_number;
  received_info.delta_time_largest_observed = QuicTime::Delta::Zero();
  manager_.OnIncomingAck(received_info, clock_.Now());
  EXPECT_EQ(expected_rtt, QuicSentPacketManagerPeer::rtt(&manager_));
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeTimeout) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);

  // Send 1 packet.
  QuicPacketSequenceNumber sequence_number = 1;
  SendDataPacket(sequence_number);

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack the third and ensure the first two are still pending.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(3, _));
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 3;
  received_info.missing_packets.insert(1);
  received_info.missing_packets.insert(2);
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  // Acking two more packets will lose both of them due to nacks.
  received_info.largest_observed = 5;
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(2);
  EXPECT_CALL(*send_algorithm_, OnPacketLost(_, _)).Times(2);
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  EXPECT_EQ(2u, stats_.tlp_count);
  EXPECT_EQ(0u, stats_.rto_count);
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeThenRTO) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);

  // Send 100 packets.
  const size_t kNumSentPackets = 100;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(101);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(102);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Advance the time enough to ensure all packets are RTO'd.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));

  // The final RTO abandons all of them.
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(2u, stats_.tlp_count);
  EXPECT_EQ(1u, stats_.rto_count);
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeout) {
  // Send 2 crypto packets and 3 data packets.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  const size_t kNumSentDataPackets = 3;
  for (size_t i = 1; i <= kNumSentDataPackets; ++i) {
    SendDataPacket(kNumSentCryptoPackets + i);
  }
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The first retransmits 2 packets.
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(2);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(6);
  RetransmitNextPacket(7);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The second retransmits 2 packets.
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(2);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(8);
  RetransmitNextPacket(9);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Now ack the two crypto packets and the speculatively encrypted request,
  // and ensure the first four crypto packets get abandoned, but not lost.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAcked(_, _)).Times(5);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 9;
  received_info.missing_packets.insert(1);
  received_info.missing_packets.insert(2);
  received_info.missing_packets.insert(6);
  received_info.missing_packets.insert(7);
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeSpuriousRetransmission) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit the crypto packet as 2.
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(1);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // Retransmit the crypto packet as 3.
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(1);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);

  // Now ack the first crypto packet, and ensure the second gets abandoned and
  // removed from unacked_packets.
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(1);
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 2;
  received_info.missing_packets.insert(1);
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  VerifyUnackedPackets(NULL, 0);
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeoutUnsentDataPacket) {
  // Send 2 crypto packets and serialize 1 data packet.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  SerializedPacket packet(CreateDataPacket(3));
  manager_.OnSerializedPacket(packet);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit 2 crypto packets, but not the serialized packet.
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _)).Times(2);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(6);
  RetransmitNextPacket(7);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeTimeoutUnsentDataPacket) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);
  // Serialize two data packets and send the latter.
  SerializedPacket packet(CreateDataPacket(1));
  manager_.OnSerializedPacket(packet);
  SendDataPacket(2);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  // Retransmit 1 unacked packets, but not the first serialized packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest, RetransmissionTimeout) {
  // Send 100 packets and then ensure all are abandoned when the RTO fires.
  const size_t kNumSentPackets = 100;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  manager_.OnRetransmissionTimeout();
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTime) {
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeCryptoHandshake) {
  SendCryptoPacket(1);

  // Check the min.
  EXPECT_CALL(*send_algorithm_, SmoothedRtt())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(1)));
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(10)),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  EXPECT_CALL(*send_algorithm_, SmoothedRtt())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(100)));

  QuicTime::Delta srtt = manager_.SmoothedRtt();
  QuicTime expected_time = clock_.Now().Add(QuicTime::Delta::FromMilliseconds(
      static_cast<int64>(1.5 * srtt.ToMilliseconds())));
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(
      static_cast<int64>(1.5 * srtt.ToMilliseconds())));
  EXPECT_CALL(*send_algorithm_, OnPacketAbandoned(_, _));
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // The retransmission time should now be twice as far in the future.
  expected_time = clock_.Now().Add(QuicTime::Delta::FromMilliseconds(
        static_cast<int64>(2 * 1.5 * srtt.ToMilliseconds())));
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeTailLossProbe) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);
  SendDataPacket(1);
  SendDataPacket(2);

  // Check the min.
  EXPECT_CALL(*send_algorithm_, SmoothedRtt())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(1)));
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(10)),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  EXPECT_CALL(*send_algorithm_, SmoothedRtt())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(100)));
  QuicTime::Delta srtt = manager_.SmoothedRtt();
  QuicTime::Delta expected_tlp_delay = QuicTime::Delta::FromMilliseconds(
      static_cast<int64>(2 * srtt.ToMilliseconds()));
  QuicTime expected_time = clock_.Now().Add(expected_tlp_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(expected_tlp_delay);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  expected_time = clock_.Now().Add(expected_tlp_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeRTO) {
  EXPECT_CALL(*send_algorithm_, SmoothedRtt())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(100)));

  SendDataPacket(1);
  SendDataPacket(2);

  QuicTime::Delta expected_rto_delay = QuicTime::Delta::FromMilliseconds(500);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(expected_rto_delay));
  QuicTime expected_time = clock_.Now().Add(expected_rto_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  clock_.AdvanceTime(expected_rto_delay);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);
  RetransmitNextPacket(4);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The delay should double the second time.
  expected_time = clock_.Now().Add(expected_rto_delay).Add(expected_rto_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Ack a packet and ensure the RTO goes back to the original value.
  ReceivedPacketInfo received_info;
  received_info.largest_observed = 2;
  received_info.missing_packets.insert(1);
  EXPECT_CALL(*send_algorithm_, UpdateRtt(_));
  manager_.OnIncomingAck(received_info, clock_.ApproximateNow());

  expected_time = clock_.Now().Add(expected_rto_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMin) {
  SendDataPacket(1);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(1)));
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(200);

  // If the delay is smaller than the min, ensure it exponentially backs off
  // from the min.
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay.Add(delay);
    EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMax) {
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillOnce(Return(QuicTime::Delta::FromSeconds(500)));

  EXPECT_EQ(QuicTime::Delta::FromSeconds(60),
            QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelay) {
  SendDataPacket(1);
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(500);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(delay));

  // Delay should back off exponentially.
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay.Add(delay);
    EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

}  // namespace
}  // namespace test
}  // namespace net
