// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection.h"

#include "net/base/net_errors.h"
#include "net/quic/congestion_control/receive_algorithm_interface.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/crypto/null_encrypter.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/quic_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::map;
using testing::_;
using testing::AnyNumber;
using testing::Between;
using testing::ContainerEq;
using testing::InSequence;
using testing::Return;
using testing::StrictMock;
using testing::SaveArg;

namespace net {
namespace test {
namespace {

const char data1[] = "foo";
const char data2[] = "bar";

class TestReceiveAlgorithm : public ReceiveAlgorithmInterface {
 public:
  explicit TestReceiveAlgorithm(QuicCongestionFeedbackFrame* feedback)
      : feedback_(feedback) {
  }

  bool GenerateCongestionFeedback(
      QuicCongestionFeedbackFrame* congestion_feedback) {
    if (feedback_ == NULL) {
      return false;
    }
    *congestion_feedback = *feedback_;
    return true;
  }

  MOCK_METHOD4(RecordIncomingPacket,
               void(QuicByteCount, QuicPacketSequenceNumber, QuicTime, bool));

 private:
  QuicCongestionFeedbackFrame* feedback_;

  DISALLOW_COPY_AND_ASSIGN(TestReceiveAlgorithm);
};

class TestConnectionHelper : public QuicConnectionHelperInterface {
 public:
  TestConnectionHelper(MockClock* clock, MockRandom* random_generator)
      : clock_(clock),
        random_generator_(random_generator),
        retransmission_alarm_(QuicTime::Zero()),
        send_alarm_(QuicTime::Zero()),
        timeout_alarm_(QuicTime::Zero()),
        blocked_(false) {
  }

  // QuicConnectionHelperInterface
  virtual void SetConnection(QuicConnection* connection) {}

  virtual const QuicClock* GetClock() const {
    return clock_;
  }

  virtual QuicRandom* GetRandomGenerator() {
    return random_generator_;
  }

  virtual int WritePacketToWire(const QuicEncryptedPacket& packet,
                                int* error) {
    QuicFramer framer(QuicDecrypter::Create(kNULL),
                      QuicEncrypter::Create(kNULL));
    FramerVisitorCapturingAcks visitor;
    framer.set_visitor(&visitor);
    EXPECT_TRUE(framer.ProcessPacket(packet));
    header_ = *visitor.header();
    if (visitor.ack()) {
      ack_.reset(new QuicAckFrame(*visitor.ack()));
    }
    if (visitor.feedback()) {
      feedback_.reset(new QuicCongestionFeedbackFrame(*visitor.feedback()));
    }
    if (blocked_) {
      *error = ERR_IO_PENDING;
      return -1;
    }
    *error = 0;
    return packet.length();
  }

  virtual void SetRetransmissionAlarm(QuicTime::Delta delay) {
    retransmission_alarm_ = clock_->Now().Add(delay);
  }

  virtual void SetSendAlarm(QuicTime::Delta delay) {
    send_alarm_ = clock_->Now().Add(delay);
  }

  virtual void SetTimeoutAlarm(QuicTime::Delta delay) {
    timeout_alarm_ = clock_->Now().Add(delay);
  }

  virtual bool IsSendAlarmSet() {
    return send_alarm_ > clock_->Now();
  }

  virtual void UnregisterSendAlarmIfRegistered() {
    send_alarm_ = QuicTime::Zero();
  }

  virtual void SetAckAlarm(QuicTime::Delta delay) {}
  virtual void ClearAckAlarm() {}

  QuicTime retransmission_alarm() const {
    return retransmission_alarm_;
  }

  QuicTime timeout_alarm() const { return timeout_alarm_; }

  QuicPacketHeader* header() { return &header_; }

  QuicAckFrame* ack() { return ack_.get(); }

  QuicCongestionFeedbackFrame* feedback() { return feedback_.get(); }

  void set_blocked(bool blocked) { blocked_ = blocked; }

 private:
  MockClock* clock_;
  MockRandom* random_generator_;
  QuicTime retransmission_alarm_;
  QuicTime send_alarm_;
  QuicTime timeout_alarm_;
  QuicPacketHeader header_;
  scoped_ptr<QuicAckFrame> ack_;
  scoped_ptr<QuicCongestionFeedbackFrame> feedback_;
  bool blocked_;

  DISALLOW_COPY_AND_ASSIGN(TestConnectionHelper);
};

class TestConnection : public QuicConnection {
 public:
  TestConnection(QuicGuid guid,
                 IPEndPoint address,
                 TestConnectionHelper* helper)
      : QuicConnection(guid, address, helper) {
  }

  void SendAck() {
    QuicConnectionPeer::SendAck(this);
  }

  void SetReceiveAlgorithm(TestReceiveAlgorithm* receive_algorithm) {
     QuicConnectionPeer::SetReceiveAlgorithm(this, receive_algorithm);
  }

  void SetSendAlgorithm(SendAlgorithmInterface* send_algorithm) {
    QuicConnectionPeer::SetSendAlgorithm(this, send_algorithm);
  }

  using QuicConnection::SendOrQueuePacket;

 private:
  DISALLOW_COPY_AND_ASSIGN(TestConnection);
};

class QuicConnectionTest : public ::testing::Test {
 protected:
  QuicConnectionTest()
      : guid_(42),
        framer_(QuicDecrypter::Create(kNULL), QuicEncrypter::Create(kNULL)),
        creator_(guid_, &framer_),
        send_algorithm_(new StrictMock<MockSendAlgorithm>),
        helper_(new TestConnectionHelper(&clock_, &random_generator_)),
        connection_(guid_, IPEndPoint(), helper_.get()),
        frame1_(1, false, 0, data1),
        frame2_(1, false, 3, data2),
        accept_packet_(true) {
    connection_.set_visitor(&visitor_);
    connection_.SetSendAlgorithm(send_algorithm_);
    // Simplify tests by not sending feedback unless specifically configured.
    SetFeedback(NULL);
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_)).WillRepeatedly(Return(
        QuicTime::Delta::Zero()));
    EXPECT_CALL(*receive_algorithm_,
                RecordIncomingPacket(_, _, _, _)).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(AnyNumber());
  }

  QuicAckFrame* outgoing_ack() {
    return QuicConnectionPeer::GetOutgoingAck(&connection_);
  }

  QuicAckFrame* last_ack() {
    return helper_->ack();
  }

  QuicCongestionFeedbackFrame* last_feedback() {
    return helper_->feedback();
  }

  QuicPacketHeader* last_header() {
    return helper_->header();
  }

  void ProcessPacket(QuicPacketSequenceNumber number) {
    EXPECT_CALL(visitor_, OnPacket(_, _, _, _))
        .WillOnce(Return(accept_packet_));
    ProcessDataPacket(number, 0);
  }

  void ProcessFecProtectedPacket(QuicPacketSequenceNumber number,
                                 bool expect_revival) {
    if (expect_revival) {
      EXPECT_CALL(visitor_, OnPacket(_, _, _, _)).Times(2).WillRepeatedly(
          Return(accept_packet_));
    } else {
      EXPECT_CALL(visitor_, OnPacket(_, _, _, _)).WillOnce(
          Return(accept_packet_));
    }
    ProcessDataPacket(number, 1);
  }

  void ProcessDataPacket(QuicPacketSequenceNumber number,
                         QuicFecGroupNumber fec_group) {
    scoped_ptr<QuicPacket> packet(ConstructDataPacket(number, fec_group));
    scoped_ptr<QuicEncryptedPacket> encrypted(framer_.EncryptPacket(*packet));
    connection_.ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *encrypted);
  }

  void ProcessClosePacket(QuicPacketSequenceNumber number,
                          QuicFecGroupNumber fec_group) {
    scoped_ptr<QuicPacket> packet(ConstructClosePacket(number, fec_group));
    scoped_ptr<QuicEncryptedPacket> encrypted(framer_.EncryptPacket(*packet));
    connection_.ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *encrypted);
  }

  // Sends an FEC packet that covers the packets that would have been sent.
  void ProcessFecPacket(QuicPacketSequenceNumber number,
                        QuicPacketSequenceNumber min_protected_packet,
                        bool expect_revival) {
    if (expect_revival) {
      EXPECT_CALL(visitor_, OnPacket(_, _, _, _)).WillOnce(
          Return(accept_packet_));
    }

    // Construct the decrypted data packet so we can compute the correct
    // redundancy.
    scoped_ptr<QuicPacket> data_packet(ConstructDataPacket(number, 1));

    header_.public_header.guid = guid_;
    header_.public_header.flags = PACKET_PUBLIC_FLAGS_NONE;
    header_.private_flags = PACKET_PRIVATE_FLAGS_FEC;
    header_.packet_sequence_number = number;
    header_.fec_group = min_protected_packet;
    QuicFecData fec_data;
    fec_data.fec_group = header_.fec_group;
    // Since all data packets in this test have the same payload, the
    // redundancy is either equal to that payload or the xor of that payload
    // with itself, depending on the number of packets.
    if (((number - min_protected_packet) % 2) == 0) {
      for (size_t i = kStartOfFecProtectedData; i < data_packet->length();
           ++i) {
        data_packet->mutable_data()[i] ^= data_packet->data()[i];
      }
    }
    fec_data.redundancy = data_packet->FecProtectedData();
    scoped_ptr<QuicPacket> fec_packet(
        framer_.ConstructFecPacket(header_, fec_data));
    scoped_ptr<QuicEncryptedPacket> encrypted(
        framer_.EncryptPacket(*fec_packet));

    connection_.ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *encrypted);
  }

  void SendStreamDataToPeer(QuicStreamId id, StringPiece data,
                            QuicStreamOffset offset, bool fin,
                            QuicPacketSequenceNumber* last_packet) {
    EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
    connection_.SendStreamData(id, data, offset, fin);
    if (last_packet != NULL) {
      *last_packet =
          QuicConnectionPeer::GetPacketCreator(&connection_)->sequence_number();
    }
    EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(AnyNumber());
  }

  void SendAckPacketToPeer() {
    EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(1);
    connection_.SendAck();
    EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(AnyNumber());
  }

  void ProcessAckPacket(QuicAckFrame* frame) {
    QuicFrames frames;
    frames.push_back(QuicFrame(frame));
    PacketPair pair = creator_.SerializeAllFrames(frames);
    scoped_ptr<QuicPacket> packet(pair.second);
    scoped_ptr<QuicEncryptedPacket> encrypted(framer_.EncryptPacket(*packet));
    connection_.ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *encrypted);
  }

  bool IsMissing(QuicPacketSequenceNumber number) {
    return outgoing_ack()->received_info.IsAwaitingPacket(number);
  }

  QuicPacket* ConstructDataPacket(QuicPacketSequenceNumber number,
                                  QuicFecGroupNumber fec_group) {
    header_.public_header.guid = guid_;
    header_.public_header.flags = PACKET_PUBLIC_FLAGS_NONE;
    header_.private_flags = PACKET_PRIVATE_FLAGS_NONE;
    header_.packet_sequence_number = number;
    header_.fec_group = fec_group;

    QuicFrames frames;
    QuicFrame frame(&frame1_);
    frames.push_back(frame);
    QuicPacket* packet = framer_.ConstructFrameDataPacket(header_, frames);
    EXPECT_TRUE(packet != NULL);
    return packet;
  }

  QuicPacket* ConstructClosePacket(QuicPacketSequenceNumber number,
                                   QuicFecGroupNumber fec_group) {
    header_.public_header.guid = guid_;
    header_.packet_sequence_number = number;
    header_.public_header.flags = PACKET_PUBLIC_FLAGS_NONE;
    header_.fec_group = fec_group;

    QuicConnectionCloseFrame qccf;
    qccf.error_code = QUIC_CLIENT_GOING_AWAY;
    qccf.ack_frame = QuicAckFrame(0, 1);

    QuicFrames frames;
    QuicFrame frame(&qccf);
    frames.push_back(frame);
    QuicPacket* packet = framer_.ConstructFrameDataPacket(header_, frames);
    EXPECT_TRUE(packet != NULL);
    return packet;
  }

  void SetFeedback(QuicCongestionFeedbackFrame* feedback) {
    receive_algorithm_ = new TestReceiveAlgorithm(feedback);
    connection_.SetReceiveAlgorithm(receive_algorithm_);
  }

  QuicGuid guid_;
  QuicFramer framer_;
  QuicPacketCreator creator_;

  MockSendAlgorithm* send_algorithm_;
  TestReceiveAlgorithm* receive_algorithm_;
  MockClock clock_;
  MockRandom random_generator_;
  scoped_ptr<TestConnectionHelper> helper_;
  TestConnection connection_;
  testing::StrictMock<MockConnectionVisitor> visitor_;

  QuicPacketHeader header_;
  QuicStreamFrame frame1_;
  QuicStreamFrame frame2_;
  bool accept_packet_;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicConnectionTest);
};

TEST_F(QuicConnectionTest, PacketsInOrder) {
  ProcessPacket(1);
  EXPECT_EQ(1u, outgoing_ack()->received_info.largest_observed);
  EXPECT_EQ(0u, outgoing_ack()->received_info.missing_packets.size());

  ProcessPacket(2);
  EXPECT_EQ(2u, outgoing_ack()->received_info.largest_observed);
  EXPECT_EQ(0u, outgoing_ack()->received_info.missing_packets.size());

  ProcessPacket(3);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_EQ(0u, outgoing_ack()->received_info.missing_packets.size());
}

TEST_F(QuicConnectionTest, PacketsRejected) {
  ProcessPacket(1);
  EXPECT_EQ(1u, outgoing_ack()->received_info.largest_observed);
  EXPECT_EQ(0u, outgoing_ack()->received_info.missing_packets.size());

  accept_packet_ = false;
  ProcessPacket(2);
  // We should not have an ack for two.
  EXPECT_EQ(1u, outgoing_ack()->received_info.largest_observed);
  EXPECT_EQ(0u, outgoing_ack()->received_info.missing_packets.size());
}

TEST_F(QuicConnectionTest, PacketsOutOfOrder) {
  ProcessPacket(3);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(2);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_FALSE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(1);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_FALSE(IsMissing(2));
  EXPECT_FALSE(IsMissing(1));
}

TEST_F(QuicConnectionTest, DuplicatePacket) {
  ProcessPacket(3);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  // Send packet 3 again, but do not set the expectation that
  // the visitor OnPacket() will be called.
  ProcessDataPacket(3, 0);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));
}

TEST_F(QuicConnectionTest, PacketsOutOfOrderWithAdditionsAndLeastAwaiting) {
  ProcessPacket(3);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(2);
  EXPECT_EQ(3u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(5);
  EXPECT_EQ(5u, outgoing_ack()->received_info.largest_observed);
  EXPECT_TRUE(IsMissing(1));
  EXPECT_TRUE(IsMissing(4));

  // Pretend at this point the client has gotten acks for 2 and 3 and 1 is a
  // packet the peer will not retransmit.  It indicates this by sending 'least
  // awaiting' is 4.  The connection should then realize 1 will not be
  // retransmitted, and will remove it from the missing list.
  creator_.set_sequence_number(5);
  QuicAckFrame frame(0, 4);
  ProcessAckPacket(&frame);

  // Force an ack to be sent.
  SendAckPacketToPeer();
  EXPECT_TRUE(IsMissing(4));
}

TEST_F(QuicConnectionTest, RejectPacketTooFarOut) {
  // Call ProcessDataPacket rather than ProcessPacket, as we should not get a
  // packet call to the visitor.
  ProcessDataPacket(6000, 0);

  SendAckPacketToPeer();  // Packet 2
  EXPECT_EQ(0u, outgoing_ack()->received_info.largest_observed);
}

TEST_F(QuicConnectionTest, TruncatedAck) {
  EXPECT_CALL(visitor_, OnAck(_)).Times(testing::AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(2);
  for (int i = 0; i < 200; ++i) {
    SendStreamDataToPeer(1, "foo", i * 3, false, NULL);
  }

  QuicAckFrame frame(0, 1);
  frame.received_info.RecordReceived(193);
  ProcessAckPacket(&frame);

  EXPECT_TRUE(QuicConnectionPeer::GetReceivedTruncatedAck(&connection_));

  frame.received_info.missing_packets.erase(192);

  ProcessAckPacket(&frame);
  EXPECT_FALSE(QuicConnectionPeer::GetReceivedTruncatedAck(&connection_));
}

TEST_F(QuicConnectionTest, LeastUnackedLower) {
  SendStreamDataToPeer(1, "foo", 0, false, NULL);
  SendStreamDataToPeer(1, "bar", 3, false, NULL);
  SendStreamDataToPeer(1, "eep", 6, false, NULL);

  // Start out saying the least unacked is 2
  creator_.set_sequence_number(5);
  QuicAckFrame frame(0, 2);
  ProcessAckPacket(&frame);

  // Change it to 1, but lower the sequence number to fake out-of-order packets.
  // This should be fine.
  creator_.set_sequence_number(1);
  QuicAckFrame frame2(0, 1);
  // The scheduler will not process out of order acks.
  ProcessAckPacket(&frame2);

  // Now claim it's one, but set the ordering so it was sent "after" the first
  // one.  This should cause a connection error.
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_INVALID_ACK_DATA, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  creator_.set_sequence_number(7);
  ProcessAckPacket(&frame2);
}

TEST_F(QuicConnectionTest, LargestObservedLower) {
  SendStreamDataToPeer(1, "foo", 0, false, NULL);
  SendStreamDataToPeer(1, "bar", 3, false, NULL);
  SendStreamDataToPeer(1, "eep", 6, false, NULL);
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(2);

  // Start out saying the largest observed is 2.
  QuicAckFrame frame(2, 0);
  EXPECT_CALL(visitor_, OnAck(_));
  ProcessAckPacket(&frame);

  // Now change it to 1, and it should cause a connection error.
  QuicAckFrame frame2(1, 0);
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_INVALID_ACK_DATA, false));
  ProcessAckPacket(&frame2);
}

TEST_F(QuicConnectionTest, LeastUnackedGreaterThanPacketSequenceNumber) {
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_INVALID_ACK_DATA, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  // Create an ack with least_unacked is 2 in packet number 1.
  creator_.set_sequence_number(0);
  QuicAckFrame frame(0, 2);
  ProcessAckPacket(&frame);
}

TEST_F(QuicConnectionTest,
       DISABLED_NackSequenceNumberGreaterThanLargestReceived) {
  SendStreamDataToPeer(1, "foo", 0, false, NULL);
  SendStreamDataToPeer(1, "bar", 3, false, NULL);
  SendStreamDataToPeer(1, "eep", 6, false, NULL);

  EXPECT_CALL(visitor_, ConnectionClose(QUIC_INVALID_ACK_DATA, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  QuicAckFrame frame(0, 1);
  frame.received_info.missing_packets.insert(3);
  ProcessAckPacket(&frame);
}

TEST_F(QuicConnectionTest, AckUnsentData) {
  // Ack a packet which has not been sent.
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_INVALID_ACK_DATA, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  QuicAckFrame frame(1, 0);
  ProcessAckPacket(&frame);
}

TEST_F(QuicConnectionTest, AckAll) {
  ProcessPacket(1);

  creator_.set_sequence_number(1);
  QuicAckFrame frame1(0, 1);
  ProcessAckPacket(&frame1);
}

TEST_F(QuicConnectionTest, BasicSending) {
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(6);
  QuicPacketSequenceNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, false, &last_packet);  // Packet 1
  EXPECT_EQ(1u, last_packet);
  SendAckPacketToPeer();  // Packet 2

  EXPECT_EQ(1u, last_ack()->sent_info.least_unacked);

  SendAckPacketToPeer();  // Packet 3
  EXPECT_EQ(1u, last_ack()->sent_info.least_unacked);

  SendStreamDataToPeer(1u, "bar", 3, false, &last_packet);  // Packet 4
  EXPECT_EQ(4u, last_packet);
  SendAckPacketToPeer();  // Packet 5
  EXPECT_EQ(1u, last_ack()->sent_info.least_unacked);

  QuicConnectionVisitorInterface::AckedPackets expected_acks;
  expected_acks.insert(1);

  // Client acks up to packet 3
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));
  QuicAckFrame frame(3, 0);
  ProcessAckPacket(&frame);
  SendAckPacketToPeer();  // Packet 6

  // As soon as we've acked one, we skip ack packets 2 and 3 and note lack of
  // ack for 4.
  EXPECT_EQ(4u, last_ack()->sent_info.least_unacked);

  expected_acks.clear();
  expected_acks.insert(4);

  // Client acks up to packet 4, the last packet
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));
  QuicAckFrame frame2(6, 0);
  ProcessAckPacket(&frame2);  // Even parity triggers ack packet 7

  // The least packet awaiting ack should now be 7
  EXPECT_EQ(7u, last_ack()->sent_info.least_unacked);

  // If we force an ack, we shouldn't change our retransmit state.
  SendAckPacketToPeer();  // Packet 8
  EXPECT_EQ(8u, last_ack()->sent_info.least_unacked);

  // But if we send more data it should.
  SendStreamDataToPeer(1, "eep", 6, false, &last_packet);  // Packet 9
  EXPECT_EQ(9u, last_packet);
  SendAckPacketToPeer();  // Packet10
  EXPECT_EQ(9u, last_ack()->sent_info.least_unacked);
}

TEST_F(QuicConnectionTest, FECSending) {
  // Limit to one byte per packet.
  size_t ciphertext_size = NullEncrypter().GetCiphertextSize(1);
  connection_.options()->max_packet_length =
      ciphertext_size + QuicUtils::StreamFramePacketOverhead(1);
  // And send FEC every two packets.
  connection_.options()->max_packets_per_fec_group = 2;

  // Send 4 data packets and 2 FEC packets.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(6);
  connection_.SendStreamData(1, "food", 0, false);
  // Expect the FEC group to be closed after SendStreamData.
  EXPECT_FALSE(creator_.ShouldSendFec(true));
}

TEST_F(QuicConnectionTest, FECQueueing) {
  // Limit to one byte per packet.
  size_t ciphertext_size = NullEncrypter().GetCiphertextSize(1);
  connection_.options()->max_packet_length =
      ciphertext_size + QuicUtils::StreamFramePacketOverhead(1);
  // And send FEC every two packets.
  connection_.options()->max_packets_per_fec_group = 2;

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  helper_->set_blocked(true);
  connection_.SendStreamData(1, "food", 0, false);
  EXPECT_FALSE(creator_.ShouldSendFec(true));
  // Expect the first data packet and the fec packet to be queued.
  EXPECT_EQ(2u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, RetransmitOnNack) {
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(2);
  QuicPacketSequenceNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, false, &last_packet);  // Packet 1
  SendStreamDataToPeer(1, "foos", 3, false, &last_packet);  // Packet 2
  SendStreamDataToPeer(1, "fooos", 7, false, &last_packet);  // Packet 3

  QuicConnectionVisitorInterface::AckedPackets expected_acks;
  expected_acks.insert(1);
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));

  // Client acks one but not two or three.  Right now we only retransmit on
  // explicit nack, so it should not trigger a retransimission.
  QuicAckFrame ack_one(1, 0);
  ProcessAckPacket(&ack_one);
  ProcessAckPacket(&ack_one);
  ProcessAckPacket(&ack_one);

  expected_acks.clear();
  expected_acks.insert(3);
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));

  // Client acks up to 3 with two explicitly missing.  Two nacks should cause no
  // change.
  QuicAckFrame nack_two(3, 0);
  nack_two.received_info.missing_packets.insert(2);
  ProcessAckPacket(&nack_two);
  ProcessAckPacket(&nack_two);

  // The third nack should trigger a retransimission.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, 37, true)).Times(1);
  ProcessAckPacket(&nack_two);
}

TEST_F(QuicConnectionTest, RetransmitNackedLargestObserved) {
  QuicPacketSequenceNumber largest_observed;
  QuicByteCount packet_size;
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, false)).WillOnce(DoAll(
      SaveArg<0>(&largest_observed), SaveArg<1>(&packet_size)));
  connection_.SendStreamData(1, "foo", 0, false);
  QuicAckFrame frame(1, largest_observed);
  frame.received_info.missing_packets.insert(largest_observed);
  ProcessAckPacket(&frame);
  // Second udp packet will force an ack frame.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, false));
  ProcessAckPacket(&frame);
  // Third nack should retransmit the largest observed packet.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, packet_size, true));
  ProcessAckPacket(&frame);
}

TEST_F(QuicConnectionTest, LimitPacketsPerNack) {
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(12, _, _)).Times(1);
  int offset = 0;
  // Send packets 1 to 12
  for (int i = 0; i < 12; ++i) {
    SendStreamDataToPeer(1, "foo", offset, false, NULL);
    offset += 3;
  }

  // Ack 12, nack 1-11
  QuicAckFrame nack(12, 0);
  for (int i = 1; i < 12; ++i) {
    nack.received_info.missing_packets.insert(i);
  }

  QuicConnectionVisitorInterface::AckedPackets expected_acks;
  expected_acks.insert(12);
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));

  // Nack three times.
  ProcessAckPacket(&nack);
  // The second call will trigger an ack.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(1);
  ProcessAckPacket(&nack);
  // The third call should trigger retransmitting 10 packets.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(10);
  ProcessAckPacket(&nack);

  // The fourth call should trigger retransmitting the 11th packet and an ack.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(2);
  ProcessAckPacket(&nack);
}

// Test sending multiple acks from the connection to the session.
TEST_F(QuicConnectionTest, MultipleAcks) {
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(6);
  QuicPacketSequenceNumber last_packet;
  SendStreamDataToPeer(1u, "foo", 0, false, &last_packet);  // Packet 1
  EXPECT_EQ(1u, last_packet);
  SendStreamDataToPeer(3u, "foo", 0, false, &last_packet);  // Packet 2
  EXPECT_EQ(2u, last_packet);
  SendAckPacketToPeer();  // Packet 3
  SendStreamDataToPeer(5u, "foo", 0, false, &last_packet);  // Packet 4
  EXPECT_EQ(4u, last_packet);
  SendStreamDataToPeer(1u, "foo", 3, false, &last_packet);  // Packet 5
  EXPECT_EQ(5u, last_packet);
  SendStreamDataToPeer(3u, "foo", 3, false, &last_packet);  // Packet 6
  EXPECT_EQ(6u, last_packet);

  // Client will ack packets 1, [!2], 3, 4, 5
  QuicAckFrame frame1(5, 0);
  frame1.received_info.missing_packets.insert(2);

  // The connection should pass up acks for 1, 4, 5.  2 is not acked, and 3 was
  // an ackframe so should not be passed up.
  QuicConnectionVisitorInterface::AckedPackets expected_acks;
  expected_acks.insert(1);
  expected_acks.insert(4);
  expected_acks.insert(5);

  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));
  ProcessAckPacket(&frame1);

  // Now the client implicitly acks 2, and explicitly acks 6
  QuicAckFrame frame2(6, 0);
  expected_acks.clear();
  // Both acks should be passed up.
  expected_acks.insert(2);
  expected_acks.insert(6);

  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));
  ProcessAckPacket(&frame2);
}

TEST_F(QuicConnectionTest, DontLatchUnackedPacket) {
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(1);
  SendStreamDataToPeer(1, "foo", 0, false, NULL);  // Packet 1;
  SendAckPacketToPeer();  // Packet 2

  // This sets least unacked to 2, the ack packet.
  QuicConnectionVisitorInterface::AckedPackets expected_acks;
  expected_acks.insert(1);
  // Client acks packet 1
  EXPECT_CALL(visitor_, OnAck(ContainerEq(expected_acks)));
  QuicAckFrame frame(1, 0);
  ProcessAckPacket(&frame);

  // Verify that our internal state has least-unacked as 2.
  QuicAckFrame* outgoing_ack = QuicConnectionPeer::GetOutgoingAck(&connection_);
  EXPECT_EQ(2u, outgoing_ack->sent_info.least_unacked);

  // When we send an ack, we make sure our least-unacked makes sense.  In this
  // case since we're not waiting on an ack for 2 and all packets are acked, we
  // set it to 3.
  SendAckPacketToPeer();  // Packet 3
  EXPECT_EQ(3u, outgoing_ack->sent_info.least_unacked);
  EXPECT_EQ(3u, last_ack()->sent_info.least_unacked);
}

TEST_F(QuicConnectionTest, ReviveMissingPacketAfterFecPacket) {
  // Don't send missing packet 1.
  ProcessFecPacket(2, 1, true);
}

TEST_F(QuicConnectionTest, ReviveMissingPacketAfterDataPacketThenFecPacket) {
  ProcessFecProtectedPacket(1, false);
  // Don't send missing packet 2.
  ProcessFecPacket(3, 1, true);
}

TEST_F(QuicConnectionTest, ReviveMissingPacketAfterDataPacketsThenFecPacket) {
  ProcessFecProtectedPacket(1, false);
  // Don't send missing packet 2.
  ProcessFecProtectedPacket(3, false);
  ProcessFecPacket(4, 1, true);
}

TEST_F(QuicConnectionTest, ReviveMissingPacketAfterDataPacket) {
  // Don't send missing packet 1.
  ProcessFecPacket(3, 1, false);  // out of order
  ProcessFecProtectedPacket(2, true);
}

TEST_F(QuicConnectionTest, ReviveMissingPacketAfterDataPackets) {
  ProcessFecProtectedPacket(1, false);
  // Don't send missing packet 2.
  ProcessFecPacket(6, 1, false);
  ProcessFecProtectedPacket(3, false);
  ProcessFecProtectedPacket(4, false);
  ProcessFecProtectedPacket(5, true);
}

TEST_F(QuicConnectionTest, TestRetransmit) {
  // TODO(rch): make this work
  // FLAGS_fake_packet_loss_percentage = 100;
  const QuicTime::Delta kDefaultRetransmissionTime =
      QuicTime::Delta::FromMilliseconds(500);

  QuicTime default_retransmission_time = clock_.Now().Add(
      kDefaultRetransmissionTime);

  QuicAckFrame* outgoing_ack = QuicConnectionPeer::GetOutgoingAck(&connection_);
  SendStreamDataToPeer(1, "foo", 0, false, NULL);
  EXPECT_EQ(1u, outgoing_ack->sent_info.least_unacked);

  EXPECT_EQ(1u, last_header()->packet_sequence_number);
  EXPECT_EQ(default_retransmission_time, helper_->retransmission_alarm());
  // Simulate the retransimission alarm firing
  clock_.AdvanceTime(kDefaultRetransmissionTime);
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  connection_.RetransmitPacket(1);
  EXPECT_EQ(2u, last_header()->packet_sequence_number);
  EXPECT_EQ(2u, outgoing_ack->sent_info.least_unacked);
}

TEST_F(QuicConnectionTest, TestRetransmitOrder) {
  QuicByteCount first_packet_size;
  EXPECT_CALL(*send_algorithm_, SentPacket(_,_,_)).WillOnce(
      SaveArg<1>(&first_packet_size));
  connection_.SendStreamData(1, "first_packet", 0, false);
  QuicByteCount second_packet_size;
  EXPECT_CALL(*send_algorithm_, SentPacket(_,_,_)).WillOnce(
      SaveArg<1>(&second_packet_size));
  connection_.SendStreamData(1, "second_packet", 12, false);
  EXPECT_NE(first_packet_size, second_packet_size);
  // Advance the clock by huge time to make sure packets will be retransmitted.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  {
    InSequence s;
    EXPECT_CALL(*send_algorithm_, SentPacket(_, first_packet_size, _));
    EXPECT_CALL(*send_algorithm_, SentPacket(_, second_packet_size, _));
  }
  connection_.OnRetransmissionTimeout();
}

TEST_F(QuicConnectionTest, TestRetransmissionCountCalculation) {
  QuicPacketSequenceNumber original_sequence_number;
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, false)).WillOnce(
      SaveArg<0>(&original_sequence_number));
  connection_.SendStreamData(1, "foo", 0, false);
  EXPECT_TRUE(QuicConnectionPeer::IsSavedForRetransmission(
      &connection_, original_sequence_number));
  EXPECT_EQ(0u, QuicConnectionPeer::GetRetransmissionCount(
      &connection_, original_sequence_number));
  // Force retransmission due to RTO.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  QuicPacketSequenceNumber rto_sequence_number;
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, true)).WillOnce(
      SaveArg<0>(&rto_sequence_number));
  connection_.OnRetransmissionTimeout();
  EXPECT_FALSE(QuicConnectionPeer::IsSavedForRetransmission(
      &connection_, original_sequence_number));
  EXPECT_TRUE(QuicConnectionPeer::IsSavedForRetransmission(
      &connection_, rto_sequence_number));
  EXPECT_EQ(1u, QuicConnectionPeer::GetRetransmissionCount(
      &connection_, rto_sequence_number));
  // Once by explicit nack.
  QuicPacketSequenceNumber nack_sequence_number;
  // Ack packets might generate some other packets, which are not
  // retransmissions. (More ack packets).
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, false)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, true)).WillOnce(
      SaveArg<0>(&nack_sequence_number));
  QuicAckFrame ack(rto_sequence_number, 0);
  // Ack the retransmitted packet.
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(1);
  ack.received_info.missing_packets.insert(rto_sequence_number);
  for (int i = 0; i < 3; i++) {
    ProcessAckPacket(&ack);
  }
  EXPECT_FALSE(QuicConnectionPeer::IsSavedForRetransmission(
      &connection_, rto_sequence_number));
  EXPECT_TRUE(QuicConnectionPeer::IsSavedForRetransmission(
      &connection_, nack_sequence_number));
  EXPECT_EQ(2u, QuicConnectionPeer::GetRetransmissionCount(
      &connection_, nack_sequence_number));
}

TEST_F(QuicConnectionTest, SetRTOAfterWritingToSocket) {
  helper_->set_blocked(true);
  connection_.SendStreamData(1, "foo", 0, false);
  // Make sure that RTO is not started when the packet is queued.
  EXPECT_EQ(0u, QuicConnectionPeer::GetNumRetransmissionTimeouts(&connection_));

  // Test that RTO is started once we write to the socket.
  helper_->set_blocked(false);
  EXPECT_CALL(visitor_, OnCanWrite());
  connection_.OnCanWrite();
  EXPECT_EQ(1u, QuicConnectionPeer::GetNumRetransmissionTimeouts(&connection_));
}

TEST_F(QuicConnectionTest, TestQueued) {
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  helper_->set_blocked(true);
  connection_.SendStreamData(1, "foo", 0, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Attempt to send all packets, but since we're actually still
  // blocked, they should all remain queued.
  EXPECT_FALSE(connection_.OnCanWrite());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Unblock the writes and actually send.
  helper_->set_blocked(false);
  EXPECT_CALL(visitor_, OnCanWrite());
  EXPECT_TRUE(connection_.OnCanWrite());
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, CloseFecGroup) {
  // Don't send missing packet 1
  // Don't send missing packet 2
  ProcessFecProtectedPacket(3, false);
  // Don't send missing FEC packet 3
  ASSERT_EQ(1u, connection_.NumFecGroups());

  // Now send non-fec protected ack packet and close the group
  QuicAckFrame frame(0, 5);
  creator_.set_sequence_number(4);
  ProcessAckPacket(&frame);
  ASSERT_EQ(0u, connection_.NumFecGroups());
}

TEST_F(QuicConnectionTest, NoQuicCongestionFeedbackFrame) {
  SendAckPacketToPeer();
  EXPECT_TRUE(last_feedback() == NULL);
}

TEST_F(QuicConnectionTest, WithQuicCongestionFeedbackFrame) {
  QuicCongestionFeedbackFrame info;
  info.type = kFixRate;
  info.fix_rate.bitrate = QuicBandwidth::FromBytesPerSecond(123);
  SetFeedback(&info);

  SendAckPacketToPeer();
  EXPECT_EQ(kFixRate, last_feedback()->type);
  EXPECT_EQ(info.fix_rate.bitrate, last_feedback()->fix_rate.bitrate);
}

TEST_F(QuicConnectionTest, UpdateQuicCongestionFeedbackFrame) {
  SendAckPacketToPeer();
  EXPECT_CALL(*receive_algorithm_, RecordIncomingPacket(_, _, _, _));
  ProcessPacket(1);
}

TEST_F(QuicConnectionTest, DontUpdateQuicCongestionFeedbackFrameForRevived) {
  SendAckPacketToPeer();
  // Process an FEC packet, and revive the missing data packet
  // but only contact the receive_algorithm once.
  EXPECT_CALL(*receive_algorithm_, RecordIncomingPacket(_, _, _, _));
  ProcessFecPacket(2, 1, true);
}

TEST_F(QuicConnectionTest, InitialTimeout) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_CONNECTION_TIMED_OUT, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));

  QuicTime default_timeout = clock_.Now().Add(
      QuicTime::Delta::FromMicroseconds(kDefaultTimeoutUs));
  EXPECT_EQ(default_timeout, helper_->timeout_alarm());

  // Simulate the timeout alarm firing
  clock_.AdvanceTime(QuicTime::Delta::FromMicroseconds(kDefaultTimeoutUs));
  EXPECT_TRUE(connection_.CheckForTimeout());
  EXPECT_FALSE(connection_.connected());
}

TEST_F(QuicConnectionTest, TimeoutAfterSend) {
  EXPECT_TRUE(connection_.connected());

  QuicTime default_timeout = clock_.Now().Add(
      QuicTime::Delta::FromMicroseconds(kDefaultTimeoutUs));

  // When we send a packet, the timeout will change to 5000 + kDefaultTimeout.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));

  // Send an ack so we don't set the retransimission alarm.
  SendAckPacketToPeer();
  EXPECT_EQ(default_timeout, helper_->timeout_alarm());

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5000.  The alarm will reregister.
  clock_.AdvanceTime(QuicTime::Delta::FromMicroseconds(
      kDefaultTimeoutUs - 5000));
  EXPECT_EQ(default_timeout, clock_.Now());
  EXPECT_FALSE(connection_.CheckForTimeout());
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(default_timeout.Add(QuicTime::Delta::FromMilliseconds(5)),
            helper_->timeout_alarm());

  // This time, we should time out.
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_CONNECTION_TIMED_OUT, false));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_EQ(default_timeout.Add(QuicTime::Delta::FromMilliseconds(5)),
            clock_.Now());
  EXPECT_TRUE(connection_.CheckForTimeout());
  EXPECT_FALSE(connection_.connected());
}

// TODO(ianswett): Add scheduler tests when should_retransmit is false.
TEST_F(QuicConnectionTest, SendScheduler) {
  // Test that if we send a packet without delay, it is not queued.
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelay) {
  // Test that if we send a packet with a delay, it ends up queued.
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(1)));
  EXPECT_CALL(*send_algorithm_, SentPacket(1, _, _)).Times(0);
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerForce) {
  // Test that if we force send a packet, it is not queued.
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(true)).Times(0);
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  connection_.SendOrQueuePacket(1, packet, true);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerEAGAIN) {
  QuicPacket* packet = ConstructDataPacket(1, 0);
  helper_->set_blocked(true);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*send_algorithm_, SentPacket(1, _, _)).Times(0);
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayThenSend) {
  // Test that if we send a packet with a delay, it ends up queued.
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(1)));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Advance the clock to fire the alarm, and configure the scheduler
  // to permit the packet to be sent.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::Zero()));
  clock_.AdvanceTime(QuicTime::Delta::FromMicroseconds(1));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  EXPECT_CALL(visitor_, OnCanWrite());
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayThenRetransmit) {
  // Fake packet loss.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*send_algorithm_, SentPacket(1, _, false));
  connection_.SendStreamData(1, "foo", 0, false);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  // Advance the time for retransmission of lost packet.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(501));
  // Test that if we send a retransmit with a delay, it ends up queued.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(true)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(1)));
  connection_.OnRetransmissionTimeout();
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Advance the clock to fire the alarm, and configure the scheduler
  // to permit the packet to be sent.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(true)).WillOnce(testing::Return(
      QuicTime::Delta::Zero()));

  // Ensure the scheduler is notified this is a retransmit.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, true));
  clock_.AdvanceTime(QuicTime::Delta::FromMicroseconds(1));
  EXPECT_CALL(visitor_, OnCanWrite());
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayAndQueue) {
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(1)));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Attempt to send another packet and make sure that it gets queued.
  packet = ConstructDataPacket(2, 0);
  connection_.SendOrQueuePacket(2, packet, false);
  EXPECT_EQ(2u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayThenAckAndSend) {
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(10)));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Now send non-retransmitting information, that we're not going to
  // retransmit 3. The far end should stop waiting for it.
  QuicAckFrame frame(0, 1);
  EXPECT_CALL(*send_algorithm_,
              TimeUntilSend(false)).WillRepeatedly(
                  testing::Return(QuicTime::Delta::Zero()));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _));
  EXPECT_CALL(visitor_, OnCanWrite());
  ProcessAckPacket(&frame);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  // Ensure alarm is not set
  EXPECT_FALSE(helper_->IsSendAlarmSet());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayThenAckAndHold) {
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(10)));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Now send non-retransmitting information, that we're not going to
  // retransmit 3.  The far end should stop waiting for it.
  QuicAckFrame frame(0, 1);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(1)));
  ProcessAckPacket(&frame);

  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, SendSchedulerDelayThenOnCanWrite) {
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(10)));
  connection_.SendOrQueuePacket(1, packet, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // OnCanWrite should not send the packet (because of the delay)
  // but should still return true.
  EXPECT_CALL(visitor_, OnCanWrite());
  EXPECT_TRUE(connection_.OnCanWrite());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, TestQueueLimitsOnSendStreamData) {
  // Limit to one byte per packet.
  size_t ciphertext_size = NullEncrypter().GetCiphertextSize(1);
  connection_.options()->max_packet_length =
      ciphertext_size + QuicUtils::StreamFramePacketOverhead(1);

  // Queue the first packet.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(false)).WillOnce(testing::Return(
      QuicTime::Delta::FromMicroseconds(10)));
  EXPECT_EQ(1u, connection_.SendStreamData(
      1, "EnoughDataToQueue", 0, false).bytes_consumed);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_F(QuicConnectionTest, LoopThroughSendingPackets) {
  // Limit to one byte per packet.
  size_t ciphertext_size = NullEncrypter().GetCiphertextSize(1);
  connection_.options()->max_packet_length =
      ciphertext_size + QuicUtils::StreamFramePacketOverhead(1);

  // Queue the first packet.
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(17);
  EXPECT_EQ(17u, connection_.SendStreamData(
                1, "EnoughDataToQueue", 0, false).bytes_consumed);
}

TEST_F(QuicConnectionTest, NoAckForClose) {
  ProcessPacket(1);
  EXPECT_CALL(*send_algorithm_, OnIncomingAck(_, _, _)).Times(0);
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_CLIENT_GOING_AWAY, true));
  EXPECT_CALL(*send_algorithm_, SentPacket(_, _, _)).Times(0);
  ProcessClosePacket(2, 0);
}

TEST_F(QuicConnectionTest, SendWhenDisconnected) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_CLIENT_GOING_AWAY, false));
  connection_.CloseConnection(QUIC_CLIENT_GOING_AWAY, false);
  EXPECT_FALSE(connection_.connected());
  QuicPacket* packet = ConstructDataPacket(1, 0);
  EXPECT_CALL(*send_algorithm_, SentPacket(1, _, _)).Times(0);
  connection_.SendOrQueuePacket(1, packet, false);
}

TEST_F(QuicConnectionTest, PublicReset) {
  QuicPublicResetPacket header;
  header.public_header.guid = guid_;
  header.public_header.flags = PACKET_PUBLIC_FLAGS_RST;
  header.rejected_sequence_number = 10101;
  scoped_ptr<QuicEncryptedPacket> packet(
      framer_.ConstructPublicResetPacket(header));
  EXPECT_CALL(visitor_, ConnectionClose(QUIC_PUBLIC_RESET, true));
  connection_.ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *packet);
}

}  // namespace
}  // namespace test
}  // namespace net
