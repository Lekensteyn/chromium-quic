// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quic/core/quic_unacked_packet_map.h"

#include "net/third_party/quic/core/quic_utils.h"
#include "net/third_party/quic/platform/api/quic_arraysize.h"
#include "net/third_party/quic/platform/api/quic_test.h"
#include "net/third_party/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class QuicUnackedPacketMapTest : public QuicTestWithParam<bool> {
 protected:
  QuicUnackedPacketMapTest()
      : unacked_packets_(),
        now_(QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1000)) {
    unacked_packets_.SetSessionNotifier(&notifier_);
    unacked_packets_.SetSessionDecideWhatToWrite(GetParam());
    EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(notifier_, OnStreamFrameRetransmitted(_))
        .Times(testing::AnyNumber());
  }

  ~QuicUnackedPacketMapTest() override {}

  SerializedPacket CreateRetransmittablePacket(QuicPacketNumber packet_number) {
    return CreateRetransmittablePacketForStream(packet_number,
                                                kHeadersStreamId);
  }

  SerializedPacket CreateRetransmittablePacketForStream(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id) {
    SerializedPacket packet(packet_number, PACKET_1BYTE_PACKET_NUMBER, nullptr,
                            kDefaultLength, false, false);
    QuicStreamFrame* frame = new QuicStreamFrame();
    frame->stream_id = stream_id;
    packet.retransmittable_frames.push_back(QuicFrame(frame));
    return packet;
  }

  SerializedPacket CreateNonRetransmittablePacket(
      QuicPacketNumber packet_number) {
    return SerializedPacket(packet_number, PACKET_1BYTE_PACKET_NUMBER, nullptr,
                            kDefaultLength, false, false);
  }

  void VerifyInFlightPackets(QuicPacketNumber* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_FALSE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      return;
    }
    if (num_packets == 1) {
      EXPECT_TRUE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      ASSERT_TRUE(unacked_packets_.IsUnacked(packets[0]));
      EXPECT_TRUE(unacked_packets_.GetTransmissionInfo(packets[0]).in_flight);
    }
    for (size_t i = 0; i < num_packets; ++i) {
      ASSERT_TRUE(unacked_packets_.IsUnacked(packets[i]));
      EXPECT_TRUE(unacked_packets_.GetTransmissionInfo(packets[i]).in_flight);
    }
    size_t in_flight_count = 0;
    for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
         it != unacked_packets_.end(); ++it) {
      if (it->in_flight) {
        ++in_flight_count;
      }
    }
    EXPECT_EQ(num_packets, in_flight_count);
  }

  void VerifyUnackedPackets(QuicPacketNumber* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_FALSE(unacked_packets_.HasUnackedPackets());
      EXPECT_FALSE(unacked_packets_.HasUnackedRetransmittableFrames());
      return;
    }
    EXPECT_TRUE(unacked_packets_.HasUnackedPackets());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.IsUnacked(packets[i])) << packets[i];
    }
    EXPECT_EQ(num_packets, unacked_packets_.GetNumUnackedPacketsDebugOnly());
  }

  void VerifyRetransmittablePackets(QuicPacketNumber* packets,
                                    size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    size_t num_retransmittable_packets = 0;
    for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
         it != unacked_packets_.end(); ++it) {
      if (unacked_packets_.HasRetransmittableFrames(*it)) {
        ++num_retransmittable_packets;
      }
    }
    EXPECT_EQ(num_packets, num_retransmittable_packets);
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.HasRetransmittableFrames(packets[i]))
          << " packets[" << i << "]:" << packets[i];
    }
  }

  void UpdatePacketState(QuicPacketNumber packet_number,
                         SentPacketState state) {
    unacked_packets_.GetMutableTransmissionInfo(packet_number)->state = state;
  }

  void RetransmitAndSendPacket(QuicPacketNumber old_packet_number,
                               QuicPacketNumber new_packet_number,
                               TransmissionType transmission_type) {
    DCHECK(unacked_packets_.HasRetransmittableFrames(old_packet_number));
    if (!unacked_packets_.session_decides_what_to_write()) {
      SerializedPacket packet(
          CreateNonRetransmittablePacket(new_packet_number));
      unacked_packets_.AddSentPacket(&packet, old_packet_number,
                                     transmission_type, now_, true);
      return;
    }
    const QuicTransmissionInfo& info =
        unacked_packets_.GetTransmissionInfo(old_packet_number);
    QuicStreamId stream_id = kHeadersStreamId;
    for (const auto& frame : info.retransmittable_frames) {
      if (frame.type == STREAM_FRAME) {
        stream_id = frame.stream_frame->stream_id;
        break;
      }
    }
    UpdatePacketState(
        old_packet_number,
        QuicUtils::RetransmissionTypeToPacketState(transmission_type));
    SerializedPacket packet(
        CreateRetransmittablePacketForStream(new_packet_number, stream_id));
    unacked_packets_.AddSentPacket(&packet, 0, transmission_type, now_, true);
  }
  QuicUnackedPacketMap unacked_packets_;
  QuicTime now_;
  StrictMock<MockSessionNotifier> notifier_;
};

INSTANTIATE_TEST_CASE_P(Tests, QuicUnackedPacketMapTest, testing::Bool());

TEST_P(QuicUnackedPacketMapTest, RttOnly) {
  // Acks are only tracked for RTT measurement purposes.
  SerializedPacket packet(CreateNonRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, false);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmittableInflightAndRtt) {
  // Simulate a retransmittable packet being sent and acked.
  SerializedPacket packet(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(unacked, QUIC_ARRAYSIZE(unacked));

  unacked_packets_.RemoveRetransmittability(1);
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(1);
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  QuicPacketNumber retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable,
                               QUIC_ARRAYSIZE(retransmittable));

  if (unacked_packets_.session_decides_what_to_write()) {
    EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  } else {
    unacked_packets_.CancelRetransmissionsForStream(stream_id);
  }
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmissionOnOtherStream) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  QuicPacketNumber retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable,
                               QUIC_ARRAYSIZE(retransmittable));

  // Stop retransmissions on another stream and verify the packet is unchanged.
  if (!unacked_packets_.session_decides_what_to_write()) {
    unacked_packets_.CancelRetransmissionsForStream(stream_id + 2);
  }
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(retransmittable,
                               QUIC_ARRAYSIZE(retransmittable));
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmissionAfterRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet1(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  RetransmitAndSendPacket(1, 2, LOSS_RETRANSMISSION);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  std::vector<QuicPacketNumber> retransmittable;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable = {1, 2};
  } else {
    retransmittable = {2};
  }
  VerifyRetransmittablePackets(&retransmittable[0], retransmittable.size());

  if (unacked_packets_.session_decides_what_to_write()) {
    EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  } else {
    unacked_packets_.CancelRetransmissionsForStream(stream_id);
  }
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmittedPacket) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  RetransmitAndSendPacket(1, 2, LOSS_RETRANSMISSION);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  std::vector<QuicPacketNumber> retransmittable;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable = {1, 2};
  } else {
    retransmittable = {2};
  }
  VerifyRetransmittablePackets(&retransmittable[0], retransmittable.size());

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  unacked_packets_.RemoveRetransmittability(1);
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(2);
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(2);
  QuicPacketNumber unacked2[] = {1};
  VerifyUnackedPackets(unacked2, QUIC_ARRAYSIZE(unacked2));
  VerifyInFlightPackets(unacked2, QUIC_ARRAYSIZE(unacked2));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmitThreeTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  QuicPacketNumber retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable,
                               QUIC_ARRAYSIZE(retransmittable));

  // Early retransmit 1 as 3 and send new data as 4.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveRetransmittability(2);
  unacked_packets_.RemoveFromInFlight(1);
  RetransmitAndSendPacket(1, 3, LOSS_RETRANSMISSION);
  SerializedPacket packet4(CreateRetransmittablePacket(4));
  unacked_packets_.AddSentPacket(&packet4, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked2[] = {1, 3, 4};
  VerifyUnackedPackets(unacked2, QUIC_ARRAYSIZE(unacked2));
  QuicPacketNumber pending2[] = {3, 4};
  VerifyInFlightPackets(pending2, QUIC_ARRAYSIZE(pending2));
  std::vector<QuicPacketNumber> retransmittable2;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable2 = {1, 3, 4};
  } else {
    retransmittable2 = {3, 4};
  }
  VerifyRetransmittablePackets(&retransmittable2[0], retransmittable2.size());

  // Early retransmit 3 (formerly 1) as 5, and remove 1 from unacked.
  unacked_packets_.IncreaseLargestObserved(4);
  unacked_packets_.RemoveFromInFlight(4);
  unacked_packets_.RemoveRetransmittability(4);
  RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);
  SerializedPacket packet6(CreateRetransmittablePacket(6));
  unacked_packets_.AddSentPacket(&packet6, 0, NOT_RETRANSMISSION, now_, true);

  std::vector<QuicPacketNumber> unacked3;
  std::vector<QuicPacketNumber> retransmittable3;
  if (unacked_packets_.session_decides_what_to_write()) {
    unacked3 = {1, 3, 5, 6};
    retransmittable3 = {1, 3, 5, 6};
  } else {
    unacked3 = {3, 5, 6};
    retransmittable3 = {5, 6};
  }
  VerifyUnackedPackets(&unacked3[0], unacked3.size());
  VerifyRetransmittablePackets(&retransmittable3[0], retransmittable3.size());
  QuicPacketNumber pending3[] = {3, 5, 6};
  VerifyInFlightPackets(pending3, QUIC_ARRAYSIZE(pending3));

  // Early retransmit 5 as 7 and ensure in flight packet 3 is not removed.
  unacked_packets_.IncreaseLargestObserved(6);
  unacked_packets_.RemoveFromInFlight(6);
  unacked_packets_.RemoveRetransmittability(6);
  RetransmitAndSendPacket(5, 7, LOSS_RETRANSMISSION);

  std::vector<QuicPacketNumber> unacked4;
  std::vector<QuicPacketNumber> retransmittable4;
  if (unacked_packets_.session_decides_what_to_write()) {
    unacked4 = {1, 3, 5, 7};
    retransmittable4 = {1, 3, 5, 7};
  } else {
    unacked4 = {3, 5, 7};
    retransmittable4 = {7};
  }
  VerifyUnackedPackets(&unacked4[0], unacked4.size());
  VerifyRetransmittablePackets(&retransmittable4[0], retransmittable4.size());
  QuicPacketNumber pending4[] = {3, 5, 7};
  VerifyInFlightPackets(pending4, QUIC_ARRAYSIZE(pending4));

  // Remove the older two transmissions from in flight.
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(5);
  QuicPacketNumber pending5[] = {7};
  VerifyInFlightPackets(pending5, QUIC_ARRAYSIZE(pending5));
}

TEST_P(QuicUnackedPacketMapTest, RetransmitFourTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, QUIC_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, QUIC_ARRAYSIZE(unacked));
  QuicPacketNumber retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable,
                               QUIC_ARRAYSIZE(retransmittable));

  // Early retransmit 1 as 3.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveRetransmittability(2);
  unacked_packets_.RemoveFromInFlight(1);
  RetransmitAndSendPacket(1, 3, LOSS_RETRANSMISSION);

  QuicPacketNumber unacked2[] = {1, 3};
  VerifyUnackedPackets(unacked2, QUIC_ARRAYSIZE(unacked2));
  QuicPacketNumber pending2[] = {3};
  VerifyInFlightPackets(pending2, QUIC_ARRAYSIZE(pending2));
  std::vector<QuicPacketNumber> retransmittable2;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable2 = {1, 3};
  } else {
    retransmittable2 = {3};
  }
  VerifyRetransmittablePackets(&retransmittable2[0], retransmittable2.size());

  // TLP 3 (formerly 1) as 4, and don't remove 1 from unacked.
  RetransmitAndSendPacket(3, 4, TLP_RETRANSMISSION);
  SerializedPacket packet5(CreateRetransmittablePacket(5));
  unacked_packets_.AddSentPacket(&packet5, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked3[] = {1, 3, 4, 5};
  VerifyUnackedPackets(unacked3, QUIC_ARRAYSIZE(unacked3));
  QuicPacketNumber pending3[] = {3, 4, 5};
  VerifyInFlightPackets(pending3, QUIC_ARRAYSIZE(pending3));
  std::vector<QuicPacketNumber> retransmittable3;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable3 = {1, 3, 4, 5};
  } else {
    retransmittable3 = {4, 5};
  }
  VerifyRetransmittablePackets(&retransmittable3[0], retransmittable3.size());

  // Early retransmit 4 as 6 and ensure in flight packet 3 is removed.
  unacked_packets_.IncreaseLargestObserved(5);
  unacked_packets_.RemoveFromInFlight(5);
  unacked_packets_.RemoveRetransmittability(5);
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(4);
  RetransmitAndSendPacket(4, 6, LOSS_RETRANSMISSION);

  std::vector<QuicPacketNumber> unacked4;
  if (unacked_packets_.session_decides_what_to_write()) {
    unacked4 = {1, 3, 4, 6};
  } else {
    unacked4 = {4, 6};
  }
  VerifyUnackedPackets(&unacked4[0], unacked4.size());
  QuicPacketNumber pending4[] = {6};
  VerifyInFlightPackets(pending4, QUIC_ARRAYSIZE(pending4));
  std::vector<QuicPacketNumber> retransmittable4;
  if (unacked_packets_.session_decides_what_to_write()) {
    retransmittable4 = {1, 3, 4, 6};
  } else {
    retransmittable4 = {6};
  }
  VerifyRetransmittablePackets(&retransmittable4[0], retransmittable4.size());
}

TEST_P(QuicUnackedPacketMapTest, SendWithGap) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet3(CreateRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, 0, NOT_RETRANSMISSION, now_, true);
  RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);

  EXPECT_EQ(1u, unacked_packets_.GetLeastUnacked());
  EXPECT_TRUE(unacked_packets_.IsUnacked(1));
  EXPECT_FALSE(unacked_packets_.IsUnacked(2));
  EXPECT_TRUE(unacked_packets_.IsUnacked(3));
  EXPECT_FALSE(unacked_packets_.IsUnacked(4));
  EXPECT_TRUE(unacked_packets_.IsUnacked(5));
  EXPECT_EQ(5u, unacked_packets_.largest_sent_packet());
}

}  // namespace
}  // namespace test
}  // namespace quic
