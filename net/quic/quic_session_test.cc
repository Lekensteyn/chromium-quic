// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_session.h"

#include <set>
#include <vector>

#include "base/basictypes.h"
#include "base/containers/hash_tables.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_crypto_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_utils.h"
#include "net/quic/reliable_quic_stream.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_data_stream_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/spdy/spdy_framer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::hash_map;
using std::set;
using std::vector;
using testing::_;
using testing::InSequence;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::StrictMock;

namespace net {
namespace test {
namespace {

const QuicPriority kHighestPriority = 0;
const QuicPriority kSomeMiddlePriority = 3;

class TestCryptoStream : public QuicCryptoStream {
 public:
  explicit TestCryptoStream(QuicSession* session)
      : QuicCryptoStream(session) {
  }

  virtual void OnHandshakeMessage(
      const CryptoHandshakeMessage& message) OVERRIDE {
    encryption_established_ = true;
    handshake_confirmed_ = true;
    CryptoHandshakeMessage msg;
    string error_details;
    session()->config()->ToHandshakeMessage(&msg);
    const QuicErrorCode error = session()->config()->ProcessClientHello(
        msg, &error_details);
    EXPECT_EQ(QUIC_NO_ERROR, error);
    session()->OnConfigNegotiated();
    session()->OnCryptoHandshakeEvent(QuicSession::HANDSHAKE_CONFIRMED);
  }

  MOCK_METHOD0(OnCanWrite, void());
};

class TestStream : public QuicDataStream {
 public:
  TestStream(QuicStreamId id, QuicSession* session)
      : QuicDataStream(id, session) {
  }

  using ReliableQuicStream::CloseWriteSide;

  virtual uint32 ProcessData(const char* data, uint32 data_len) {
    return data_len;
  }

  MOCK_METHOD0(OnCanWrite, void());
};

// Poor man's functor for use as callback in a mock.
class StreamBlocker {
 public:
  StreamBlocker(QuicSession* session, QuicStreamId stream_id)
      : session_(session),
        stream_id_(stream_id) {
  }

  void MarkWriteBlocked() {
    session_->MarkWriteBlocked(stream_id_, kSomeMiddlePriority);
  }

 private:
  QuicSession* const session_;
  const QuicStreamId stream_id_;
};

class TestSession : public QuicSession {
 public:
  explicit TestSession(QuicConnection* connection)
      : QuicSession(connection, DefaultQuicConfig()),
        crypto_stream_(this) {
  }

  virtual TestCryptoStream* GetCryptoStream() OVERRIDE {
    return &crypto_stream_;
  }

  virtual TestStream* CreateOutgoingDataStream() OVERRIDE {
    TestStream* stream = new TestStream(GetNextStreamId(), this);
    ActivateStream(stream);
    return stream;
  }

  virtual TestStream* CreateIncomingDataStream(QuicStreamId id) OVERRIDE {
    return new TestStream(id, this);
  }

  bool IsClosedStream(QuicStreamId id) {
    return QuicSession::IsClosedStream(id);
  }

  QuicDataStream* GetIncomingDataStream(QuicStreamId stream_id) {
    return QuicSession::GetIncomingDataStream(stream_id);
  }

  TestCryptoStream crypto_stream_;
};

class QuicSessionTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicSessionTest()
      : connection_(new MockConnection(true, SupportedVersions(GetParam()))),
        session_(connection_) {
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "http";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
  }

  void CheckClosedStreams() {
    for (int i = kCryptoStreamId; i < 100; i++) {
      if (closed_streams_.count(i) == 0) {
        EXPECT_FALSE(session_.IsClosedStream(i)) << " stream id: " << i;
      } else {
        EXPECT_TRUE(session_.IsClosedStream(i)) << " stream id: " << i;
      }
    }
  }

  void CloseStream(QuicStreamId id) {
    session_.CloseStream(id);
    closed_streams_.insert(id);
  }

  MockConnection* connection_;
  TestSession session_;
  set<QuicStreamId> closed_streams_;
  SpdyHeaderBlock headers_;
};

INSTANTIATE_TEST_CASE_P(Tests, QuicSessionTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicSessionTest, PeerAddress) {
  EXPECT_EQ(IPEndPoint(Loopback4(), kTestPort), session_.peer_address());
}

TEST_P(QuicSessionTest, IsCryptoHandshakeConfirmed) {
  EXPECT_FALSE(session_.IsCryptoHandshakeConfirmed());
  CryptoHandshakeMessage message;
  session_.crypto_stream_.OnHandshakeMessage(message);
  EXPECT_TRUE(session_.IsCryptoHandshakeConfirmed());
}

TEST_P(QuicSessionTest, IsClosedStreamDefault) {
  // Ensure that no streams are initially closed.
  for (int i = kCryptoStreamId; i < 100; i++) {
    EXPECT_FALSE(session_.IsClosedStream(i)) << "stream id: " << i;
  }
}

TEST_P(QuicSessionTest, ImplicitlyCreatedStreams) {
  ASSERT_TRUE(session_.GetIncomingDataStream(7) != NULL);
  // Both 3 and 5 should be implicitly created.
  EXPECT_FALSE(session_.IsClosedStream(3));
  EXPECT_FALSE(session_.IsClosedStream(5));
  ASSERT_TRUE(session_.GetIncomingDataStream(5) != NULL);
  ASSERT_TRUE(session_.GetIncomingDataStream(3) != NULL);
}

TEST_P(QuicSessionTest, IsClosedStreamLocallyCreated) {
  TestStream* stream2 = session_.CreateOutgoingDataStream();
  EXPECT_EQ(2u, stream2->id());
  TestStream* stream4 = session_.CreateOutgoingDataStream();
  EXPECT_EQ(4u, stream4->id());
  if (GetParam() <= QUIC_VERSION_12) {
    QuicDataStreamPeer::SetHeadersDecompressed(stream2, true);
    QuicDataStreamPeer::SetHeadersDecompressed(stream4, true);
  }

  CheckClosedStreams();
  CloseStream(4);
  CheckClosedStreams();
  CloseStream(2);
  CheckClosedStreams();
}

TEST_P(QuicSessionTest, IsClosedStreamPeerCreated) {
  QuicStreamId stream_id1 = GetParam() > QUIC_VERSION_12 ? 5 : 3;
  QuicStreamId stream_id2 = stream_id1 + 2;
  QuicDataStream* stream1 = session_.GetIncomingDataStream(stream_id1);
  QuicDataStreamPeer::SetHeadersDecompressed(stream1, true);
  QuicDataStream* stream2 = session_.GetIncomingDataStream(stream_id2);
  QuicDataStreamPeer::SetHeadersDecompressed(stream2, true);

  CheckClosedStreams();
  CloseStream(stream_id1);
  CheckClosedStreams();
  CloseStream(stream_id2);
  // Create a stream explicitly, and another implicitly.
  QuicDataStream* stream3 = session_.GetIncomingDataStream(stream_id2 + 4);
  QuicDataStreamPeer::SetHeadersDecompressed(stream3, true);
  CheckClosedStreams();
  // Close one, but make sure the other is still not closed
  CloseStream(stream3->id());
  CheckClosedStreams();
}

TEST_P(QuicSessionTest, StreamIdTooLarge) {
  QuicStreamId stream_id = GetParam() > QUIC_VERSION_12 ? 5 : 3;
  session_.GetIncomingDataStream(stream_id);
  EXPECT_CALL(*connection_, SendConnectionClose(QUIC_INVALID_STREAM_ID));
  session_.GetIncomingDataStream(stream_id + 102);
}

TEST_P(QuicSessionTest, DecompressionError) {
  if (GetParam() > QUIC_VERSION_12) {
    QuicHeadersStream* stream = QuicSessionPeer::GetHeadersStream(&session_);
    const unsigned char data[] = {
        0x80, 0x03, 0x00, 0x01,  // SPDY/3 SYN_STREAM frame
        0x00, 0x00, 0x00, 0x25,  // flags/length
        0x00, 0x00, 0x00, 0x05,  // stream id
        0x00, 0x00, 0x00, 0x00,  // associated stream id
        0x00, 0x00,
        'a',  'b',  'c',  'd'    // invalid compressed data
    };
    EXPECT_CALL(*connection_,
                SendConnectionCloseWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                               "SPDY framing error."));
    stream->ProcessRawData(reinterpret_cast<const char*>(data),
                           arraysize(data));
  } else {
    ReliableQuicStream* stream = session_.GetIncomingDataStream(3);
    const char data[] =
        "\0\0\0\0"   // priority
        "\1\0\0\0"   // headers id
        "\0\0\0\4"   // length
        "abcd";      // invalid compressed data
    EXPECT_CALL(*connection_, SendConnectionClose(QUIC_DECOMPRESSION_FAILURE));
    stream->ProcessRawData(data, arraysize(data));
  }
}

TEST_P(QuicSessionTest, DebugDFatalIfMarkingClosedStreamWriteBlocked) {
  TestStream* stream2 = session_.CreateOutgoingDataStream();
  // Close the stream.
  stream2->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
  // TODO(rtenneti): enable when chromium supports EXPECT_DEBUG_DFATAL.
  /*
  QuicStreamId kClosedStreamId = stream2->id();
  EXPECT_DEBUG_DFATAL(
      session_.MarkWriteBlocked(kClosedStreamId, kSomeMiddlePriority),
      "Marking unknown stream 2 blocked.");
  */
}

TEST_P(QuicSessionTest, DebugDFatalIfMarkWriteBlockedCalledWithWrongPriority) {
  const QuicPriority kDifferentPriority = 0;

  TestStream* stream2 = session_.CreateOutgoingDataStream();
  EXPECT_NE(kDifferentPriority, stream2->EffectivePriority());
  // TODO(rtenneti): enable when chromium supports EXPECT_DEBUG_DFATAL.
  /*
  EXPECT_DEBUG_DFATAL(
      session_.MarkWriteBlocked(stream2->id(), kDifferentPriority),
      "Priorities do not match.  Got: 0 Expected: 3");
  */
}

TEST_P(QuicSessionTest, OnCanWrite) {
  TestStream* stream2 = session_.CreateOutgoingDataStream();
  TestStream* stream4 = session_.CreateOutgoingDataStream();
  TestStream* stream6 = session_.CreateOutgoingDataStream();

  session_.MarkWriteBlocked(stream2->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream6->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream4->id(), kSomeMiddlePriority);

  InSequence s;
  StreamBlocker stream2_blocker(&session_, stream2->id());
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(
      // Reregister, to test the loop limit.
      InvokeWithoutArgs(&stream2_blocker, &StreamBlocker::MarkWriteBlocked));
  EXPECT_CALL(*stream6, OnCanWrite());
  EXPECT_CALL(*stream4, OnCanWrite());

  EXPECT_FALSE(session_.OnCanWrite());
}

TEST_P(QuicSessionTest, OnCanWriteCongestionControlBlocks) {
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);

  TestStream* stream2 = session_.CreateOutgoingDataStream();
  TestStream* stream4 = session_.CreateOutgoingDataStream();
  TestStream* stream6 = session_.CreateOutgoingDataStream();

  session_.MarkWriteBlocked(stream2->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream6->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream4->id(), kSomeMiddlePriority);

  StreamBlocker stream2_blocker(&session_, stream2->id());
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _, _, _)).WillOnce(Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _, _, _)).WillOnce(Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream6, OnCanWrite());
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _, _, _)).WillOnce(Return(
      QuicTime::Delta::Infinite()));
  // stream4->OnCanWrite is not called.

  // TODO(avd) change return value to 'true', since the connection
  // can't write because it is congestion control blocked.
  EXPECT_FALSE(session_.OnCanWrite());

  // Still congestion-control blocked.
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _, _, _)).WillOnce(Return(
      QuicTime::Delta::Infinite()));
  EXPECT_FALSE(session_.OnCanWrite());

  // stream4->OnCanWrite is called once the connection stops being
  // congestion-control blocked.
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _, _, _)).WillOnce(Return(
      QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_TRUE(session_.OnCanWrite());
}

TEST_P(QuicSessionTest, BufferedHandshake) {
  EXPECT_FALSE(session_.HasPendingHandshake());  // Default value.

  // Test that blocking other streams does not change our status.
  TestStream* stream2 = session_.CreateOutgoingDataStream();
  StreamBlocker stream2_blocker(&session_, stream2->id());
  stream2_blocker.MarkWriteBlocked();
  EXPECT_FALSE(session_.HasPendingHandshake());

  TestStream* stream3 = session_.CreateOutgoingDataStream();
  StreamBlocker stream3_blocker(&session_, stream3->id());
  stream3_blocker.MarkWriteBlocked();
  EXPECT_FALSE(session_.HasPendingHandshake());

  // Blocking (due to buffering of) the Crypto stream is detected.
  session_.MarkWriteBlocked(kCryptoStreamId, kHighestPriority);
  EXPECT_TRUE(session_.HasPendingHandshake());

  TestStream* stream4 = session_.CreateOutgoingDataStream();
  StreamBlocker stream4_blocker(&session_, stream4->id());
  stream4_blocker.MarkWriteBlocked();
  EXPECT_TRUE(session_.HasPendingHandshake());

  InSequence s;
  // Force most streams to re-register, which is common scenario when we block
  // the Crypto stream, and only the crypto stream can "really" write.

  // Due to prioritization, we *should* be asked to write the crypto stream
  // first.
  // Don't re-register the crypto stream (which signals complete writing).
  TestCryptoStream* crypto_stream = session_.GetCryptoStream();
  EXPECT_CALL(*crypto_stream, OnCanWrite());

  // Re-register all other streams, to show they weren't able to proceed.
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(
      InvokeWithoutArgs(&stream2_blocker, &StreamBlocker::MarkWriteBlocked));

  EXPECT_CALL(*stream3, OnCanWrite()).WillOnce(
      InvokeWithoutArgs(&stream3_blocker, &StreamBlocker::MarkWriteBlocked));

  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(
      InvokeWithoutArgs(&stream4_blocker, &StreamBlocker::MarkWriteBlocked));

  EXPECT_FALSE(session_.OnCanWrite());
  EXPECT_FALSE(session_.HasPendingHandshake());  // Crypto stream wrote.
}

TEST_P(QuicSessionTest, OnCanWriteWithClosedStream) {
  TestStream* stream2 = session_.CreateOutgoingDataStream();
  TestStream* stream4 = session_.CreateOutgoingDataStream();
  TestStream* stream6 = session_.CreateOutgoingDataStream();

  session_.MarkWriteBlocked(stream2->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream6->id(), kSomeMiddlePriority);
  session_.MarkWriteBlocked(stream4->id(), kSomeMiddlePriority);
  CloseStream(stream6->id());

  InSequence s;
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_TRUE(session_.OnCanWrite());
}

// Regression test for http://crbug.com/248737
TEST_P(QuicSessionTest, OutOfOrderHeaders) {
  QuicSpdyCompressor compressor;
  vector<QuicStreamFrame> frames;
  QuicPacketHeader header;
  header.public_header.guid = session_.guid();

  TestStream* stream2 = session_.CreateOutgoingDataStream();
  TestStream* stream4 = session_.CreateOutgoingDataStream();
  stream2->CloseWriteSide();
  stream4->CloseWriteSide();

  // Create frame with headers for stream2.
  string compressed_headers1 = compressor.CompressHeaders(headers_);
  QuicStreamFrame frame1(
      stream2->id(), false, 0, MakeIOVector(compressed_headers1));

  // Create frame with headers for stream4.
  string compressed_headers2 = compressor.CompressHeaders(headers_);
  QuicStreamFrame frame2(
      stream4->id(), true, 0, MakeIOVector(compressed_headers2));

  // Process the second frame first.  This will cause the headers to
  // be queued up and processed after the first frame is processed.
  frames.push_back(frame2);
  session_.OnStreamFrames(frames);

  // Process the first frame, and un-cork the buffered headers.
  frames[0] = frame1;
  session_.OnStreamFrames(frames);

  // Ensure that the streams actually close and we don't DCHECK.
  connection_->CloseConnection(QUIC_CONNECTION_TIMED_OUT, true);
}

TEST_P(QuicSessionTest, SendGoAway) {
  // After sending a GoAway, ensure new incoming streams cannot be created and
  // result in a RST being sent.
  EXPECT_CALL(*connection_,
              SendGoAway(QUIC_PEER_GOING_AWAY, 0u, "Going Away."));
  session_.SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_.goaway_sent());

  EXPECT_CALL(*connection_, SendRstStream(3u, QUIC_STREAM_PEER_GOING_AWAY));
  EXPECT_FALSE(session_.GetIncomingDataStream(3u));
}

TEST_P(QuicSessionTest, IncreasedTimeoutAfterCryptoHandshake) {
  EXPECT_EQ(kDefaultInitialTimeoutSecs,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
  CryptoHandshakeMessage msg;
  session_.crypto_stream_.OnHandshakeMessage(msg);
  EXPECT_EQ(kDefaultTimeoutSecs,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
}

TEST_P(QuicSessionTest, ZombieStream) {
  QuicStreamId stream_id1 = GetParam() > QUIC_VERSION_12 ? 5 : 3;
  QuicStreamId stream_id2 = stream_id1 + 2;
  StrictMock<MockConnection>* connection =
      new StrictMock<MockConnection>(false, SupportedVersions(GetParam()));
  TestSession session(connection);

  TestStream* stream1 = session.CreateOutgoingDataStream();
  EXPECT_EQ(stream_id1, stream1->id());
  TestStream* stream2 = session.CreateOutgoingDataStream();
  EXPECT_EQ(stream_id2, stream2->id());
  EXPECT_EQ(2u, session.GetNumOpenStreams());

  // Reset the stream, but since the headers have not been decompressed
  // it will become a zombie and will continue to process data
  // until the headers are decompressed.
  EXPECT_CALL(*connection, SendRstStream(stream_id1, QUIC_STREAM_CANCELLED));
  session.SendRstStream(stream_id1, QUIC_STREAM_CANCELLED);

  EXPECT_EQ(1u, session.GetNumOpenStreams());

  vector<QuicStreamFrame> frames;
  QuicPacketHeader header;
  header.public_header.guid = session_.guid();

  // Create frame with headers for stream2.
  QuicSpdyCompressor compressor;
  string compressed_headers1 = compressor.CompressHeaders(headers_);
  QuicStreamFrame frame1(
      stream1->id(), false, 0, MakeIOVector(compressed_headers1));

  // Process the second frame first.  This will cause the headers to
  // be queued up and processed after the first frame is processed.
  frames.push_back(frame1);
  EXPECT_FALSE(stream1->headers_decompressed());

  session.OnStreamFrames(frames);
  EXPECT_EQ(1u, session.GetNumOpenStreams());

  EXPECT_TRUE(connection->connected());
}

TEST_P(QuicSessionTest, ZombieStreamConnectionClose) {
  QuicStreamId stream_id1 = GetParam() > QUIC_VERSION_12 ? 5 : 3;
  QuicStreamId stream_id2 = stream_id1 + 2;
  StrictMock<MockConnection>* connection =
      new StrictMock<MockConnection>(false, SupportedVersions(GetParam()));
  TestSession session(connection);

  TestStream* stream1 = session.CreateOutgoingDataStream();
  EXPECT_EQ(stream_id1, stream1->id());
  TestStream* stream2 = session.CreateOutgoingDataStream();
  EXPECT_EQ(stream_id2, stream2->id());
  EXPECT_EQ(2u, session.GetNumOpenStreams());

  stream1->CloseWriteSide();
  // Reset the stream, but since the headers have not been decompressed
  // it will become a zombie and will continue to process data
  // until the headers are decompressed.
  EXPECT_CALL(*connection, SendRstStream(stream_id1, QUIC_STREAM_CANCELLED));
  session.SendRstStream(stream_id1, QUIC_STREAM_CANCELLED);

  EXPECT_EQ(1u, session.GetNumOpenStreams());

  connection->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);

  EXPECT_EQ(0u, session.GetNumOpenStreams());
}

TEST_P(QuicSessionTest, RstStreamBeforeHeadersDecompressed) {
  QuicStreamId stream_id1 = GetParam() > QUIC_VERSION_12 ? 5 : 3;
  // Send two bytes of payload.
  QuicStreamFrame data1(stream_id1, false, 0, MakeIOVector("HT"));
  vector<QuicStreamFrame> frames;
  frames.push_back(data1);
  EXPECT_TRUE(session_.OnStreamFrames(frames));
  EXPECT_EQ(1u, session_.GetNumOpenStreams());

  if (GetParam() <= QUIC_VERSION_12) {
    // Send a reset before the headers have been decompressed.  This causes
    // an unrecoverable compression context state.
    EXPECT_CALL(*connection_, SendConnectionClose(
        QUIC_STREAM_RST_BEFORE_HEADERS_DECOMPRESSED));
  }

  QuicRstStreamFrame rst1(stream_id1, QUIC_STREAM_NO_ERROR);
  session_.OnRstStream(rst1);
  EXPECT_EQ(0u, session_.GetNumOpenStreams());
}

}  // namespace
}  // namespace test
}  // namespace net
