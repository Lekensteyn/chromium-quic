// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server_session.h"

#include <algorithm>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_spdy_stream_peer.h"
#include "net/quic/test_tools/quic_sustained_bandwidth_recorder_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "net/tools/quic/quic_simple_server_stream.h"
#include "net/tools/quic/test_tools/mock_quic_server_session_visitor.h"
#include "net/tools/quic/test_tools/quic_in_memory_cache_peer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using __gnu_cxx::vector;
using net::test::CryptoTestUtils;
using net::test::MockConnection;
using net::test::MockConnectionHelper;
using net::test::QuicConfigPeer;
using net::test::QuicConnectionPeer;
using net::test::QuicSpdyStreamPeer;
using net::test::QuicSentPacketManagerPeer;
using net::test::QuicSessionPeer;
using net::test::QuicSpdySessionPeer;
using net::test::QuicSustainedBandwidthRecorderPeer;
using net::test::SupportedVersions;
using net::test::ValueRestore;
using net::test::kClientDataStreamId1;
using net::test::kClientDataStreamId2;
using net::test::kClientDataStreamId3;
using net::test::kInitialSessionFlowControlWindowForTest;
using net::test::kInitialStreamFlowControlWindowForTest;
using std::string;
using testing::StrictMock;
using testing::_;
using testing::InSequence;
using testing::Return;

namespace net {
namespace tools {
namespace test {
namespace {
typedef QuicSimpleServerSession::PromisedStreamInfo PromisedStreamInfo;
}  // namespace

class MockQuicHeadersStream : public QuicHeadersStream {
 public:
  explicit MockQuicHeadersStream(QuicSpdySession* session)
      : QuicHeadersStream(session) {}

  MOCK_METHOD4(WritePushPromise,
               size_t(QuicStreamId original_stream_id,
                      QuicStreamId promised_stream_id,
                      const SpdyHeaderBlock& headers,
                      QuicAckListenerInterface* ack_listener));

  MOCK_METHOD5(WriteHeaders,
               size_t(QuicStreamId stream_id,
                      const SpdyHeaderBlock& headers,
                      bool fin,
                      SpdyPriority priority,
                      QuicAckListenerInterface* ack_listener));
};

class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  explicit MockQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicSession* session)
      : QuicCryptoServerStream(crypto_config, session) {}
  ~MockQuicCryptoServerStream() override {}

  MOCK_METHOD1(SendServerConfigUpdate,
               void(const CachedNetworkParameters* cached_network_parameters));

  void set_encryption_established(bool has_established) {
    encryption_established_ = has_established;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockQuicCryptoServerStream);
};

class MockConnectionWithSendStreamData : public MockConnection {
 public:
  MockConnectionWithSendStreamData(MockConnectionHelper* helper,
                                   Perspective perspective,
                                   const QuicVersionVector& supported_versions)
      : MockConnection(helper, perspective, supported_versions) {}

  MOCK_METHOD6(SendStreamData,
               QuicConsumedData(QuicStreamId id,
                                QuicIOVector iov,
                                QuicStreamOffset offset,
                                bool fin,
                                FecProtection fec_protection,
                                QuicAckListenerInterface* listern));
};

class QuicSimpleServerSessionPeer {
 public:
  static void SetCryptoStream(QuicSimpleServerSession* s,
                              QuicCryptoServerStream* crypto_stream) {
    s->crypto_stream_.reset(crypto_stream);
    s->static_streams()[kCryptoStreamId] = crypto_stream;
  }

  static QuicSpdyStream* CreateIncomingDynamicStream(QuicSimpleServerSession* s,
                                                     QuicStreamId id) {
    return s->CreateIncomingDynamicStream(id);
  }

  static QuicSimpleServerStream* CreateOutgoingDynamicStream(
      QuicSimpleServerSession* s,
      SpdyPriority priority) {
    return s->CreateOutgoingDynamicStream(priority);
  }

  static std::deque<PromisedStreamInfo>* promised_streams(
      QuicSimpleServerSession* s) {
    return &(s->promised_streams_);
  }

  static QuicStreamId hightest_promised_stream_id(QuicSimpleServerSession* s) {
    return s->highest_promised_stream_id_;
  }
};

namespace {

const size_t kMaxStreamsForTest = 10;

class QuicSimpleServerSessionTest
    : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicSimpleServerSessionTest()
      : crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       CryptoTestUtils::ProofSourceForTesting()) {
    config_.SetMaxStreamsPerConnection(kMaxStreamsForTest, kMaxStreamsForTest);
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);

    connection_ = new StrictMock<MockConnectionWithSendStreamData>(
        &helper_, Perspective::IS_SERVER, SupportedVersions(GetParam()));
    session_.reset(new QuicSimpleServerSession(config_, connection_, &owner_,
                                               &crypto_config_));
    MockClock clock;
    handshake_message_.reset(crypto_config_.AddDefaultConfig(
        QuicRandom::GetInstance(), &clock,
        QuicCryptoServerConfig::ConfigOptions()));
    session_->Initialize();
    visitor_ = QuicConnectionPeer::GetVisitor(connection_);
    headers_stream_ = new MockQuicHeadersStream(session_.get());
    QuicSpdySessionPeer::SetHeadersStream(session_.get(), headers_stream_);
  }

  // Given |num_resources|, create this number of fake push resources and push
  // them by sending PUSH_PROMISE for all and sending push responses for as much
  // as possible(limited by kMaxStreamsForTest).
  // If |num_resources| > kMaxStreamsForTest, the left over will be queued.
  void PromisePushResources(size_t num_resources) {
    // Assume encryption already established.
    MockQuicCryptoServerStream* crypto_stream =
        new MockQuicCryptoServerStream(&crypto_config_, session_.get());
    crypto_stream->set_encryption_established(true);
    QuicSimpleServerSessionPeer::SetCryptoStream(session_.get(), crypto_stream);

    QuicInMemoryCachePeer::ResetForTests();

    string request_url = "mail.google.com/";
    SpdyHeaderBlock request_headers;
    string resource_host = "www.google.com";
    string partial_push_resource_path = "/server_push_src";
    string partial_push_response_body =
        "Push resource body " + partial_push_resource_path;
    list<QuicInMemoryCache::ServerPushInfo> push_resources;
    string scheme = "http";
    for (unsigned int i = 1; i <= num_resources; ++i) {
      string path = partial_push_resource_path + base::UintToString(i);
      string url = scheme + "://" + resource_host + path;
      GURL resource_url = GURL(url);
      string body = partial_push_response_body + base::UintToString(i);
      SpdyHeaderBlock response_headers;
      QuicInMemoryCache::GetInstance()->AddSimpleResponse(resource_host, path,
                                                          200, body);
      push_resources.push_back(QuicInMemoryCache::ServerPushInfo(
          resource_url, response_headers, kDefaultPriority, body));
      // PUSH_PROMISED are sent for all the resources.
      EXPECT_CALL(*headers_stream_,
                  WritePushPromise(kClientDataStreamId1, i * 2, _, nullptr));
      if (i <= kMaxStreamsForTest) {
        // |kMaxStreamsForTest| promised responses should be sent.
        EXPECT_CALL(*headers_stream_,
                    WriteHeaders(i * 2, _, false, kDefaultPriority, nullptr));
        // Mock that SendStreamData() returns less than supposed to send to keep
        // the stream open.
        EXPECT_CALL(*connection_, SendStreamData(i * 2, _, 0, true, _, nullptr))
            .WillOnce(Return(QuicConsumedData(0, false)));
      }
    }
    session_->PromisePushResources(request_url, push_resources,
                                   kClientDataStreamId1, request_headers);
  }

  StrictMock<MockQuicServerSessionVisitor> owner_;
  MockConnectionHelper helper_;
  StrictMock<MockConnectionWithSendStreamData>* connection_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  scoped_ptr<QuicSimpleServerSession> session_;
  scoped_ptr<CryptoHandshakeMessage> handshake_message_;
  QuicConnectionVisitorInterface* visitor_;
  MockQuicHeadersStream* headers_stream_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicSimpleServerSessionTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicSimpleServerSessionTest, CloseStreamDueToReset) {
  // Open a stream, then reset it.
  // Send two bytes of payload to open it.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());

  // Receive a reset (and send a RST in response).
  QuicRstStreamFrame rst1(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM,
                          0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());

  // Send the same two bytes of payload in a new packet.
  visitor_->OnStreamFrame(data1);

  // The stream should not be re-opened.
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, NeverOpenStreamDueToReset) {
  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM,
                          0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());

  // Send two bytes of payload.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  visitor_->OnStreamFrame(data1);

  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, AcceptClosedStream) {
  // Send (empty) compressed headers followed by two bytes of data.
  QuicStreamFrame frame1(kClientDataStreamId1, false, 0,
                         StringPiece("\1\0\0\0\0\0\0\0HT"));
  QuicStreamFrame frame2(kClientDataStreamId2, false, 0,
                         StringPiece("\2\0\0\0\0\0\0\0HT"));
  visitor_->OnStreamFrame(frame1);
  visitor_->OnStreamFrame(frame2);
  EXPECT_EQ(2u, session_->GetNumOpenIncomingStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst);

  // If we were tracking, we'd probably want to reject this because it's data
  // past the reset point of stream 3.  As it's a closed stream we just drop the
  // data on the floor, but accept the packet because it has data for stream 5.
  QuicStreamFrame frame3(kClientDataStreamId1, false, 2, StringPiece("TP"));
  QuicStreamFrame frame4(kClientDataStreamId2, false, 2, StringPiece("TP"));
  visitor_->OnStreamFrame(frame3);
  visitor_->OnStreamFrame(frame4);
  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, CreateIncomingDynamicStreamDisconnected) {
  // Tests that incoming stream creation fails when connection is not connected.
  size_t initial_num_open_stream = session_->GetNumOpenIncomingStreams();
  QuicConnectionPeer::CloseConnection(connection_);
  EXPECT_DFATAL(QuicSimpleServerSessionPeer::CreateIncomingDynamicStream(
                    session_.get(), kClientDataStreamId1),
                "ShouldCreateIncomingDynamicStream called when disconnected");
  EXPECT_EQ(initial_num_open_stream, session_->GetNumOpenIncomingStreams());
}

TEST_P(QuicSimpleServerSessionTest, CreateEvenIncomingDynamicStream) {
  // Tests that incoming stream creation fails when given stream id is even.
  size_t initial_num_open_stream = session_->GetNumOpenIncomingStreams();
  EXPECT_CALL(*connection_, SendConnectionCloseWithDetails(
                                QUIC_INVALID_STREAM_ID,
                                "Client created even numbered stream"));
  QuicSimpleServerSessionPeer::CreateIncomingDynamicStream(session_.get(), 2);
  EXPECT_EQ(initial_num_open_stream, session_->GetNumOpenIncomingStreams());
}

TEST_P(QuicSimpleServerSessionTest, CreateIncomingDynamicStream) {
  std::unique_ptr<QuicSpdyStream> stream(
      QuicSimpleServerSessionPeer::CreateIncomingDynamicStream(
          session_.get(), kClientDataStreamId1));
  EXPECT_NE(nullptr, stream);
  EXPECT_EQ(kClientDataStreamId1, stream->id());
}

TEST_P(QuicSimpleServerSessionTest, CreateOutgoingDynamicStreamDisconnected) {
  // Tests that outgoing stream creation fails when connection is not connected.
  size_t initial_num_open_stream = session_->GetNumOpenOutgoingStreams();
  QuicConnectionPeer::CloseConnection(connection_);
  EXPECT_DFATAL(QuicSimpleServerSessionPeer::CreateOutgoingDynamicStream(
                    session_.get(), kDefaultPriority),
                "ShouldCreateOutgoingDynamicStream called when disconnected");

  EXPECT_EQ(initial_num_open_stream, session_->GetNumOpenOutgoingStreams());
}

TEST_P(QuicSimpleServerSessionTest, CreateOutgoingDynamicStreamUnencrypted) {
  // Tests that outgoing stream creation fails when encryption has not yet been
  // established.
  size_t initial_num_open_stream = session_->GetNumOpenOutgoingStreams();
  EXPECT_DFATAL(QuicSimpleServerSessionPeer::CreateOutgoingDynamicStream(
                    session_.get(), kDefaultPriority),
                "Encryption not established so no outgoing stream created.");
  EXPECT_EQ(initial_num_open_stream, session_->GetNumOpenOutgoingStreams());
}

TEST_P(QuicSimpleServerSessionTest, CreateOutgoingDynamicStreamUptoLimit) {
  // Tests that outgoing stream creation should not be affected by existing
  // incoming stream and vice-versa. But when reaching the limit of max outgoing
  // stream allowed, creation should fail.

  // Receive some data to initiate a incoming stream which should not effect
  // creating outgoing streams.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());
  EXPECT_EQ(0u, session_->GetNumOpenOutgoingStreams());

  // Assume encryption already established.
  MockQuicCryptoServerStream* crypto_stream =
      new MockQuicCryptoServerStream(&crypto_config_, session_.get());
  crypto_stream->set_encryption_established(true);
  QuicSimpleServerSessionPeer::SetCryptoStream(session_.get(), crypto_stream);

  // Create push streams till reaching the upper limit of allowed open streams.
  for (size_t i = 0; i < kMaxStreamsForTest; ++i) {
    QuicSpdyStream* created_stream =
        QuicSimpleServerSessionPeer::CreateOutgoingDynamicStream(
            session_.get(), kDefaultPriority);
    EXPECT_EQ(2 * (i + 1), created_stream->id());
    EXPECT_EQ(i + 1, session_->GetNumOpenOutgoingStreams());
  }

  // Continuing creating push stream would fail.
  EXPECT_EQ(nullptr, QuicSimpleServerSessionPeer::CreateOutgoingDynamicStream(
                         session_.get(), kDefaultPriority));
  EXPECT_EQ(kMaxStreamsForTest, session_->GetNumOpenOutgoingStreams());

  // Create peer initiated stream should have no problem.
  QuicStreamFrame data2(kClientDataStreamId2, false, 0, StringPiece("HT"));
  session_->OnStreamFrame(data2);
  EXPECT_EQ(2u, session_->GetNumOpenIncomingStreams());
}

TEST_P(QuicSimpleServerSessionTest, OnStreamFrameWithEvenStreamId) {
  QuicStreamFrame frame(2, false, 0, StringPiece());
  EXPECT_CALL(*connection_, SendConnectionCloseWithDetails(
                                QUIC_INVALID_STREAM_ID,
                                "Client sent data on server push stream"));
  session_->OnStreamFrame(frame);
}

TEST_P(QuicSimpleServerSessionTest, TestPromisePushResources) {
  // Tests that given more than kMaxOpenStreamForTest resources, all their
  // PUSH_PROMISE's will be sent out and only |kMaxOpenStreamForTest| streams
  // will be opened and send push response.
  size_t num_resources = kMaxStreamsForTest + 5;
  PromisePushResources(num_resources);
  EXPECT_EQ(kMaxStreamsForTest, session_->GetNumOpenOutgoingStreams());
}

TEST_P(QuicSimpleServerSessionTest,
       HandlePromisedPushRequestsAfterStreamDraining) {
  // Tests that after promised stream queued up, when an opened stream is marked
  // draining, a queued promised stream will become open and send push response.
  size_t num_resources = kMaxStreamsForTest + 1;
  PromisePushResources(num_resources);
  QuicStreamId next_out_going_stream_id = num_resources * 2;

  // After an open stream is marked draining, a new stream is expected to be
  // created and a response sent on the stream.
  EXPECT_CALL(*headers_stream_, WriteHeaders(next_out_going_stream_id, _, false,
                                             kDefaultPriority, nullptr));
  EXPECT_CALL(*connection_,
              SendStreamData(next_out_going_stream_id, _, 0, true, _, nullptr))
      .WillOnce(Return(QuicConsumedData(0, false)));
  session_->StreamDraining(2);
  // Number of open outgoing streams should still be the same, because a new
  // stream is opened. And the queue should be empty.
  EXPECT_EQ(kMaxStreamsForTest, session_->GetNumOpenOutgoingStreams());
}

TEST_P(QuicSimpleServerSessionTest, GetEvenIncomingError) {
  // Tests that calling GetOrCreateDynamicStream() on an outgoing stream not
  // promised yet should result close connection.
  EXPECT_CALL(*connection_,
              SendConnectionCloseWithDetails(QUIC_INVALID_STREAM_ID,
                                             "Data for nonexistent stream"));
  EXPECT_EQ(nullptr,
            QuicSessionPeer::GetOrCreateDynamicStream(session_.get(), 4));
}

TEST_P(QuicSimpleServerSessionTest, ResetPromisedStreamToCancelServerPush) {
  // Tests that after all resources are promised, a RST frame from client can
  // prevent a promised resource to be send out.

  // Having two extra resources to be send later. One of them will be reset, so
  // when opened stream become close, only one will become open.
  size_t num_resources = kMaxStreamsForTest + 2;
  PromisePushResources(num_resources);

  // Reset the last stream in the queue. It should be marked cancelled.
  QuicStreamId stream_got_reset = num_resources * 2;
  QuicRstStreamFrame rst(stream_got_reset, QUIC_STREAM_CANCELLED, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(stream_got_reset, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst);

  // When the first 2 streams becomes draining, the two queued up stream could
  // be created. But since one of them was marked cancelled due to RST frame,
  // only one queued resource will be sent out.
  QuicStreamId stream_not_reset = (kMaxStreamsForTest + 1) * 2;
  InSequence s;
  EXPECT_CALL(*headers_stream_, WriteHeaders(stream_not_reset, _, false,
                                             kDefaultPriority, nullptr));
  EXPECT_CALL(*connection_,
              SendStreamData(stream_not_reset, _, 0, true, _, nullptr))
      .WillOnce(Return(QuicConsumedData(0, false)));
  EXPECT_CALL(*headers_stream_, WriteHeaders(stream_got_reset, _, false,
                                             kDefaultPriority, nullptr))
      .Times(0);

  session_->StreamDraining(2);
  session_->StreamDraining(4);
}

TEST_P(QuicSimpleServerSessionTest, CloseStreamToHandleMorePromisedStream) {
  // Tests that closing a open outgoing stream can trigger a promised resource
  // in the queue to be send out.
  size_t num_resources = kMaxStreamsForTest + 1;
  PromisePushResources(num_resources);
  QuicStreamId stream_to_open = num_resources * 2;

  // Resetting 1st open stream will close the stream and give space for extra
  // stream to be opened.
  QuicStreamId stream_got_reset = 2;
  EXPECT_CALL(*connection_,
              SendRstStream(stream_got_reset, QUIC_RST_ACKNOWLEDGEMENT, _));
  EXPECT_CALL(*headers_stream_, WriteHeaders(stream_to_open, _, false,
                                             kDefaultPriority, nullptr));
  EXPECT_CALL(*connection_,
              SendStreamData(stream_to_open, _, 0, true, _, nullptr))
      .WillOnce(Return(QuicConsumedData(0, false)));

  QuicRstStreamFrame rst(stream_got_reset, QUIC_STREAM_CANCELLED, 0);
  visitor_->OnRstStream(rst);
}

}  // namespace
}  // namespace test
}  // namespace tools
}  // namespace net
