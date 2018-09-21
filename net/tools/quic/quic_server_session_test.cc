// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_server_session.h"

#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_data_stream_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_spdy_server_stream.h"
#include "net/tools/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using __gnu_cxx::vector;
using net::test::MockConnection;
using net::test::QuicConnectionPeer;
using net::test::QuicDataStreamPeer;
using net::test::SupportedVersions;
using testing::StrictMock;
using testing::_;

namespace net {
namespace tools {
namespace test {

class QuicServerSessionPeer {
 public:
  static QuicDataStream* GetIncomingDataStream(
      QuicServerSession* s, QuicStreamId id) {
    return s->GetIncomingDataStream(id);
  }
  static QuicDataStream* GetDataStream(QuicServerSession* s, QuicStreamId id) {
    return s->GetDataStream(id);
  }
};

namespace {

class QuicServerSessionTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicServerSessionTest()
      : crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance()) {
    config_.SetDefaults();
    config_.set_max_streams_per_connection(3, 3);

    connection_ =
        new StrictMock<MockConnection>(true, SupportedVersions(GetParam()));
    session_.reset(new QuicServerSession(
        config_, connection_, &owner_));
    session_->InitializeSession(crypto_config_);
    visitor_ = QuicConnectionPeer::GetVisitor(connection_);
  }

  QuicVersion version() const { return connection_->version(); }

  StrictMock<MockQuicServerSessionVisitor> owner_;
  StrictMock<MockConnection>* connection_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  scoped_ptr<QuicServerSession> session_;
  QuicConnectionVisitorInterface* visitor_;
};

INSTANTIATE_TEST_CASE_P(Tests, QuicServerSessionTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicServerSessionTest, CloseStreamDueToReset) {
  QuicStreamId stream_id = 5;
  // Open a stream, then reset it.
  // Send two bytes of payload to open it.
  QuicStreamFrame data1(stream_id, false, 0, MakeIOVector("HT"));
  vector<QuicStreamFrame> frames;
  frames.push_back(data1);
  session_->OnStreamFrames(frames);
  EXPECT_EQ(1u, session_->GetNumOpenStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(stream_id, QUIC_STREAM_NO_ERROR, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(stream_id, QUIC_RST_FLOW_CONTROL_ACCOUNTING, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenStreams());

  // Send the same two bytes of payload in a new packet.
  visitor_->OnStreamFrames(frames);

  // The stream should not be re-opened.
  EXPECT_EQ(0u, session_->GetNumOpenStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionTest, NeverOpenStreamDueToReset) {
  QuicStreamId stream_id = 5;

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(stream_id, QUIC_STREAM_NO_ERROR, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(stream_id, QUIC_RST_FLOW_CONTROL_ACCOUNTING, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenStreams());

  // Send two bytes of payload.
  QuicStreamFrame data1(stream_id, false, 0, MakeIOVector("HT"));
  vector<QuicStreamFrame> frames;
  frames.push_back(data1);
  visitor_->OnStreamFrames(frames);

  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(0u, session_->GetNumOpenStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionTest, AcceptClosedStream) {
  QuicStreamId stream_id = 5;
  vector<QuicStreamFrame> frames;
  // Send (empty) compressed headers followed by two bytes of data.
  frames.push_back(QuicStreamFrame(stream_id, false, 0,
                                   MakeIOVector("\1\0\0\0\0\0\0\0HT")));
  frames.push_back(QuicStreamFrame(stream_id + 2, false, 0,
                                   MakeIOVector("\2\0\0\0\0\0\0\0HT")));
  visitor_->OnStreamFrames(frames);
  EXPECT_EQ(2u, session_->GetNumOpenStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst(stream_id, QUIC_STREAM_NO_ERROR, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(stream_id, QUIC_RST_FLOW_CONTROL_ACCOUNTING, 0));
  visitor_->OnRstStream(rst);

  // If we were tracking, we'd probably want to reject this because it's data
  // past the reset point of stream 3.  As it's a closed stream we just drop the
  // data on the floor, but accept the packet because it has data for stream 5.
  frames.clear();
  frames.push_back(QuicStreamFrame(stream_id, false, 2, MakeIOVector("TP")));
  frames.push_back(QuicStreamFrame(stream_id + 2, false, 2,
                                   MakeIOVector("TP")));
  visitor_->OnStreamFrames(frames);
  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(1u, session_->GetNumOpenStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionTest, MaxNumConnections) {
  QuicStreamId stream_id = 5;
  EXPECT_EQ(0u, session_->GetNumOpenStreams());
  EXPECT_TRUE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                           stream_id));
  EXPECT_TRUE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                           stream_id + 2));
  EXPECT_TRUE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                           stream_id + 4));
  EXPECT_CALL(*connection_, SendConnectionClose(QUIC_TOO_MANY_OPEN_STREAMS));
  EXPECT_FALSE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                            stream_id + 6));
}

TEST_P(QuicServerSessionTest, MaxNumConnectionsImplicit) {
  QuicStreamId stream_id = 5;
  EXPECT_EQ(0u, session_->GetNumOpenStreams());
  EXPECT_TRUE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                           stream_id));
  // Implicitly opens two more streams.
  EXPECT_CALL(*connection_, SendConnectionClose(QUIC_TOO_MANY_OPEN_STREAMS));
  EXPECT_FALSE(QuicServerSessionPeer::GetIncomingDataStream(session_.get(),
                                                            stream_id + 6));
}

TEST_P(QuicServerSessionTest, GetEvenIncomingError) {
  // Incoming streams on the server session must be odd.
  EXPECT_CALL(*connection_, SendConnectionClose(QUIC_INVALID_STREAM_ID));
  EXPECT_EQ(NULL,
            QuicServerSessionPeer::GetIncomingDataStream(session_.get(), 4));
}

}  // namespace
}  // namespace test
}  // namespace tools
}  // namespace net
