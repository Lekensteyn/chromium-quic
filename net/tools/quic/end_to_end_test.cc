// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <string>

#include "base/memory/scoped_ptr.h"
#include "base/memory/singleton.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/null_encrypter.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_packet_creator.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_test_writer.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_in_memory_cache.h"
#include "net/tools/quic/quic_server.h"
#include "net/tools/quic/quic_socket_utils.h"
#include "net/tools/quic/test_tools/http_message_test_utils.h"
#include "net/tools/quic/test_tools/packet_dropping_test_writer.h"
#include "net/tools/quic/test_tools/quic_client_peer.h"
#include "net/tools/quic/test_tools/quic_dispatcher_peer.h"
#include "net/tools/quic/test_tools/quic_in_memory_cache_peer.h"
#include "net/tools/quic/test_tools/quic_server_peer.h"
#include "net/tools/quic/test_tools/quic_test_client.h"
#include "net/tools/quic/test_tools/server_thread.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using base::WaitableEvent;
using net::test::QuicConnectionPeer;
using net::test::QuicSessionPeer;
using net::test::QuicTestWriter;
using net::test::ReliableQuicStreamPeer;
using net::tools::test::PacketDroppingTestWriter;
using net::tools::test::QuicDispatcherPeer;
using net::tools::test::QuicServerPeer;
using std::string;

namespace net {
namespace tools {
namespace test {
namespace {

const char* kFooResponseBody = "Artichoke hearts make me happy.";
const char* kBarResponseBody = "Palm hearts are pretty delicious, also.";
const size_t kCongestionFeedbackFrameSize = 25;
// If kCongestionFeedbackFrameSize increase we need to expand this string
// accordingly.
const char* kLargeRequest =
    "https://www.google.com/foo/test/a/request/string/longer/than/25/bytes";

void GenerateBody(string* body, int length) {
  body->clear();
  body->reserve(length);
  for (int i = 0; i < length; ++i) {
    body->append(1, static_cast<char>(32 + i % (126 - 32)));
  }
}

class EndToEndTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  EndToEndTest()
      : server_hostname_("example.com"),
        server_started_(false),
        strike_register_no_startup_period_(false) {
    net::IPAddressNumber ip;
    CHECK(net::ParseIPLiteralToNumber("127.0.0.1", &ip));
    server_address_ = IPEndPoint(ip, 0);
    QuicConnection::g_acks_do_not_instigate_acks = true;
    FLAGS_track_retransmission_history = true;
    client_config_.SetDefaults();
    server_config_.SetDefaults();

    QuicInMemoryCachePeer::ResetForTests();
    AddToCache("GET", kLargeRequest, "HTTP/1.1", "200", "OK", kFooResponseBody);
    AddToCache("GET", "https://www.google.com/foo",
               "HTTP/1.1", "200", "OK", kFooResponseBody);
    AddToCache("GET", "https://www.google.com/bar",
               "HTTP/1.1", "200", "OK", kBarResponseBody);
    version_ = GetParam();
  }

  virtual ~EndToEndTest() {
    QuicInMemoryCachePeer::ResetForTests();
  }

  virtual QuicTestClient* CreateQuicClient(QuicTestWriter* writer) {
    QuicTestClient* client = new QuicTestClient(server_address_,
                                                server_hostname_,
                                                false,  // not secure
                                                client_config_,
                                                version_);
    client->UseWriter(writer);
    client->Connect();
    return client;
  }

  virtual bool Initialize() {
    // Start the server first, because CreateQuicClient() attempts
    // to connect to the server.
    StartServer();
    client_.reset(CreateQuicClient(client_writer_));
    QuicEpollConnectionHelper* helper =
        reinterpret_cast<QuicEpollConnectionHelper*>(
            QuicConnectionPeer::GetHelper(
                client_->client()->session()->connection()));
    client_writer_->SetConnectionHelper(helper);
    return client_->client()->connected();
  }

  virtual void SetUp() {
    // The ownership of these gets transferred to the QuicTestWriter and
    // QuicDispatcher when Initialize() is executed.
    client_writer_ = new PacketDroppingTestWriter();
    server_writer_ = new PacketDroppingTestWriter();
  }

  virtual void TearDown() {
    StopServer();
  }

  void StartServer() {
    server_thread_.reset(new ServerThread(server_address_, server_config_,
                                          strike_register_no_startup_period_));
    server_thread_->Start();
    server_thread_->listening()->Wait();
    server_address_ = IPEndPoint(server_address_.address(),
                                 server_thread_->GetPort());
    QuicDispatcher* dispatcher = QuicServerPeer::GetDispatcher(
        server_thread_->server());
    QuicDispatcherPeer::UseWriter(dispatcher, server_writer_);
    server_started_ = true;
  }

  void StopServer() {
    if (!server_started_)
      return;
    if (server_thread_.get()) {
      server_thread_->quit()->Signal();
      server_thread_->Join();
    }
  }

  void AddToCache(StringPiece method,
                  StringPiece path,
                  StringPiece version,
                  StringPiece response_code,
                  StringPiece response_detail,
                  StringPiece body) {
    QuicInMemoryCache::GetInstance()->AddSimpleResponse(
        method, path, version, response_code, response_detail, body);
  }

  void SetPacketLossPercentage(int32 loss) {
    // TODO(rtenneti): enable when we can do random packet loss tests in
    // chrome's tree.
    // client_writer_->set_fake_packet_loss_percentage(loss);
    // server_writer_->set_fake_packet_loss_percentage(loss);
  }

  IPEndPoint server_address_;
  string server_hostname_;
  scoped_ptr<ServerThread> server_thread_;
  scoped_ptr<QuicTestClient> client_;
  PacketDroppingTestWriter* client_writer_;
  PacketDroppingTestWriter* server_writer_;
  bool server_started_;
  QuicConfig client_config_;
  QuicConfig server_config_;
  QuicVersion version_;
  bool strike_register_no_startup_period_;
};

// Run all end to end tests with all supported versions.
INSTANTIATE_TEST_CASE_P(EndToEndTests,
                        EndToEndTest,
                        ::testing::ValuesIn(kSupportedQuicVersions));

TEST_P(EndToEndTest, SimpleRequestResponse) {
  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

// TODO(rch): figure out how to detect missing v6 supprt (like on the linux
// try bots) and selectively disable this test.
TEST_P(EndToEndTest, DISABLED_SimpleRequestResponsev6) {
  IPAddressNumber ip;
  CHECK(net::ParseIPLiteralToNumber("::1", &ip));
  server_address_ = IPEndPoint(ip, server_address_.port());
  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, SeparateFinPacket) {
  ASSERT_TRUE(Initialize());

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.set_has_complete_message(false);

  client_->SendMessage(request);

  client_->SendData(string(), true);

  client_->WaitForResponse();
  EXPECT_EQ(kFooResponseBody, client_->response_body());
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());

  request.AddBody("foo", true);

  client_->SendMessage(request);
  client_->SendData(string(), true);
  client_->WaitForResponse();
  EXPECT_EQ(kFooResponseBody, client_->response_body());
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, MultipleRequestResponse) {
  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, MultipleClients) {
  ASSERT_TRUE(Initialize());
  scoped_ptr<QuicTestClient> client2(CreateQuicClient(NULL));

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddHeader("content-length", "3");
  request.set_has_complete_message(false);

  client_->SendMessage(request);
  client2->SendMessage(request);

  client_->SendData("bar", true);
  client_->WaitForResponse();
  EXPECT_EQ(kFooResponseBody, client_->response_body());
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());

  client2->SendData("eep", true);
  client2->WaitForResponse();
  EXPECT_EQ(kFooResponseBody, client2->response_body());
  EXPECT_EQ(200u, client2->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, RequestOverMultiplePackets) {
  ASSERT_TRUE(Initialize());
  // Set things up so we have a small payload, to guarantee fragmentation.
  // A congestion feedback frame can't be split into multiple packets, make sure
  // that our packet have room for at least this amount after the normal headers
  // are added.

  // TODO(rch) handle this better when we have different encryption options.
  const size_t kStreamDataLength = 3;
  const QuicStreamId kStreamId = 1u;
  const QuicStreamOffset kStreamOffset = 0u;
  size_t stream_payload_size =
      QuicFramer::GetMinStreamFrameSize(
          GetParam(), kStreamId, kStreamOffset, true) + kStreamDataLength;
  size_t min_payload_size =
      std::max(kCongestionFeedbackFrameSize, stream_payload_size);
  size_t ciphertext_size =
      NullEncrypter(GetParam()).GetCiphertextSize(min_payload_size);
  // TODO(satyashekhar): Fix this when versioning is implemented.
  client_->options()->max_packet_length =
      GetPacketHeaderSize(PACKET_8BYTE_GUID, !kIncludeVersion,
                          PACKET_6BYTE_SEQUENCE_NUMBER, NOT_IN_FEC_GROUP) +
      ciphertext_size;

  // Make sure our request is too large to fit in one packet.
  EXPECT_GT(strlen(kLargeRequest), min_payload_size);
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest(kLargeRequest));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, MultipleFramesRandomOrder) {
  ASSERT_TRUE(Initialize());
  // Set things up so we have a small payload, to guarantee fragmentation.
  // A congestion feedback frame can't be split into multiple packets, make sure
  // that our packet have room for at least this amount after the normal headers
  // are added.

  // TODO(rch) handle this better when we have different encryption options.
  const size_t kStreamDataLength = 3;
  const QuicStreamId kStreamId = 1u;
  const QuicStreamOffset kStreamOffset = 0u;
  size_t stream_payload_size =
      QuicFramer::GetMinStreamFrameSize(
          GetParam(), kStreamId, kStreamOffset, true) + kStreamDataLength;
  size_t min_payload_size =
      std::max(kCongestionFeedbackFrameSize, stream_payload_size);
  size_t ciphertext_size =
      NullEncrypter(GetParam()).GetCiphertextSize(min_payload_size);
  // TODO(satyashekhar): Fix this when versioning is implemented.
  client_->options()->max_packet_length =
      GetPacketHeaderSize(PACKET_8BYTE_GUID, !kIncludeVersion,
                          PACKET_6BYTE_SEQUENCE_NUMBER, NOT_IN_FEC_GROUP) +
      ciphertext_size;
  client_->options()->random_reorder = true;

  // Make sure our request is too large to fit in one packet.
  EXPECT_GT(strlen(kLargeRequest), min_payload_size);
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest(kLargeRequest));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, PostMissingBytes) {
  ASSERT_TRUE(Initialize());

  // Add a content length header with no body.
  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddHeader("content-length", "3");
  request.set_skip_message_validation(true);

  // This should be detected as stream fin without complete request,
  // triggering an error response.
  client_->SendCustomSynchronousRequest(request);
  EXPECT_EQ("bad", client_->response_body());
  EXPECT_EQ(500u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, LargePostNoPacketLoss) {
  ASSERT_TRUE(Initialize());

  client_->client()->WaitForCryptoHandshakeConfirmed();

  // 1 Mb body.
  string body;
  GenerateBody(&body, 1024 * 1024);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);

  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
}

TEST_P(EndToEndTest, LargePostWithPacketLoss) {
  // Connect with lower fake packet loss than we'd like to test.  Until
  // b/10126687 is fixed, losing handshake packets is pretty brutal.
  SetPacketLossPercentage(5);
  ASSERT_TRUE(Initialize());

  // Wait for the server SHLO before upping the packet loss.
  client_->client()->WaitForCryptoHandshakeConfirmed();
  SetPacketLossPercentage(30);

  // 10 Kb body.
  string body;
  GenerateBody(&body, 1024 * 10);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);

  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
}

TEST_P(EndToEndTest, LargePostWithPacketLossAndBlocketSocket) {
  // Connect with lower fake packet loss than we'd like to test.  Until
  // b/10126687 is fixed, losing handshake packets is pretty brutal.
  SetPacketLossPercentage(5);
  ASSERT_TRUE(Initialize());

  // Wait for the server SHLO before upping the packet loss.
  client_->client()->WaitForCryptoHandshakeConfirmed();
  SetPacketLossPercentage(30);
  client_writer_->set_fake_blocked_socket_percentage(10);

  // 10 Kb body.
  string body;
  GenerateBody(&body, 1024 * 10);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);

  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
}

// TODO(rtenneti): rch is investigating the root cause. Will enable after we
// find the bug.
TEST_P(EndToEndTest, DISABLED_LargePostZeroRTTFailure) {
  // Have the server accept 0-RTT without waiting a startup period.
  strike_register_no_startup_period_ = true;

  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  ASSERT_TRUE(Initialize());

  string body;
  GenerateBody(&body, 20480);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);

  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
  EXPECT_EQ(2, client_->client()->session()->GetNumSentClientHellos());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
  EXPECT_EQ(1, client_->client()->session()->GetNumSentClientHellos());

  client_->Disconnect();

  // Restart the server so that the 0-RTT handshake will take 1 RTT.
  StopServer();
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  client_->Connect();
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
  EXPECT_EQ(2, client_->client()->session()->GetNumSentClientHellos());
}

// TODO(ianswett): Enable once b/9295090 is fixed.
TEST_P(EndToEndTest, DISABLED_LargePostFEC) {
  SetPacketLossPercentage(30);
  ASSERT_TRUE(Initialize());
  client_->options()->max_packets_per_fec_group = 6;

  string body;
  GenerateBody(&body, 10240);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);

  EXPECT_EQ(kFooResponseBody, client_->SendCustomSynchronousRequest(request));
}

/*TEST_P(EndToEndTest, PacketTooLarge) {
  FLAGS_quic_allow_oversized_packets_for_test = true;
  ASSERT_TRUE(Initialize());

  string body;
  GenerateBody(&body, kMaxPacketSize);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);
  client_->options()->max_packet_length = 20480;

  EXPECT_EQ("", client_->SendCustomSynchronousRequest(request));
  EXPECT_EQ(QUIC_STREAM_CONNECTION_ERROR, client_->stream_error());
  EXPECT_EQ(QUIC_PACKET_TOO_LARGE, client_->connection_error());
}*/

TEST_P(EndToEndTest, InvalidStream) {
  ASSERT_TRUE(Initialize());

  string body;
  GenerateBody(&body, kMaxPacketSize);

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddBody(body, true);
  // Force the client to write with a stream ID belonging to a nonexistent
  // server-side stream.
  QuicSessionPeer::SetNextStreamId(client_->client()->session(), 2);

  client_->SendCustomSynchronousRequest(request);
//  EXPECT_EQ(QUIC_STREAM_CONNECTION_ERROR, client_->stream_error());
  EXPECT_EQ(QUIC_PACKET_FOR_NONEXISTENT_STREAM, client_->connection_error());
}

// TODO(rch): this test seems to cause net_unittests timeouts :|
TEST_P(EndToEndTest, DISABLED_MultipleTermination) {
  ASSERT_TRUE(Initialize());

  HTTPMessage request(HttpConstants::HTTP_1_1,
                      HttpConstants::POST, "/foo");
  request.AddHeader("content-length", "3");
  request.set_has_complete_message(false);

  // Set the offset so we won't frame.  Otherwise when we pick up termination
  // before HTTP framing is complete, we send an error and close the stream,
  // and the second write is picked up as writing on a closed stream.
  QuicReliableClientStream* stream = client_->GetOrCreateStream();
  ASSERT_TRUE(stream != NULL);
  ReliableQuicStreamPeer::SetStreamBytesWritten(3, stream);

  client_->SendData("bar", true);

  // By default the stream protects itself from writes after terminte is set.
  // Override this to test the server handling buggy clients.
  ReliableQuicStreamPeer::SetWriteSideClosed(
      false, client_->GetOrCreateStream());

#if !defined(WIN32) && defined(GTEST_HAS_DEATH_TEST)
#if !defined(DCHECK_ALWAYS_ON)
  EXPECT_DEBUG_DEATH({
      client_->SendData("eep", true);
      client_->WaitForResponse();
      EXPECT_EQ(QUIC_MULTIPLE_TERMINATION_OFFSETS, client_->stream_error());
    },
    "Check failed: !fin_buffered_");
#else
  EXPECT_DEATH({
      client_->SendData("eep", true);
      client_->WaitForResponse();
      EXPECT_EQ(QUIC_MULTIPLE_TERMINATION_OFFSETS, client_->stream_error());
    },
    "Check failed: !fin_buffered_");
#endif
#endif
}

TEST_P(EndToEndTest, Timeout) {
  client_config_.set_idle_connection_state_lifetime(
      QuicTime::Delta::FromMicroseconds(500),
      QuicTime::Delta::FromMicroseconds(500));
  // Note: we do NOT ASSERT_TRUE: we may time out during initial handshake:
  // that's enough to validate timeout in this case.
  Initialize();
  while (client_->client()->connected()) {
    client_->client()->WaitForEvents();
  }
}

TEST_P(EndToEndTest, LimitMaxOpenStreams) {
  // Server limits the number of max streams to 2.
  server_config_.set_max_streams_per_connection(2, 2);
  // Client tries to negotiate for 10.
  client_config_.set_max_streams_per_connection(10, 5);

  ASSERT_TRUE(Initialize());
  client_->client()->WaitForCryptoHandshakeConfirmed();
  QuicConfig* client_negotiated_config = client_->client()->session()->config();
  EXPECT_EQ(2u, client_negotiated_config->max_streams_per_connection());
}

TEST_P(EndToEndTest, ResetConnection) {
  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
  client_->ResetConnection();
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());
}

TEST_P(EndToEndTest, MaxStreamsUberTest) {
  SetPacketLossPercentage(1);
  ASSERT_TRUE(Initialize());
  string large_body;
  GenerateBody(&large_body, 10240);
  int max_streams = 100;

  AddToCache("GET", "/large_response", "HTTP/1.1", "200", "OK", large_body);;

  client_->client()->WaitForCryptoHandshakeConfirmed();
  SetPacketLossPercentage(10);

  for (int i = 0; i < max_streams; ++i) {
    EXPECT_LT(0, client_->SendRequest("/large_response"));
  }

  // WaitForEvents waits 50ms and returns true if there are outstanding
  // requests.
  while (client_->client()->WaitForEvents() == true) {
  }
}

class WrongAddressWriter : public QuicTestWriter {
 public:
  WrongAddressWriter() {
    IPAddressNumber ip;
    CHECK(net::ParseIPLiteralToNumber("127.0.0.2", &ip));
    self_address_ = IPEndPoint(ip, 0);
  }

  virtual WriteResult WritePacket(
      const char* buffer, size_t buf_len,
      const IPAddressNumber& real_self_address,
      const IPEndPoint& peer_address,
      QuicBlockedWriterInterface* blocked_writer) OVERRIDE {
    return writer()->WritePacket(buffer, buf_len, self_address_.address(),
                                 peer_address, blocked_writer);
  }

  virtual bool IsWriteBlockedDataBuffered() const OVERRIDE {
    return false;
  }

  IPEndPoint self_address_;
};

TEST_P(EndToEndTest, ConnectionMigration) {
  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  EXPECT_EQ(200u, client_->response_headers()->parsed_response_code());

  scoped_ptr<WrongAddressWriter> writer(new WrongAddressWriter());

  writer->set_writer(new QuicDefaultPacketWriter(
      QuicClientPeer::GetFd(client_->client())));
  QuicConnectionPeer::SetWriter(
      client_->client()->session()->connection(),
      reinterpret_cast<QuicTestWriter*>(writer.get()));

  client_->SendSynchronousRequest("/bar");

  EXPECT_EQ(QUIC_STREAM_CONNECTION_ERROR, client_->stream_error());
  EXPECT_EQ(QUIC_ERROR_MIGRATING_ADDRESS, client_->connection_error());
}

}  // namespace
}  // namespace test
}  // namespace tools
}  // namespace net
