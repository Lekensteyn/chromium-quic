// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_stream_factory.h"

#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/thread_task_runner_handle.h"
#include "net/base/test_data_directory.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/crypto/properties_based_quic_server_info.h"
#include "net/quic/crypto/quic_crypto_client_config.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_server_info.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_crypto_client_stream_factory.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_stream_factory_peer.h"
#include "net/quic/test_tools/quic_test_packet_maker.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/test_task_runner.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session_test_util.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/test/cert_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::ostream;
using std::string;
using std::vector;

namespace net {

namespace test {

namespace {
const char kDefaultServerHostName[] = "www.example.org";
const char kServer2HostName[] = "mail.example.org";
const char kServer3HostName[] = "docs.example.org";
const char kServer4HostName[] = "images.example.org";
const int kDefaultServerPort = 443;

// Run all tests with all the combinations of versions and
// enable_connection_racing.
struct TestParams {
  TestParams(const QuicVersion version, bool enable_connection_racing)
      : version(version), enable_connection_racing(enable_connection_racing) {}

  friend ostream& operator<<(ostream& os, const TestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version);
    os << " enable_connection_racing: " << p.enable_connection_racing << " }";
    return os;
  }

  QuicVersion version;
  bool enable_connection_racing;
};

// Constructs various test permutations.
vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  QuicVersionVector all_supported_versions = QuicSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(TestParams(version, false));
    params.push_back(TestParams(version, true));
  }
  return params;
}

}  // namespace anonymous

class MockQuicServerInfo : public QuicServerInfo {
 public:
  MockQuicServerInfo(const QuicServerId& server_id)
      : QuicServerInfo(server_id) {}
  ~MockQuicServerInfo() override {}

  void Start() override {}

  int WaitForDataReady(const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }

  void ResetWaitForDataReadyCallback() override {}

  void CancelWaitForDataReadyCallback() override {}

  bool IsDataReady() override { return false; }

  bool IsReadyToPersist() override { return false; }

  void Persist() override {}

  void OnExternalCacheHit() override {}
};

class MockQuicServerInfoFactory : public QuicServerInfoFactory {
 public:
  MockQuicServerInfoFactory() {}
  ~MockQuicServerInfoFactory() override {}

  QuicServerInfo* GetForServer(const QuicServerId& server_id) override {
    return new MockQuicServerInfo(server_id);
  }
};

class MockNetworkChangeNotifier : public NetworkChangeNotifier {
 public:
  MockNetworkChangeNotifier() : force_network_handles_supported_(false) {}

  ConnectionType GetCurrentConnectionType() const override {
    return CONNECTION_UNKNOWN;
  }

  void ForceNetworkHandlesSupported() {
    force_network_handles_supported_ = true;
  }

  bool AreNetworkHandlesCurrentlySupported() const override {
    return force_network_handles_supported_;
  }

  void SetConnectedNetworksList(const NetworkList& network_list) {
    connected_networks_ = network_list;
  }

  void GetCurrentConnectedNetworks(NetworkList* network_list) const override {
    network_list->clear();
    *network_list = connected_networks_;
  }

  void NotifyNetworkSoonToDisconnect(
      NetworkChangeNotifier::NetworkHandle network) {
    NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
        NetworkChangeNotifier::SOON_TO_DISCONNECT, network);
    // Spin the message loop so the notification is delivered.
    base::MessageLoop::current()->RunUntilIdle();
  }

  void NotifyNetworkDisconnected(NetworkChangeNotifier::NetworkHandle network) {
    NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
        NetworkChangeNotifier::DISCONNECTED, network);
    // Spin the message loop so the notification is delivered.
    base::MessageLoop::current()->RunUntilIdle();
  }

 private:
  bool force_network_handles_supported_;
  NetworkChangeNotifier::NetworkList connected_networks_;
};

// Class to replace existing NetworkChangeNotifier singleton with a
// MockNetworkChangeNotifier for a test. To use, simply create a
// ScopedMockNetworkChangeNotifier object in the test.
class ScopedMockNetworkChangeNotifier {
 public:
  ScopedMockNetworkChangeNotifier()
      : disable_network_change_notifier_for_tests_(
            new NetworkChangeNotifier::DisableForTest()),
        mock_network_change_notifier_(new MockNetworkChangeNotifier()) {}

  MockNetworkChangeNotifier* mock_network_change_notifier() {
    return mock_network_change_notifier_.get();
  }

 private:
  scoped_ptr<NetworkChangeNotifier::DisableForTest>
      disable_network_change_notifier_for_tests_;
  scoped_ptr<MockNetworkChangeNotifier> mock_network_change_notifier_;
};

class QuicStreamFactoryTest : public ::testing::TestWithParam<TestParams> {
 protected:
  QuicStreamFactoryTest()
      : random_generator_(0),
        clock_(new MockClock()),
        runner_(new TestTaskRunner(clock_)),
        maker_(GetParam().version, 0, clock_, kDefaultServerHostName),
        cert_verifier_(CertVerifier::CreateDefault()),
        channel_id_service_(
            new ChannelIDService(new DefaultChannelIDStore(nullptr),
                                 base::ThreadTaskRunnerHandle::Get())),
        cert_transparency_verifier_(new MultiLogCTVerifier()),
        scoped_mock_network_change_notifier_(nullptr),
        factory_(nullptr),
        host_port_pair_(kDefaultServerHostName, kDefaultServerPort),
        privacy_mode_(PRIVACY_MODE_DISABLED),
        enable_port_selection_(true),
        always_require_handshake_confirmation_(false),
        disable_connection_pooling_(false),
        load_server_info_timeout_srtt_multiplier_(0.0f),
        enable_connection_racing_(true),
        enable_non_blocking_io_(true),
        disable_disk_cache_(false),
        prefer_aes_(false),
        max_number_of_lossy_connections_(0),
        packet_loss_threshold_(1.0f),
        max_disabled_reasons_(3),
        threshold_timeouts_with_open_streams_(2),
        threshold_public_resets_post_handshake_(2),
        receive_buffer_size_(0),
        delay_tcp_race_(false),
        close_sessions_on_ip_change_(false),
        idle_connection_timeout_seconds_(kIdleConnectionTimeoutSeconds),
        migrate_sessions_on_network_change_(false) {
    clock_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  void Initialize() {
    factory_.reset(new QuicStreamFactory(
        &host_resolver_, &socket_factory_, http_server_properties_.GetWeakPtr(),
        cert_verifier_.get(), nullptr, channel_id_service_.get(),
        &transport_security_state_, cert_transparency_verifier_.get(),
        /*SocketPerformanceWatcherFactory*/ nullptr,
        &crypto_client_stream_factory_, &random_generator_, clock_,
        kDefaultMaxPacketSize, std::string(),
        SupportedVersions(GetParam().version), enable_port_selection_,
        always_require_handshake_confirmation_, disable_connection_pooling_,
        load_server_info_timeout_srtt_multiplier_, enable_connection_racing_,
        enable_non_blocking_io_, disable_disk_cache_, prefer_aes_,
        max_number_of_lossy_connections_, packet_loss_threshold_,
        max_disabled_reasons_, threshold_timeouts_with_open_streams_,
        threshold_public_resets_post_handshake_, receive_buffer_size_,
        delay_tcp_race_, /*max_server_configs_stored_in_properties*/ 0,
        close_sessions_on_ip_change_, idle_connection_timeout_seconds_,
        migrate_sessions_on_network_change_, QuicTagVector()));
    factory_->set_require_confirmation(false);
    EXPECT_FALSE(factory_->has_quic_server_info_factory());
    factory_->set_quic_server_info_factory(new MockQuicServerInfoFactory());
    EXPECT_TRUE(factory_->has_quic_server_info_factory());
  }

  void InitializeConnectionMigrationTest(
      NetworkChangeNotifier::NetworkList connected_networks) {
    scoped_mock_network_change_notifier_.reset(
        new ScopedMockNetworkChangeNotifier());
    MockNetworkChangeNotifier* mock_ncn =
        scoped_mock_network_change_notifier_->mock_network_change_notifier();
    mock_ncn->ForceNetworkHandlesSupported();
    mock_ncn->SetConnectedNetworksList(connected_networks);
    migrate_sessions_on_network_change_ = true;
    Initialize();
  }

  bool HasActiveSession(const HostPortPair& host_port_pair) {
    return QuicStreamFactoryPeer::HasActiveSession(factory_.get(),
                                                   host_port_pair);
  }

  scoped_ptr<QuicHttpStream> CreateFromSession(
      const HostPortPair& host_port_pair) {
    QuicChromiumClientSession* session =
        QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair);
    return QuicStreamFactoryPeer::CreateFromSession(factory_.get(), session);
  }

  int GetSourcePortForNewSession(const HostPortPair& destination) {
    return GetSourcePortForNewSessionInner(destination, false);
  }

  int GetSourcePortForNewSessionAndGoAway(const HostPortPair& destination) {
    return GetSourcePortForNewSessionInner(destination, true);
  }

  int GetSourcePortForNewSessionInner(const HostPortPair& destination,
                                      bool goaway_received) {
    // Should only be called if there is no active session for this destination.
    EXPECT_FALSE(HasActiveSession(destination));
    size_t socket_count = socket_factory_.udp_client_socket_ports().size();

    MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
    SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
    socket_factory_.AddSocketDataProvider(&socket_data);

    QuicStreamRequest request(factory_.get());
    EXPECT_EQ(ERR_IO_PENDING,
              request.Request(destination, privacy_mode_,
                              /*cert_verify_flags=*/0, destination.host(),
                              "GET", net_log_, callback_.callback()));

    EXPECT_EQ(OK, callback_.WaitForResult());
    scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
    EXPECT_TRUE(stream.get());
    stream.reset();

    QuicChromiumClientSession* session =
        QuicStreamFactoryPeer::GetActiveSession(factory_.get(), destination);

    if (socket_count + 1 != socket_factory_.udp_client_socket_ports().size()) {
      ADD_FAILURE();
      return 0;
    }

    if (goaway_received) {
      QuicGoAwayFrame goaway(QUIC_NO_ERROR, 1, "");
      session->connection()->OnGoAwayFrame(goaway);
    }

    factory_->OnSessionClosed(session);
    EXPECT_FALSE(HasActiveSession(destination));
    EXPECT_TRUE(socket_data.AllReadDataConsumed());
    EXPECT_TRUE(socket_data.AllWriteDataConsumed());
    return socket_factory_.udp_client_socket_ports()[socket_count];
  }

  scoped_ptr<QuicEncryptedPacket> ConstructConnectionClosePacket(
      QuicPacketNumber num) {
    return maker_.MakeConnectionClosePacket(num);
  }

  scoped_ptr<QuicEncryptedPacket> ConstructRstPacket() {
    QuicStreamId stream_id = kClientDataStreamId1;
    return maker_.MakeRstPacket(
        1, true, stream_id,
        AdjustErrorForVersion(QUIC_RST_ACKNOWLEDGEMENT, GetParam().version));
  }

  static ProofVerifyDetailsChromium DefaultProofVerifyDetails() {
    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    ProofVerifyDetailsChromium verify_details;
    verify_details.cert_verify_result.verified_cert = test_cert;
    verify_details.cert_verify_result.is_issued_by_known_root = true;
    return verify_details;
  }

  void NotifyIPAddressChanged() {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Spin the message loop so the notification is delivered.
    base::MessageLoop::current()->RunUntilIdle();
  }

  scoped_ptr<QuicEncryptedPacket> ConstructGetRequestPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin) {
    SpdyHeaderBlock headers = maker_.GetRequestHeaders("GET", "https", "/");
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    size_t spdy_headers_frame_len;
    return maker_.MakeRequestHeadersPacket(
        packet_number, stream_id, should_include_version, fin, priority,
        headers, &spdy_headers_frame_len);
  }

  scoped_ptr<QuicEncryptedPacket> ConstructOkResponsePacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin) {
    SpdyHeaderBlock headers = maker_.GetResponseHeaders("200 OK");
    size_t spdy_headers_frame_len;
    return maker_.MakeResponseHeadersPacket(packet_number, stream_id,
                                            should_include_version, fin,
                                            headers, &spdy_headers_frame_len);
  }

  MockHostResolver host_resolver_;
  MockClientSocketFactory socket_factory_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  ProofVerifyDetailsChromium verify_details_;
  MockRandom random_generator_;
  MockClock* clock_;  // Owned by factory_.
  scoped_refptr<TestTaskRunner> runner_;
  QuicTestPacketMaker maker_;
  HttpServerPropertiesImpl http_server_properties_;
  scoped_ptr<CertVerifier> cert_verifier_;
  scoped_ptr<ChannelIDService> channel_id_service_;
  TransportSecurityState transport_security_state_;
  scoped_ptr<CTVerifier> cert_transparency_verifier_;
  scoped_ptr<ScopedMockNetworkChangeNotifier>
      scoped_mock_network_change_notifier_;
  scoped_ptr<QuicStreamFactory> factory_;
  HostPortPair host_port_pair_;
  PrivacyMode privacy_mode_;
  BoundNetLog net_log_;
  TestCompletionCallback callback_;

  // Variables to configure QuicStreamFactory.
  bool enable_port_selection_;
  bool always_require_handshake_confirmation_;
  bool disable_connection_pooling_;
  double load_server_info_timeout_srtt_multiplier_;
  bool enable_connection_racing_;
  bool enable_non_blocking_io_;
  bool disable_disk_cache_;
  bool prefer_aes_;
  int max_number_of_lossy_connections_;
  double packet_loss_threshold_;
  int max_disabled_reasons_;
  int threshold_timeouts_with_open_streams_;
  int threshold_public_resets_post_handshake_;
  int receive_buffer_size_;
  bool delay_tcp_race_;
  bool close_sessions_on_ip_change_;
  int idle_connection_timeout_seconds_;
  bool migrate_sessions_on_network_change_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicStreamFactoryTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicStreamFactoryTest, Create) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Will reset stream 3.
  stream = CreateFromSession(host_port_pair_);
  EXPECT_TRUE(stream.get());

  // TODO(rtenneti): We should probably have a tests that HTTP and HTTPS result
  // in streams on different sessions.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));
  stream = request2.ReleaseStream();  // Will reset stream 5.
  stream.reset();                     // Will reset stream 7.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateZeroRtt) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateZeroRttPost) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  // Posts require handshake confirmation, so this will return asynchronously.
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "POST", net_log_, callback_.callback()));

  // Confirm the handshake and verify that the stream is created.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoZeroRttForDifferentHost) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  int rv =
      request.Request(host_port_pair_, privacy_mode_, /*cert_verify_flags=*/0,
                      kServer2HostName, "GET", net_log_, callback_.callback());
  // If server and origin have different hostnames, then handshake confirmation
  // should be required, so Request will return asynchronously.
  EXPECT_EQ(ERR_IO_PENDING, rv);
  // Confirm handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  EXPECT_EQ(OK, callback_.WaitForResult());

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, GoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  session->OnGoAway(QuicGoAwayFrame());

  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, Pooling) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_),
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoPoolingIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_),
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoPoolingAfterGoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  factory_->OnSessionGoingAway(
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server2));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback3.callback()));
  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());

  EXPECT_TRUE(QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, HttpsPooling) {
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, server1.host(), "GET",
                                net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server1),
            QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, server1.host(), "GET",
                                net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server1),
            QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

class QuicAlternativeServiceCertificateValidationPooling
    : public QuicStreamFactoryTest {
 public:
  void Run(bool valid) {
    MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
    SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
    socket_factory_.AddSocketDataProvider(&socket_data1);

    HostPortPair server1(kDefaultServerHostName, 443);
    HostPortPair server2(kServer2HostName, 443);

    std::string origin_host(valid ? kServer2HostName : "invalid.example.com");
    HostPortPair alternative(kDefaultServerHostName, 443);

    ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
    bool common_name_fallback_used;
    EXPECT_EQ(valid,
              verify_details.cert_verify_result.verified_cert->VerifyNameMatch(
                  origin_host, &common_name_fallback_used));
    EXPECT_TRUE(
        verify_details.cert_verify_result.verified_cert->VerifyNameMatch(
            alternative.host(), &common_name_fallback_used));
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

    host_resolver_.set_synchronous_mode(true);
    host_resolver_.rules()->AddIPLiteralRule(alternative.host(), "192.168.0.1",
                                             "");

    // Open first stream to alternative.
    QuicStreamRequest request1(factory_.get());
    EXPECT_EQ(OK, request1.Request(alternative, privacy_mode_,
                                   /*cert_verify_flags=*/0, alternative.host(),
                                   "GET", net_log_, callback_.callback()));
    scoped_ptr<QuicHttpStream> stream1 = request1.ReleaseStream();
    EXPECT_TRUE(stream1.get());

    QuicStreamRequest request2(factory_.get());
    int rv = request2.Request(alternative, privacy_mode_,
                              /*cert_verify_flags=*/0, origin_host, "GET",
                              net_log_, callback_.callback());
    if (valid) {
      // Alternative service of origin to |alternative| should pool to session
      // of |stream1| even if origin is different.  Since only one
      // SocketDataProvider is set up, the second request succeeding means that
      // it pooled to the session opened by the first one.
      EXPECT_EQ(OK, rv);
      scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
      EXPECT_TRUE(stream2.get());
    } else {
      EXPECT_EQ(ERR_ALTERNATIVE_CERT_NOT_VALID_FOR_ORIGIN, rv);
    }

    EXPECT_TRUE(socket_data1.AllReadDataConsumed());
    EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  }
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicAlternativeServiceCertificateValidationPooling,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicAlternativeServiceCertificateValidationPooling, Valid) {
  Initialize();
  Run(true);
}

TEST_P(QuicAlternativeServiceCertificateValidationPooling, Invalid) {
  Initialize();
  Run(false);
}

TEST_P(QuicStreamFactoryTest, HttpsPoolingWithMatchingPins) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  verify_details.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, server1.host(), "GET",
                                net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server1),
            QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingWithMatchingPinsIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  verify_details.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, server1.host(), "GET",
                                net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server1),
            QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingWithDifferentPins) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  uint8_t bad_pin = 3;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details1 = DefaultProofVerifyDetails();
  verify_details1.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(bad_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2 = DefaultProofVerifyDetails();
  verify_details2.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, server1.host(), "GET",
                                net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback_.callback()));
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server1),
            QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, Goaway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Mark the session as going away.  Ensure that while it is still alive
  // that it is no longer active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  factory_->OnSessionGoingAway(session);
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  // Create a new request for the same destination and verify that a
  // new session is created.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_NE(session, QuicStreamFactoryPeer::GetActiveSession(factory_.get(),
                                                             host_port_pair_));
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));

  stream2.reset();
  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MaxOpenStream) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamId stream_id = kClientDataStreamId1;
  scoped_ptr<QuicEncryptedPacket> client_rst(
      maker_.MakeRstPacket(1, true, stream_id, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 0),
  };
  scoped_ptr<QuicEncryptedPacket> server_rst(
      maker_.MakeRstPacket(1, false, stream_id, QUIC_STREAM_CANCELLED));
  MockRead reads[] = {
      MockRead(ASYNC, server_rst->data(), server_rst->length(), 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  HttpRequestInfo request_info;
  std::vector<QuicHttpStream*> streams;
  // The MockCryptoClientStream sets max_open_streams to be
  // kDefaultMaxStreamsPerConnection / 2.
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection / 2; i++) {
    QuicStreamRequest request(factory_.get());
    int rv = request.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback());
    if (i == 0) {
      EXPECT_EQ(ERR_IO_PENDING, rv);
      EXPECT_EQ(OK, callback_.WaitForResult());
    } else {
      EXPECT_EQ(OK, rv);
    }
    scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
    EXPECT_TRUE(stream);
    EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                           net_log_, CompletionCallback()));
    streams.push_back(stream.release());
  }

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, CompletionCallback()));
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->InitializeStream(&request_info, DEFAULT_PRIORITY, net_log_,
                                     callback_.callback()));

  // Close the first stream.
  streams.front()->Close(false);
  // Trigger exchange of RSTs that in turn allow progress for the last
  // stream.
  EXPECT_EQ(OK, callback_.WaitForResult());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());

  // Force close of the connection to suppress the generation of RST
  // packets when streams are torn down, which wouldn't be relevant to
  // this test anyway.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);

  STLDeleteElements(&streams);
}

TEST_P(QuicStreamFactoryTest, ResolutionErrorInCreate) {
  Initialize();
  SequencedSocketData socket_data(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  host_resolver_.rules()->AddSimulatedFailure(kDefaultServerHostName);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, callback_.WaitForResult());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, ConnectErrorInCreate) {
  Initialize();
  MockConnect connect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  SequencedSocketData socket_data(nullptr, 0, nullptr, 0);
  socket_data.set_connect_data(connect);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(ERR_ADDRESS_IN_USE, callback_.WaitForResult());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CancelCreate) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);
  {
    QuicStreamRequest request(factory_.get());
    EXPECT_EQ(ERR_IO_PENDING,
              request.Request(host_port_pair_, privacy_mode_,
                              /*cert_verify_flags=*/0, host_port_pair_.host(),
                              "GET", net_log_, callback_.callback()));
  }

  base::RunLoop().RunUntilIdle();

  scoped_ptr<QuicHttpStream> stream(CreateFromSession(host_port_pair_));
  EXPECT_TRUE(stream.get());
  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateConsistentEphemeralPort) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Sequentially connect to the default host, then another host, and then the
  // default host.  Verify that the default host gets a consistent ephemeral
  // port, that is different from the other host's connection.

  std::string other_server_name = kServer2HostName;
  EXPECT_NE(kDefaultServerHostName, other_server_name);
  HostPortPair host_port_pair2(other_server_name, kDefaultServerPort);

  int original_port = GetSourcePortForNewSession(host_port_pair_);
  EXPECT_NE(original_port, GetSourcePortForNewSession(host_port_pair2));
  EXPECT_EQ(original_port, GetSourcePortForNewSession(host_port_pair_));
}

TEST_P(QuicStreamFactoryTest, GoAwayDisablesConsistentEphemeralPort) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Get a session to the host using the port suggester.
  int original_port = GetSourcePortForNewSessionAndGoAway(host_port_pair_);
  // Verify that the port is different after the goaway.
  EXPECT_NE(original_port, GetSourcePortForNewSession(host_port_pair_));
  // Since the previous session did not goaway we should see the original port.
  EXPECT_EQ(original_port, GetSourcePortForNewSession(host_port_pair_));
}

TEST_P(QuicStreamFactoryTest, CloseAllSessions) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> rst(ConstructRstPacket());
  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Close the session and verify that stream saw the error.
  factory_->CloseAllSessions(ERR_INTERNET_DISCONNECTED, QUIC_INTERNAL_ERROR);
  EXPECT_EQ(ERR_INTERNET_DISCONNECTED,
            stream->ReadResponseHeaders(callback_.callback()));

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  stream = request2.ReleaseStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnIPAddressChanged) {
  close_sessions_on_ip_change_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> rst(ConstructRstPacket());
  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Change the IP address and verify that stream saw the error.
  NotifyIPAddressChanged();
  EXPECT_EQ(ERR_NETWORK_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_TRUE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  stream = request2.ReleaseStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnect) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  scoped_ptr<QuicEncryptedPacket> ping(
      maker_.MakePingPacket(2, /*include_version=*/true));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0)};
  scoped_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger connection migration. This should cause a PING frame
  // to be emitted.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_NE(session, QuicStreamFactoryPeer::GetActiveSession(factory_.get(),
                                                             host_port_pair_));

  // On a DISCONNECTED notification, nothing happens to the migrated session.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnected) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response_info;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response_info,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  scoped_ptr<QuicEncryptedPacket> ping(
      maker_.MakePingPacket(2, /*include_version=*/true));
  scoped_ptr<QuicEncryptedPacket> client_rst(maker_.MakeRstPacket(
      3, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0)};
  scoped_ptr<QuicEncryptedPacket> response_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {
      MockRead(ASYNC, response_packet->data(), response_packet->length(), 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger connection migration. This should cause a PING frame
  // to be emitted.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_NE(session, QuicStreamFactoryPeer::GetActiveSession(factory_.get(),
                                                             host_port_pair_));
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoNetworks) {
  NetworkChangeNotifier::NetworkList no_networks(0);
  InitializeConnectionMigrationTest(no_networks);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> client_rst(maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause the session to continue on the same
  // socket, but be marked as going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoNetworks) {
  NetworkChangeNotifier::NetworkList no_networks(0);
  InitializeConnectionMigrationTest(no_networks);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> client_rst(maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause a RST_STREAM frame to be emitted
  // and the session to be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> client_rst(maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause session to be continue but be marked as
  // going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> client_rst(maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause a RST_STREAM frame to be emitted
  // with QUIC_RST_ACKNOWLEDGEMENT error code, and the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0u);
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0u);
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnSSLConfigChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> rst(ConstructRstPacket());
  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  factory_->OnSSLConfigChanged();
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  stream = request2.ReleaseStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnCertAdded) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> rst(ConstructRstPacket());
  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Add a cert and verify that stream saw the event.
  factory_->OnCertAdded(nullptr);
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  stream = request2.ReleaseStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnCACertChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  scoped_ptr<QuicEncryptedPacket> rst(ConstructRstPacket());
  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Change the CA cert and verify that stream saw the event.
  factory_->OnCACertChanged(nullptr);
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, host_port_pair_.host(),
                             "GET", net_log_, callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
  stream = request2.ReleaseStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, SharedCryptoConfig) {
  Initialize();

  vector<string> cannoncial_suffixes;
  cannoncial_suffixes.push_back(string(".c.youtube.com"));
  cannoncial_suffixes.push_back(string(".googlevideo.com"));

  for (unsigned i = 0; i < cannoncial_suffixes.size(); ++i) {
    string r1_host_name("r1");
    string r2_host_name("r2");
    r1_host_name.append(cannoncial_suffixes[i]);
    r2_host_name.append(cannoncial_suffixes[i]);

    HostPortPair host_port_pair1(r1_host_name, 80);
    QuicCryptoClientConfig* crypto_config =
        QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
    QuicServerId server_id1(host_port_pair1, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r1_host_name);
    cached1->SetProofValid();

    HostPortPair host_port_pair2(r2_host_name, 80);
    QuicServerId server_id2(host_port_pair2, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config->LookupOrCreate(server_id2);
    EXPECT_EQ(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->proof_valid());
  }
}

TEST_P(QuicStreamFactoryTest, CryptoConfigWhenProofIsInvalid) {
  Initialize();
  vector<string> cannoncial_suffixes;
  cannoncial_suffixes.push_back(string(".c.youtube.com"));
  cannoncial_suffixes.push_back(string(".googlevideo.com"));

  for (unsigned i = 0; i < cannoncial_suffixes.size(); ++i) {
    string r3_host_name("r3");
    string r4_host_name("r4");
    r3_host_name.append(cannoncial_suffixes[i]);
    r4_host_name.append(cannoncial_suffixes[i]);

    HostPortPair host_port_pair1(r3_host_name, 80);
    QuicCryptoClientConfig* crypto_config =
        QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
    QuicServerId server_id1(host_port_pair1, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r3_host_name);
    cached1->SetProofInvalid();

    HostPortPair host_port_pair2(r4_host_name, 80);
    QuicServerId server_id2(host_port_pair2, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config->LookupOrCreate(server_id2);
    EXPECT_NE(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->source_address_token().empty());
    EXPECT_FALSE(cached2->proof_valid());
  }
}

TEST_P(QuicStreamFactoryTest, RacingConnections) {
  disable_disk_cache_ = false;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  if (!GetParam().enable_connection_racing)
    return;

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  const AlternativeService alternative_service1(QUIC, host_port_pair_.host(),
                                                host_port_pair_.port());
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, 1.0, expiration));

  http_server_properties_.SetAlternativeServices(
      host_port_pair_, alternative_service_info_vector);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  QuicServerId server_id(host_port_pair_, privacy_mode_);
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "GET", net_log_, callback_.callback()));
  EXPECT_EQ(2u, QuicStreamFactoryPeer::GetNumberOfActiveJobs(factory_.get(),
                                                             server_id));

  runner_->RunNextTask();

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_EQ(0u, QuicStreamFactoryPeer::GetNumberOfActiveJobs(factory_.get(),
                                                             server_id));
}

TEST_P(QuicStreamFactoryTest, EnableNotLoadFromDiskCache) {
  disable_disk_cache_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  // If we are waiting for disk cache, we would have posted a task. Verify that
  // the CancelWaitForDataReady task hasn't been posted.
  ASSERT_EQ(0u, runner_->GetPostedTasks().size());

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, BadPacketLoss) {
  disable_disk_cache_ = false;
  max_number_of_lossy_connections_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  DVLOG(1) << "Create 1st session and test packet loss";

  // Set packet_loss_rate to a lower value than packet_loss_threshold.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session, /*packet_loss_rate=*/0.9f));
  EXPECT_TRUE(session->connection()->connected());
  EXPECT_TRUE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  // Set packet_loss_rate to a higher value than packet_loss_threshold only once
  // and that shouldn't close the session and it shouldn't disable QUIC.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));
  EXPECT_TRUE(session->connection()->connected());
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_TRUE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), host_port_pair_));

  // Test N-in-a-row high packet loss connections.

  DVLOG(1) << "Create 2nd session and test packet loss";

  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  // If there is no packet loss during handshake confirmation, number of lossy
  // connections for the port should be 0.
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session2, /*packet_loss_rate=*/0.9f));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server2.port()));

  // Set packet_loss_rate to a higher value than packet_loss_threshold only once
  // and that shouldn't close the session and it shouldn't disable QUIC.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session2, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_TRUE(session2->connection()->connected());
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server2.port()));
  EXPECT_TRUE(QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server2));

  DVLOG(1) << "Create 3rd session which also has packet loss";

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, server3.host(), "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server3);

  DVLOG(1) << "Create 4th session with packet loss and test IsQuicDisabled()";
  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, server4.host(), "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server4);

  // Set packet_loss_rate to higher value than packet_loss_threshold 2nd time in
  // a row and that should close the session and disable QUIC.
  EXPECT_TRUE(
      factory_->OnHandshakeConfirmed(session3, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server3.port()));
  EXPECT_FALSE(session3->connection()->connected());
  EXPECT_TRUE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server3.port()));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server3));
  EXPECT_FALSE(HasActiveSession(server3));

  // Set packet_loss_rate to higher value than packet_loss_threshold 3rd time in
  // a row and IsQuicDisabled() should close the session.
  EXPECT_TRUE(
      factory_->OnHandshakeConfirmed(session4, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(3, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server4.port()));
  EXPECT_FALSE(session4->connection()->connected());
  EXPECT_TRUE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server4.port()));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server4));
  EXPECT_FALSE(HasActiveSession(server4));

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());
  scoped_ptr<QuicHttpStream> stream4 = request4.ReleaseStream();
  EXPECT_TRUE(stream4.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfTwo) {
  disable_disk_cache_ = false;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row public reset post handshakes..
  DVLOG(1) << "Create 2nd session and trigger public reset post handshake";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  session2->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(
      QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE,
      factory_->QuicDisabledReason(host_port_pair_.port()));

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfTwo) {
  disable_disk_cache_ = true;
  threshold_timeouts_with_open_streams_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session and timeout with open stream";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(OK, stream2->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));

  session2->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      2, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS,
            factory_->QuicDisabledReason(host_port_pair_.port()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfThree) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");

  // Test first and third out of three public reset post handshakes.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd session without disable trigger";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  session2->connection()->CloseConnection(QUIC_NO_ERROR, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 3rd session with public reset post handshake,"
           << " will disable QUIC";
  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, server3.host(), "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server3);

  session3->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(
      QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE,
      factory_->QuicDisabledReason(host_port_pair_.port()));

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfThree) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  //  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");

  // Test first and third out of three timeouts with open streams.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session without timeout";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  session2->connection()->CloseConnection(QUIC_NO_ERROR, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 3rd session with timeout with open streams,"
           << " will disable QUIC";

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, server3.host(), "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server3);

  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());
  EXPECT_EQ(OK, stream3->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  session3->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(
      2, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS,
            factory_->QuicDisabledReason(host_port_pair_.port()));

  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfFour) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  // Test first and fourth out of four public reset post handshakes.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd and 3rd sessions without disable trigger";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  session2->connection()->CloseConnection(QUIC_NO_ERROR, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, server3.host(), "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server3);

  session3->connection()->CloseConnection(QUIC_NO_ERROR, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 4rd session with public reset post handshake,"
           << " will not disable QUIC";
  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, server4.host(), "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server4);

  session4->connection()->CloseConnection(QUIC_PUBLIC_RESET, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop4;
  run_loop4.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());
  scoped_ptr<QuicHttpStream> stream4 = request4.ReleaseStream();
  EXPECT_TRUE(stream4.get());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfFour) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  //  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  // Test first and fourth out of three timeouts with open streams.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  QuicChromiumClientSession* session =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), host_port_pair_);

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd and 3rd sessions without timeout";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, server2.host(), "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server2);

  session2->connection()->CloseConnection(QUIC_NO_ERROR, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, server3.host(), "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server3);

  session3->connection()->CloseConnection(QUIC_NO_ERROR, true);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 4th session with timeout with open streams,"
           << " will not disable QUIC";

  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, server4.host(), "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 =
      QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server4);

  scoped_ptr<QuicHttpStream> stream4 = request4.ReleaseStream();
  EXPECT_TRUE(stream4.get());
  EXPECT_EQ(OK, stream4->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  session4->connection()->CloseConnection(QUIC_CONNECTION_TIMED_OUT, false);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop4;
  run_loop4.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  scoped_ptr<QuicHttpStream> stream2 = request2.ReleaseStream();
  EXPECT_TRUE(stream2.get());
  scoped_ptr<QuicHttpStream> stream3 = request3.ReleaseStream();
  EXPECT_TRUE(stream3.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, EnableDelayTcpRace) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  bool delay_tcp_race = QuicStreamFactoryPeer::GetDelayTcpRace(factory_.get());
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), false);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  http_server_properties_.SetServerNetworkStats(host_port_pair_, stats1);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, host_port_pair_.host(),
                            "POST", net_log_, callback_.callback()));

  // If we don't delay TCP connection, then time delay should be 0.
  EXPECT_FALSE(factory_->delay_tcp_race());
  EXPECT_EQ(base::TimeDelta(), request.GetTimeDelayForWaitingJob());

  // Enable |delay_tcp_race_| param and verify delay is one RTT and that
  // server supports QUIC.
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), true);
  EXPECT_TRUE(factory_->delay_tcp_race());
  EXPECT_EQ(base::TimeDelta::FromMicroseconds(15),
            request.GetTimeDelayForWaitingJob());

  // Confirm the handshake and verify that the stream is created.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  EXPECT_EQ(OK, callback_.WaitForResult());

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), delay_tcp_race);
}

TEST_P(QuicStreamFactoryTest, MaybeInitialize) {
  idle_connection_timeout_seconds_ = 500;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  const QuicConfig* config = QuicStreamFactoryPeer::GetConfig(factory_.get());
  EXPECT_EQ(500, config->IdleConnectionStateLifetime().ToSeconds());

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  const AlternativeService alternative_service1(QUIC, host_port_pair_.host(),
                                                host_port_pair_.port());
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, 1.0, expiration));

  http_server_properties_.SetAlternativeServices(
      host_port_pair_, alternative_service_info_vector);
  http_server_properties_.SetMaxServerConfigsStoredInProperties(
      kMaxQuicServersToPersist);

  QuicServerId quic_server_id(kDefaultServerHostName, 80,
                              PRIVACY_MODE_DISABLED);
  QuicServerInfoFactory* quic_server_info_factory =
      new PropertiesBasedQuicServerInfoFactory(
          http_server_properties_.GetWeakPtr());
  factory_->set_quic_server_info_factory(quic_server_info_factory);

  scoped_ptr<QuicServerInfo> quic_server_info(
      quic_server_info_factory->GetForServer(quic_server_id));

  // Update quic_server_info's server_config and persist it.
  QuicServerInfo::State* state = quic_server_info->mutable_state();
  // Minimum SCFG that passes config validation checks.
  const char scfg[] = {// SCFG
                       0x53, 0x43, 0x46, 0x47,
                       // num entries
                       0x01, 0x00,
                       // padding
                       0x00, 0x00,
                       // EXPY
                       0x45, 0x58, 0x50, 0x59,
                       // EXPY end offset
                       0x08, 0x00, 0x00, 0x00,
                       // Value
                       '1', '2', '3', '4', '5', '6', '7', '8'};

  // Create temporary strings becasue Persist() clears string data in |state|.
  string server_config(reinterpret_cast<const char*>(&scfg), sizeof(scfg));
  string source_address_token("test_source_address_token");
  string signature("test_signature");
  string test_cert("test_cert");
  vector<string> certs;
  certs.push_back(test_cert);
  state->server_config = server_config;
  state->source_address_token = source_address_token;
  state->server_config_sig = signature;
  state->certs = certs;

  quic_server_info->Persist();

  QuicStreamFactoryPeer::MaybeInitialize(factory_.get());
  EXPECT_TRUE(QuicStreamFactoryPeer::HasInitializedData(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::SupportsQuicAtStartUp(factory_.get(),
                                                           host_port_pair_));
  EXPECT_FALSE(QuicStreamFactoryPeer::CryptoConfigCacheIsEmpty(factory_.get(),
                                                               quic_server_id));
  QuicCryptoClientConfig* crypto_config =
      QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config->LookupOrCreate(quic_server_id);
  EXPECT_FALSE(cached->server_config().empty());
  EXPECT_TRUE(cached->GetServerConfig());
  EXPECT_EQ(server_config, cached->server_config());
  EXPECT_EQ(source_address_token, cached->source_address_token());
  EXPECT_EQ(signature, cached->signature());
  ASSERT_EQ(1U, cached->certs().size());
  EXPECT_EQ(test_cert, cached->certs()[0]);
}

TEST_P(QuicStreamFactoryTest, QuicDoingZeroRTT) {
  Initialize();

  factory_->set_require_confirmation(true);
  QuicServerId quic_server_id(host_port_pair_, PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(factory_->ZeroRTTEnabledFor(quic_server_id));

  factory_->set_require_confirmation(false);
  EXPECT_FALSE(factory_->ZeroRTTEnabledFor(quic_server_id));

  // Load server config and verify QUIC will do 0RTT.
  QuicStreamFactoryPeer::CacheDummyServerConfig(factory_.get(), quic_server_id);
  EXPECT_TRUE(factory_->ZeroRTTEnabledFor(quic_server_id));
}

TEST_P(QuicStreamFactoryTest, YieldAfterPackets) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetYieldAfterPackets(factory_.get(), 0);

  scoped_ptr<QuicEncryptedPacket> close_packet(
      ConstructConnectionClosePacket(0));
  vector<MockRead> reads;
  reads.push_back(
      MockRead(SYNCHRONOUS, close_packet->data(), close_packet->length(), 0));
  reads.push_back(MockRead(ASYNC, OK, 1));
  SequencedSocketData socket_data(&reads[0], reads.size(), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicPacketReader::StartReading posts a
  // task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_packet_reader.cc", "StartReading");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  // Call run_loop so that QuicPacketReader::OnReadComplete() gets called.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicPacketReader::StartReading() has posted only one task and yielded the
  // read.
  EXPECT_EQ(1u, observer.executed_count());

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, YieldAfterDuration) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetYieldAfterDuration(
      factory_.get(), QuicTime::Delta::FromMilliseconds(-1));

  scoped_ptr<QuicEncryptedPacket> close_packet(
      ConstructConnectionClosePacket(0));
  vector<MockRead> reads;
  reads.push_back(
      MockRead(SYNCHRONOUS, close_packet->data(), close_packet->length(), 0));
  reads.push_back(MockRead(ASYNC, OK, 1));
  SequencedSocketData socket_data(&reads[0], reads.size(), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicPacketReader::StartReading posts a
  // task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_packet_reader.cc", "StartReading");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, host_port_pair_.host(),
                                "GET", net_log_, callback_.callback()));

  // Call run_loop so that QuicPacketReader::OnReadComplete() gets called.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicPacketReader::StartReading() has posted only one task and yielded the
  // read.
  EXPECT_EQ(1u, observer.executed_count());

  scoped_ptr<QuicHttpStream> stream = request.ReleaseStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

}  // namespace test
}  // namespace net
