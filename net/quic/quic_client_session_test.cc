// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_client_session.h"

#include <vector>

#include "base/files/file_path.h"
#include "base/rand_util.h"
#include "net/base/capturing_net_log.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_data_directory.h"
#include "net/cert/cert_verify_result.h"
#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_server_info.h"
#include "net/quic/quic_default_packet_writer.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_client_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simple_quic_framer.h"
#include "net/socket/socket_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/udp/datagram_client_socket.h"

using testing::_;

namespace net {
namespace test {
namespace {

const char kServerHostname[] = "www.example.org";
const uint16 kServerPort = 80;

class TestPacketWriter : public QuicDefaultPacketWriter {
 public:
  TestPacketWriter(QuicVersion version) : version_(version) {}

  // QuicPacketWriter
  virtual WriteResult WritePacket(
      const char* buffer, size_t buf_len,
      const IPAddressNumber& self_address,
      const IPEndPoint& peer_address) OVERRIDE {
    SimpleQuicFramer framer(SupportedVersions(version_));
    QuicEncryptedPacket packet(buffer, buf_len);
    EXPECT_TRUE(framer.ProcessPacket(packet));
    header_ = framer.header();
    return WriteResult(WRITE_STATUS_OK, packet.length());
  }

  virtual bool IsWriteBlockedDataBuffered() const OVERRIDE {
    // Chrome sockets' Write() methods buffer the data until the Write is
    // permitted.
    return true;
  }

  // Returns the header from the last packet written.
  const QuicPacketHeader& header() { return header_; }

 private:
  QuicVersion version_;
  QuicPacketHeader header_;
};

class QuicClientSessionTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicClientSessionTest()
      : writer_(new TestPacketWriter(GetParam())),
        connection_(
            new PacketSavingConnection(false, SupportedVersions(GetParam()))),
        session_(connection_, GetSocket().Pass(), writer_.Pass(), NULL, NULL,
                 make_scoped_ptr((QuicServerInfo*)NULL),
                 QuicServerId(kServerHostname, kServerPort, false,
                              PRIVACY_MODE_DISABLED),
                 DefaultQuicConfig(), &crypto_config_,
                 base::MessageLoop::current()->message_loop_proxy().get(),
                 &net_log_) {
    session_.config()->SetDefaults();
    crypto_config_.SetDefaults();
  }

  virtual void TearDown() OVERRIDE {
    session_.CloseSessionOnError(ERR_ABORTED);
  }

  scoped_ptr<DatagramClientSocket> GetSocket() {
    socket_factory_.AddSocketDataProvider(&socket_data_);
    return socket_factory_.CreateDatagramClientSocket(
        DatagramSocket::DEFAULT_BIND, base::Bind(&base::RandInt),
        &net_log_, NetLog::Source());
  }

  void CompleteCryptoHandshake() {
    ASSERT_EQ(ERR_IO_PENDING,
              session_.CryptoConnect(false, callback_.callback()));
    CryptoTestUtils::HandshakeWithFakeServer(
        connection_, session_.GetCryptoStream());
    ASSERT_EQ(OK, callback_.WaitForResult());
  }

  scoped_ptr<QuicDefaultPacketWriter> writer_;
  PacketSavingConnection* connection_;
  CapturingNetLog net_log_;
  MockClientSocketFactory socket_factory_;
  StaticSocketDataProvider socket_data_;
  QuicClientSession session_;
  MockClock clock_;
  MockRandom random_;
  QuicConnectionVisitorInterface* visitor_;
  TestCompletionCallback callback_;
  QuicCryptoClientConfig crypto_config_;
};

INSTANTIATE_TEST_CASE_P(Tests, QuicClientSessionTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicClientSessionTest, CryptoConnect) {
  CompleteCryptoHandshake();
}

TEST_P(QuicClientSessionTest, MaxNumStreams) {
  CompleteCryptoHandshake();

  std::vector<QuicReliableClientStream*> streams;
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection; i++) {
    QuicReliableClientStream* stream = session_.CreateOutgoingDataStream();
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }
  EXPECT_FALSE(session_.CreateOutgoingDataStream());

  // Close a stream and ensure I can now open a new one.
  session_.CloseStream(streams[0]->id());
  EXPECT_TRUE(session_.CreateOutgoingDataStream());
}

TEST_P(QuicClientSessionTest, MaxNumStreamsViaRequest) {
  CompleteCryptoHandshake();

  std::vector<QuicReliableClientStream*> streams;
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection; i++) {
    QuicReliableClientStream* stream = session_.CreateOutgoingDataStream();
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }

  QuicReliableClientStream* stream;
  QuicClientSession::StreamRequest stream_request;
  TestCompletionCallback callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream_request.StartRequest(session_.GetWeakPtr(), &stream,
                                        callback.callback()));

  // Close a stream and ensure I can now open a new one.
  session_.CloseStream(streams[0]->id());
  ASSERT_TRUE(callback.have_result());
  EXPECT_EQ(OK, callback.WaitForResult());
  EXPECT_TRUE(stream != NULL);
}

TEST_P(QuicClientSessionTest, GoAwayReceived) {
  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_.OnGoAway(QuicGoAwayFrame(QUIC_PEER_GOING_AWAY, 1u, "Going away."));
  EXPECT_EQ(NULL, session_.CreateOutgoingDataStream());
}

TEST_P(QuicClientSessionTest, CanPool) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com
  base::FilePath certs_dir = GetTestCertsDirectory();

  CertVerifyResult result;
  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(certs_dir, "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert);

  session_.OnProofVerifyDetailsAvailable(details);
  CompleteCryptoHandshake();


  EXPECT_TRUE(session_.CanPool("www.example.org"));
  EXPECT_TRUE(session_.CanPool("mail.example.org"));
  EXPECT_TRUE(session_.CanPool("mail.example.com"));
  EXPECT_FALSE(session_.CanPool("mail.google.com"));
}

TEST_P(QuicClientSessionTest, ConnectionPooledWithTlsChannelId) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com
  base::FilePath certs_dir = GetTestCertsDirectory();

  CertVerifyResult result;
  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(certs_dir, "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert);

  session_.OnProofVerifyDetailsAvailable(details);
  CompleteCryptoHandshake();
  QuicClientSessionPeer::SetChannelIDSent(&session_, true);

  EXPECT_TRUE(session_.CanPool("www.example.org"));
  EXPECT_TRUE(session_.CanPool("mail.example.org"));
  EXPECT_FALSE(session_.CanPool("mail.example.com"));
  EXPECT_FALSE(session_.CanPool("mail.google.com"));
}

}  // namespace
}  // namespace test
}  // namespace net
