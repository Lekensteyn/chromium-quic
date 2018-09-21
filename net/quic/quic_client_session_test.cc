// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_client_session.h"

#include <vector>

#include "net/base/capturing_net_log.h"
#include "net/base/test_completion_callback.h"
#include "net/quic/crypto/aes_128_gcm_encrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"

using testing::_;

namespace net {
namespace test {
namespace {

const char kServerHostname[] = "www.example.com";

class QuicClientSessionTest : public ::testing::Test {
 protected:
  QuicClientSessionTest()
      : guid_(1),
        connection_(new PacketSavingConnection(guid_, IPEndPoint(), false)),
        session_(connection_, NULL, NULL, NULL, kServerHostname,
                 &crypto_config_, &net_log_) {
    crypto_config_.SetDefaults();
  }

  void CompleteCryptoHandshake() {
    ASSERT_EQ(ERR_IO_PENDING,
              session_.CryptoConnect(callback_.callback()));
    CryptoTestUtils::HandshakeWithFakeServer(
        connection_, session_.GetCryptoStream());
    ASSERT_EQ(OK, callback_.WaitForResult());
  }

  QuicGuid guid_;
  PacketSavingConnection* connection_;
  CapturingNetLog net_log_;
  QuicClientSession session_;
  MockClock clock_;
  MockRandom random_;
  QuicConnectionVisitorInterface* visitor_;
  TestCompletionCallback callback_;
  QuicConfig* config_;
  QuicCryptoClientConfig crypto_config_;
};

TEST_F(QuicClientSessionTest, CryptoConnect) {
  if (!Aes128GcmEncrypter::IsSupported()) {
    LOG(INFO) << "AES GCM not supported. Test skipped.";
    return;
  }

  CompleteCryptoHandshake();
}

TEST_F(QuicClientSessionTest, MaxNumConnections) {
  if (!Aes128GcmEncrypter::IsSupported()) {
    LOG(INFO) << "AES GCM not supported. Test skipped.";
    return;
  }

  CompleteCryptoHandshake();

  std::vector<QuicReliableClientStream*> streams;
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection; i++) {
    QuicReliableClientStream* stream = session_.CreateOutgoingReliableStream();
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }
  EXPECT_FALSE(session_.CreateOutgoingReliableStream());

  // Close a stream and ensure I can now open a new one.
  session_.CloseStream(streams[0]->id());
  EXPECT_TRUE(session_.CreateOutgoingReliableStream());
}

TEST_F(QuicClientSessionTest, GoAwayReceived) {
  if (!Aes128GcmEncrypter::IsSupported()) {
    LOG(INFO) << "AES GCM not supported. Test skipped.";
    return;
  }

  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_.OnGoAway(QuicGoAwayFrame(QUIC_PEER_GOING_AWAY, 1u, "Going away."));
  EXPECT_EQ(NULL, session_.CreateOutgoingReliableStream());
}

}  // namespace
}  // namespace test
}  // namespace net
