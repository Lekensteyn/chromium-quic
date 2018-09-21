// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_handshake.h"

#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_time.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {

class QuicCryptoServerConfigPeer {
 public:
  explicit QuicCryptoServerConfigPeer(QuicCryptoServerConfig* server_config)
      : server_config_(server_config) {}

  string NewSourceAddressToken(IPEndPoint ip,
                               QuicRandom* rand,
                               QuicWallTime now) {
    return server_config_->NewSourceAddressToken(ip, rand, now);
  }

  bool ValidateSourceAddressToken(StringPiece srct,
                                  IPEndPoint ip,
                                  QuicWallTime now) {
    return server_config_->ValidateSourceAddressToken(srct, ip, now);
  }

 private:
  QuicCryptoServerConfig* const server_config_;
};

TEST(QuicCryptoServerConfigTest, ServerConfig) {
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand);
  MockClock clock;

  scoped_ptr<CryptoHandshakeMessage>(
      server.AddDefaultConfig(rand, &clock,
                              QuicCryptoServerConfig::ConfigOptions()));
}

TEST(QuicCryptoServerConfigTest, SourceAddressTokens) {
  if (!Aes128Gcm12Encrypter::IsSupported()) {
    LOG(INFO) << "AES GCM not supported. Test skipped.";
    return;
  }

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand);
  IPAddressNumber ip;
  CHECK(ParseIPLiteralToNumber("192.0.2.33", &ip));
  IPEndPoint ip4 = IPEndPoint(ip, 1);
  CHECK(ParseIPLiteralToNumber("2001:db8:0::42", &ip));
  IPEndPoint ip6 = IPEndPoint(ip, 2);
  MockClock clock;
  clock.AdvanceTime(QuicTime::Delta::FromSeconds(1000000));
  QuicCryptoServerConfigPeer peer(&server);

  QuicWallTime now = clock.WallNow();
  const QuicWallTime original_time = now;

  const string token4 = peer.NewSourceAddressToken(ip4, rand, now);
  const string token6 = peer.NewSourceAddressToken(ip6, rand, now);
  EXPECT_TRUE(peer.ValidateSourceAddressToken(token4, ip4, now));
  EXPECT_FALSE(peer.ValidateSourceAddressToken(token4, ip6, now));
  EXPECT_TRUE(peer.ValidateSourceAddressToken(token6, ip6, now));

  now = original_time.Add(QuicTime::Delta::FromSeconds(86400 * 7));
  EXPECT_FALSE(peer.ValidateSourceAddressToken(token4, ip4, now));

  now = original_time.Subtract(QuicTime::Delta::FromSeconds(3600 * 2));
  EXPECT_FALSE(peer.ValidateSourceAddressToken(token4, ip4, now));
}

}  // namespace test
}  // namespace net
