// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_crypto_client_stream_factory.h"

#include "base/lazy_instance.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_crypto_client_stream.h"

namespace net {

namespace {

class DefaultCryptoStreamFactory : public QuicCryptoClientStreamFactory {
 public:
  QuicCryptoClientStream* CreateQuicCryptoClientStream(
      const QuicServerId& server_id,
      QuicChromiumClientSession* session,
      scoped_ptr<ProofVerifyContext> proof_verify_context,
      QuicCryptoClientConfig* crypto_config) override {
    return new QuicCryptoClientStream(
        server_id, session, proof_verify_context.release(), crypto_config);
  }
};

static base::LazyInstance<DefaultCryptoStreamFactory>::Leaky
    g_default_crypto_stream_factory = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
QuicCryptoClientStreamFactory*
QuicCryptoClientStreamFactory::GetDefaultFactory() {
  return g_default_crypto_stream_factory.Pointer();
}

}  // namespace net
