// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A client specific QuicSession subclass.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_

#include <string>

#include "base/basictypes.h"
#include "net/quic/quic_client_session_base.h"
#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/tools/quic/quic_spdy_client_stream.h"

namespace net {

class QuicConnection;
class QuicServerId;
class ReliableQuicStream;

namespace tools {

class QuicClientSession : public QuicClientSessionBase {
 public:
  QuicClientSession(const QuicConfig& config,
                    QuicConnection* connection,
                    bool is_secure);
  ~QuicClientSession() override;

  void InitializeSession(const QuicServerId& server_id,
                         QuicCryptoClientConfig* config);

  // QuicSession methods:
  QuicSpdyClientStream* CreateOutgoingDataStream() override;
  QuicCryptoClientStream* GetCryptoStream() override;

  // QuicClientSessionBase methods:
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;

  // Performs a crypto handshake with the server. Returns true if the crypto
  // handshake is started successfully.
  bool CryptoConnect();

  // Returns the number of client hello messages that have been sent on the
  // crypto stream. If the handshake has completed then this is one greater
  // than the number of round-trips needed for the handshake.
  int GetNumSentClientHellos() const;

 protected:
  // QuicSession methods:
  QuicDataStream* CreateIncomingDataStream(QuicStreamId id) override;

 private:
  scoped_ptr<QuicCryptoClientStream> crypto_stream_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientSession);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_
