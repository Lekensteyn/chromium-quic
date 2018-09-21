// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A client specific QuicSession subclass.

#ifndef NET_QUIC_QUIC_CLIENT_SESSION_H_
#define NET_QUIC_QUIC_CLIENT_SESSION_H_

#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_reliable_client_stream.h"
#include "net/quic/quic_session.h"

namespace net {

class NET_EXPORT_PRIVATE QuicClientSession : public QuicSession {
 public:
  explicit QuicClientSession(QuicConnection* connection);

  virtual ~QuicClientSession();

  // QuicSession methods:
  virtual QuicReliableClientStream* CreateOutgoingReliableStream() OVERRIDE;
  virtual QuicCryptoClientStream* GetCryptoStream() OVERRIDE;

  // Perform a crypto handshake with the server.
  void CryptoConnect();

 protected:
  // QuicSession methods:
  virtual ReliableQuicStream* CreateIncomingReliableStream(
      QuicStreamId id) OVERRIDE;

 private:
  QuicCryptoClientStream crypto_stream_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientSession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_SESSION_H_
