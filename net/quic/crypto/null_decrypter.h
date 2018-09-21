// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_NULL_DECRYPTER_H_
#define NET_QUIC_CRYPTO_NULL_DECRYPTER_H_

#include "base/compiler_specific.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/quic_decrypter.h"

namespace net {

// A NullDecrypter is a QuicDecrypter used before a crypto negotiation
// has occurred.  It does not actually decrypt the payload, but does
// verify a hash (fnv128) over both the payload and associated data.
class NET_EXPORT_PRIVATE NullDecrypter : public QuicDecrypter {
 public:
  virtual ~NullDecrypter() {}

  // QuicDecrypter implementation
  virtual QuicData* Decrypt(base::StringPiece associated_data,
                            base::StringPiece ciphertext) OVERRIDE;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_NULL_DECRYPTER_H_
