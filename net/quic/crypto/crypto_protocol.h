// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CRYPTO_PROTOCOL_H_
#define NET_QUIC_CRYPTO_CRYPTO_PROTOCOL_H_

#include <map>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/logging.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

// CryptoTag is the type of a tag in the wire protocol.
typedef uint32 CryptoTag;
typedef std::string ServerConfigID;
typedef std::map<CryptoTag, std::string> CryptoTagValueMap;
typedef std::vector<CryptoTag> CryptoTagVector;
// An intermediate format of a handshake message that's convenient for a
// CryptoFramer to serialize from or parse into.
struct NET_EXPORT_PRIVATE CryptoHandshakeMessage {
  CryptoHandshakeMessage();
  ~CryptoHandshakeMessage();

  // SetValue sets an element with the given tag to the raw, memory contents of
  // |v|.
  template<class T> void SetValue(CryptoTag tag, const T& v) {
    tag_value_map[tag] = std::string(reinterpret_cast<const char*>(&v),
                                     sizeof(v));
  }

  // SetVector sets an element with the given tag to the raw contents of an
  // array of elements in |v|.
  template<class T> void SetVector(CryptoTag tag, const std::vector<T>& v) {
    if (v.empty()) {
      tag_value_map[tag] = std::string();
    } else {
      tag_value_map[tag] = std::string(reinterpret_cast<const char*>(&v[0]),
                                       v.size() * sizeof(T));
    }
  }

  // SetTaglist sets an element with the given tag to contain a list of tags,
  // passed as varargs. The argument list must be terminated with a 0 element.
  void SetTaglist(CryptoTag tag, ...);

  // GetTaglist finds an element with the given tag containing zero or more
  // tags. If such a tag doesn't exist, it returns false. Otherwise it sets
  // |out_tags| and |out_len| to point to the array of tags and returns true.
  // The array points into the CryptoHandshakeMessage and is valid only for as
  // long as the CryptoHandshakeMessage exists and is not modified.
  QuicErrorCode GetTaglist(CryptoTag tag, const CryptoTag** out_tags,
                           size_t* out_len) const;

  bool GetStringPiece(CryptoTag tag, base::StringPiece* out) const;

  // GetNthValue16 interprets the value with the given tag to be a series of
  // 16-bit length prefixed values and it returns the subvalue with the given
  // index.
  QuicErrorCode GetNthValue16(CryptoTag tag,
                              unsigned index,
                              base::StringPiece* out) const;
  bool GetString(CryptoTag tag, std::string* out) const;
  QuicErrorCode GetUint16(CryptoTag tag, uint16* out) const;
  QuicErrorCode GetUint32(CryptoTag tag, uint32* out) const;

  CryptoTag tag;
  CryptoTagValueMap tag_value_map;

 private:
  // GetPOD is a utility function for extracting a plain-old-data value. If
  // |tag| exists in the message, and has a value of exactly |len| bytes then
  // it copies |len| bytes of data into |out|. Otherwise |len| bytes at |out|
  // are zeroed out.
  //
  // If used to copy integers then this assumes that the machine is
  // little-endian.
  QuicErrorCode GetPOD(CryptoTag tag, void* out, size_t len) const;
};

const CryptoTag kCHLO = MAKE_TAG('C', 'H', 'L', 'O');  // Client hello
const CryptoTag kSHLO = MAKE_TAG('S', 'H', 'L', 'O');  // Server hello
const CryptoTag kSCFG = MAKE_TAG('S', 'H', 'L', 'O');  // Server config
const CryptoTag kREJ  = MAKE_TAG('R', 'E', 'J', '\0');  // Reject

// Key exchange methods
const CryptoTag kP256 = MAKE_TAG('P', '2', '5', '6');  // ECDH, Curve P-256
const CryptoTag kC255 = MAKE_TAG('C', '2', '5', '5');  // ECDH, Curve25519

// AEAD algorithms
const CryptoTag kNULL = MAKE_TAG('N', 'U', 'L', 'L');  // null algorithm
const CryptoTag kAESG = MAKE_TAG('A', 'E', 'S', 'G');  // AES128 + GCM

// Congestion control feedback types
const CryptoTag kQBIC = MAKE_TAG('Q', 'B', 'I', 'C');  // TCP cubic
const CryptoTag kINAR = MAKE_TAG('I', 'N', 'A', 'R');  // Inter arrival

// Client hello tags
const CryptoTag kVERS = MAKE_TAG('V', 'E', 'R', 'S');  // Version
const CryptoTag kNONC = MAKE_TAG('N', 'O', 'N', 'C');  // The connection nonce
const CryptoTag kSSID = MAKE_TAG('S', 'S', 'I', 'D');  // Session ID
const CryptoTag kKEXS = MAKE_TAG('K', 'E', 'X', 'S');  // Key exchange methods
const CryptoTag kAEAD = MAKE_TAG('A', 'E', 'A', 'D');  // Authenticated
                                                       // encryption algorithms
const CryptoTag kCGST = MAKE_TAG('C', 'G', 'S', 'T');  // Congestion control
                                                       // feedback types
const CryptoTag kICSL = MAKE_TAG('I', 'C', 'S', 'L');  // Idle connection state
                                                       // lifetime
const CryptoTag kKATO = MAKE_TAG('K', 'A', 'T', 'O');  // Keepalive timeout
const CryptoTag kSNI = MAKE_TAG('S', 'N', 'I', '\0');  // Server name
                                                       // indication
const CryptoTag kPUBS = MAKE_TAG('P', 'U', 'B', 'S');  // Public key values
const CryptoTag kSCID = MAKE_TAG('S', 'C', 'I', 'D');  // Server config id

const size_t kMaxEntries = 16;  // Max number of entries in a message.

const size_t kNonceSize = 32;  // Size in bytes of the connection nonce.

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CRYPTO_PROTOCOL_H_
