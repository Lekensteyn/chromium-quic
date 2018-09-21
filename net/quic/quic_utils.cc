// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_utils.h"

#include "base/logging.h"
#include "base/port.h"

namespace net {

// static
size_t QuicUtils::StreamFramePacketOverhead(int num_frames) {
  // TODO(jar): Use sizeof(some name).
  return kPacketHeaderSize +
         (kFrameTypeSize +
          kMinStreamFrameLength) * num_frames;
}

// static
uint128 QuicUtils::FNV1a_128_Hash(const char* data, int len) {
  // The following two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // 309485009821345068724781371
  const uint128 kPrime(16777216, 315);
  // 144066263297769815596495629667062367629
  const uint128 kOffset(GG_UINT64_C(7809847782465536322),
                        GG_UINT64_C(7113472399480571277));

  const uint8* octets = reinterpret_cast<const uint8*>(data);

  uint128 hash = kOffset;

  for (int i = 0; i < len; ++i) {
    hash  = hash ^ uint128(0, octets[i]);
    hash = hash * kPrime;
  }

  return hash;
}

#define RETURN_STRING_LITERAL(x) \
case x: \
return #x;

// static
const char* QuicUtils::ErrorToString(QuicErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_DATA_AFTER_TERMINATION);
    RETURN_STRING_LITERAL(QUIC_SERVER_ERROR_PROCESSING_STREAM);
    RETURN_STRING_LITERAL(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    RETURN_STRING_LITERAL(QUIC_BAD_APPLICATION_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_INVALID_PACKET_HEADER);
    RETURN_STRING_LITERAL(QUIC_INVALID_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_RST_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_CONNECTION_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_GOAWAY_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_ACK_DATA);
    RETURN_STRING_LITERAL(QUIC_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_ENCRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_PACKET_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_PACKET_FOR_NONEXISTENT_STREAM);
    RETURN_STRING_LITERAL(QUIC_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TAGS_OUT_OF_ORDER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_ENTRIES);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INVALID_VALUE_LENGTH)
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_TYPE);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_ID);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OPEN_STREAMS);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESET);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_TIMED_OUT);
    // Intentionally have no default case, so we'll break the build
    // if we add errors and don't put them here.
  }
  return "";
}

}  // namespace net
