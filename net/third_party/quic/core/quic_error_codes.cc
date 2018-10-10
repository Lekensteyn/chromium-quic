// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quic/core/quic_error_codes.h"

#include "base/metrics/histogram_macros.h"

namespace quic {

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x;

const char* QuicRstStreamErrorCodeToString(QuicRstStreamErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_STREAM_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_CONNECTION_ERROR);
    RETURN_STRING_LITERAL(QUIC_ERROR_PROCESSING_STREAM);
    RETURN_STRING_LITERAL(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    RETURN_STRING_LITERAL(QUIC_BAD_APPLICATION_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_STREAM_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_STREAM_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_RST_ACKNOWLEDGEMENT);
    RETURN_STRING_LITERAL(QUIC_REFUSED_STREAM);
    RETURN_STRING_LITERAL(QUIC_STREAM_LAST_ERROR);
    RETURN_STRING_LITERAL(QUIC_INVALID_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_UNAUTHORIZED_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_DUPLICATE_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_PROMISE_VARY_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_INVALID_PROMISE_METHOD);
    RETURN_STRING_LITERAL(QUIC_PUSH_STREAM_TIMED_OUT);
    RETURN_STRING_LITERAL(QUIC_HEADERS_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_STREAM_TTL_EXPIRED);
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicRstStreamErrorCodes. This can happen when the RstStream
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_RST_STREAM_ERROR_CODE";
}

const char* QuicErrorCodeToString(QuicErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_DATA_AFTER_TERMINATION);
    RETURN_STRING_LITERAL(QUIC_INVALID_PACKET_HEADER);
    RETURN_STRING_LITERAL(QUIC_INVALID_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_MISSING_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_INVALID_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_OVERLAPPING_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_UNENCRYPTED_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_RST_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_CONNECTION_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_GOAWAY_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_WINDOW_UPDATE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STOP_WAITING_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_ACK_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    RETURN_STRING_LITERAL(QUIC_INVALID_PUBLIC_RST_PACKET);
    RETURN_STRING_LITERAL(QUIC_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_ENCRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_PACKET_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TAGS_OUT_OF_ORDER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_ENTRIES);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_REJECTS);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INVALID_VALUE_LENGTH)
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_VERSION_NOT_SUPPORTED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_NO_SUPPORT);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_TYPE);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_UNSUPPORTED_PROOF_DEMAND);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_PRIORITY);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OPEN_STREAMS);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESET);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADER_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEGOTIATED_VALUE);
    RETURN_STRING_LITERAL(QUIC_DECOMPRESSION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_NETWORK_IDLE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_ERROR_MIGRATING_ADDRESS);
    RETURN_STRING_LITERAL(QUIC_ERROR_MIGRATING_PORT);
    RETURN_STRING_LITERAL(QUIC_PACKET_WRITE_ERROR);
    RETURN_STRING_LITERAL(QUIC_PACKET_READ_ERROR);
    RETURN_STRING_LITERAL(QUIC_EMPTY_STREAM_FRAME_NO_FIN);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADERS_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_INVALID_WINDOW);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_IP_POOLED);
    RETURN_STRING_LITERAL(QUIC_PROOF_INVALID);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_DUPLICATE_TAG);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SERVER_CONFIG_EXPIRED);
    RETURN_STRING_LITERAL(QUIC_INVALID_CHANNEL_ID_SIGNATURE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_VERSION_NEGOTIATION_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_BAD_PACKET_LOSS_RATE);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESETS_POST_HANDSHAKE);
    RETURN_STRING_LITERAL(QUIC_FAILED_TO_SERIALIZE_PACKET);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_AVAILABLE_STREAMS);
    RETURN_STRING_LITERAL(QUIC_UNENCRYPTED_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_BAD_MULTIPATH_FLAG);
    RETURN_STRING_LITERAL(QUIC_IP_ADDRESS_CHANGED);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_RTOS);
    RETURN_STRING_LITERAL(QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_MAYBE_CORRUPTED_MEMORY);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_CHLO_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_MULTIPATH_PATH_DOES_NOT_EXIST);
    RETURN_STRING_LITERAL(QUIC_MULTIPATH_PATH_NOT_ACTIVE);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_STREAM_DATA_INTERVALS);
    RETURN_STRING_LITERAL(QUIC_STREAM_SEQUENCER_INVALID_STATE);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_SESSIONS_ON_SERVER);
    RETURN_STRING_LITERAL(QUIC_STREAM_LENGTH_OVERFLOW);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_INVALID_APPLICATION_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_MAX_DATA_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_MAX_STREAM_DATA_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_MAX_STREAM_ID_DATA);
    RETURN_STRING_LITERAL(QUIC_STREAM_ID_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEW_CONNECTION_ID_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STOP_SENDING_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_CHALLENGE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_RESPONSE_DATA);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED);
    RETURN_STRING_LITERAL(QUIC_INVALID_MESSAGE_DATA);
    RETURN_STRING_LITERAL(IETF_QUIC_PROTOCOL_VIOLATION);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEW_TOKEN);
    RETURN_STRING_LITERAL(QUIC_DATA_RECEIVED_ON_WRITE_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_LAST_ERROR);
    // Intentionally have no default case, so we'll break the build
    // if we add errors and don't put them here.
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicErrorCodes. This can happen when the ConnectionClose
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_ERROR_CODE";
}

void RecordInternalErrorLocation(QuicInternalErrorLocation location) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.InternalErrorLocation", location,
                            INTERNAL_ERROR_LOCATION_MAX);
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds
}  // namespace quic
