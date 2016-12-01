// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_TRANSMISSION_INFO_H_
#define NET_QUIC_CORE_QUIC_TRANSMISSION_INFO_H_

#include <list>

#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/quic_ack_listener_interface.h"
#include "net/quic/core/quic_types.h"

namespace net {

// Stores details of a single sent packet.
struct NET_EXPORT_PRIVATE QuicTransmissionInfo {
  // Used by STL when assigning into a map.
  QuicTransmissionInfo();

  // Constructs a Transmission with a new all_transmissions set
  // containing |packet_number|.
  QuicTransmissionInfo(EncryptionLevel level,
                       QuicPacketNumberLength packet_number_length,
                       TransmissionType transmission_type,
                       QuicTime sent_time,
                       QuicPacketLength bytes_sent,
                       bool has_crypto_handshake,
                       int num_padding_bytes);

  QuicTransmissionInfo(const QuicTransmissionInfo& other);

  ~QuicTransmissionInfo();

  QuicFrames retransmittable_frames;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
  QuicPacketLength bytes_sent;
  QuicTime sent_time;
  // Reason why this packet was transmitted.
  TransmissionType transmission_type;
  // In flight packets have not been abandoned or lost.
  bool in_flight;
  // True if the packet can never be acked, so it can be removed.  Occurs when
  // a packet is never sent, after it is acknowledged once, or if it's a crypto
  // packet we never expect to receive an ack for.
  bool is_unackable;
  // True if the packet contains stream data from the crypto stream.
  bool has_crypto_handshake;
  // Non-zero if the packet needs padding if it's retransmitted.
  int16_t num_padding_bytes;
  // Stores the packet number of the next retransmission of this packet.
  // Zero if the packet has not been retransmitted.
  QuicPacketNumber retransmission;
  // Non-empty if there is a listener for this packet.
  std::list<AckListenerWrapper> ack_listeners;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_TRANSMISSION_INFO_H_
