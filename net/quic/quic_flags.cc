// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_flags.h"

// TODO(rtenneti): Remove this.
// Do not flip this flag until the flakiness of the
// net/tools/quic/end_to_end_test is fixed.
// If true, then QUIC connections will track the retransmission history of a
// packet so that an ack of a previous transmission will ack the data of all
// other transmissions.
bool FLAGS_track_retransmission_history = false;

bool FLAGS_quic_allow_oversized_packets_for_test = false;

// When true, the use time based loss detection instead of nack.
bool FLAGS_quic_use_time_loss_detection = false;

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

// If true, QUIC crypto reject message will include the reasons for rejection.
bool FLAGS_send_quic_crypto_reject_reason = false;

// If true, QUIC connections will support FEC protection of data while sending
// packets, to reduce latency of data delivery to the application. The client
// must also request FEC protection for the server to use FEC.
bool FLAGS_enable_quic_fec = false;

// When true, defaults to BBR congestion control instead of Cubic.
bool FLAGS_quic_use_bbr_congestion_control = false;

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
bool FLAGS_quic_allow_bbr = false;

// If true, truncate QUIC connection IDs if the client requests it.
bool FLAGS_allow_truncated_connection_ids_for_quic = false;

// Do not flip this flag.  jokulik plans more testing and additional monitoring
// before the flag can go the auto-flip process.
//
// If true, record the timestamp for the last sent new packet before the call to
// WritePacket, rather than after in QUIC.
bool FLAGS_quic_record_send_time_before_write = false;

// If true, enables the QUIC bandwidth resumption experiment (triggered by
// Chrome/Finch).
bool FLAGS_quic_enable_bandwidth_resumption_experiment = true;

// If true, QUIC congestion control will be paced.  If false, pacing may be
// controlled by QUIC connection options in the config or by enabling BBR
// congestion control.
bool FLAGS_quic_enable_pacing = false;

// If true, the silent close option will be honored.
bool FLAGS_quic_allow_silent_close = true;

// If true, use std::cbrt instead of custom cube root.
bool FLAGS_quic_use_std_cbrt = true;

// If true, the QUIC packet generator will not attempt to queue multiple ACK
// frames.
bool FLAGS_quic_disallow_multiple_pending_ack_frames = true;

// If true, then the source address tokens generated for QUIC connects will
// store multiple addresses.
bool FLAGS_quic_use_multiple_address_in_source_tokens = false;
