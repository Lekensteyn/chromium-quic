// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FLAGS_H_
#define NET_QUIC_QUIC_FLAGS_H_

#include <stdint.h>

#include "net/base/net_export.h"

NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_time_loss_detection;
NET_EXPORT_PRIVATE extern bool FLAGS_use_early_return_when_verifying_chlo;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_bbr_congestion_control;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_allow_bbr;
NET_EXPORT_PRIVATE extern int64_t FLAGS_quic_time_wait_list_seconds;
NET_EXPORT_PRIVATE extern int64_t FLAGS_quic_time_wait_list_max_connections;
NET_EXPORT_PRIVATE extern bool FLAGS_enable_quic_stateless_reject_support;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_always_log_bugs_for_tests;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_auto_tune_receive_window;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_enable_multipath;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_require_handshake_confirmation;
NET_EXPORT_PRIVATE extern bool FLAGS_shift_quic_cubic_epoch_when_app_limited;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_measure_headers_hol_blocking_time;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_disable_pacing;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_respect_send_alarm2;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_never_write_unencrypted_data;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_require_fix;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_stateless_version_negotiation;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_supports_push_promise;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_supports_push_promise;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_rfc7539;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_log_loss_event;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_include_path_id_in_iv;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_cede_correctly;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_different_max_num_open_streams;
NET_EXPORT_PRIVATE extern bool
    FLAGS_quic_crypto_server_config_default_has_chacha20;
NET_EXPORT_PRIVATE extern bool FLAGS_check_peer_address_change_after_decryption;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_log_received_parameters;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_new_tcp_sender;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_save_initial_subkey_secret;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_ack_decimation2;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_connection_defer_ack_response;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_only_cancel_set_alarms;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_inplace_encryption2;
NET_EXPORT_PRIVATE extern bool FLAGS_spdy_on_stream_end;

#endif  // NET_QUIC_QUIC_FLAGS_H_
