// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_ack_listener_interface.h"

namespace net {

AckListenerWrapper::AckListenerWrapper(
    scoped_refptr<QuicAckListenerInterface> listener,
    QuicPacketLength data_length)
    : ack_listener(std::move(listener)), length(data_length) {}

AckListenerWrapper::AckListenerWrapper(const AckListenerWrapper& other) =
    default;

AckListenerWrapper::~AckListenerWrapper() {}

}  // namespace net
