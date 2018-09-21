// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_SOURCE_ADDRESS_TOKEN_H_
#define NET_QUIC_CRYPTO_SOURCE_ADDRESS_TOKEN_H_

#include <string>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/cached_network_parameters.h"

namespace net {

// TODO(rtenneti): sync with server more rationally.
// A SourceAddressToken is serialised, encrypted and sent to clients so that
// they can prove ownership of an IP address.
class NET_EXPORT_PRIVATE SourceAddressToken {
 public:
  SourceAddressToken();
  ~SourceAddressToken();

  std::string SerializeAsString() const;

  bool ParseFromArray(const char* plaintext, size_t plaintext_length);

  std::string ip() const {
    return ip_;
  }
  void set_ip(base::StringPiece ip) {
    ip_ = ip.as_string();
  }

  int64 timestamp() const {
    return timestamp_;
  }
  void set_timestamp(int64 timestamp) {
    timestamp_ = timestamp;
  }

  const CachedNetworkParameters& cached_network_parameters() const {
    return cached_network_parameters_;
  }
  void set_cached_network_parameters(
      const CachedNetworkParameters& cached_network_parameters) {
    cached_network_parameters_ = cached_network_parameters;
    has_cached_network_parameters_ = true;
  }
  bool has_cached_network_parameters() const {
    return has_cached_network_parameters_;
  }

 private:
  // ip_ contains either 4 (IPv4) or 16 (IPv6) bytes of IP address in network
  // byte order.
  std::string ip_;
  // timestamp_ contains a UNIX timestamp value of the time when the token was
  // created.
  int64 timestamp_;

  // The server can provide estimated network parameters to be used for
  // initial parameter selection in future connections.
  CachedNetworkParameters cached_network_parameters_;
  // TODO(rtenneti): Delete |has_cached_network_parameters_| after we convert
  // SourceAddressToken to protobuf.
  bool has_cached_network_parameters_;

  DISALLOW_COPY_AND_ASSIGN(SourceAddressToken);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_SOURCE_ADDRESS_TOKEN_H_
