// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_THIRD_PARTY_QUIC_PLATFORM_API_QUIC_PTR_UTIL_H_
#define NET_THIRD_PARTY_QUIC_PLATFORM_API_QUIC_PTR_UTIL_H_

#include <memory>
#include <utility>

#include "net/third_party/quic/platform/impl/quic_ptr_util_impl.h"

namespace quic {

template <typename T, typename... Args>
std::unique_ptr<T> QuicMakeUnique(Args&&... args) {
  return QuicMakeUniqueImpl<T>(std::forward<Args>(args)...);
}

template <typename T>
std::unique_ptr<T> QuicWrapUnique(T* ptr) {
  return QuicWrapUniqueImpl<T>(ptr);
}

}  // namespace quic

#endif  // NET_THIRD_PARTY_QUIC_PLATFORM_API_QUIC_PTR_UTIL_H_
