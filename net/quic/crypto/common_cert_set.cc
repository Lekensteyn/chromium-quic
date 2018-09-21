// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/common_cert_set.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;

namespace net {

namespace common_cert_set_0 {
#include "net/quic/crypto/common_cert_set_0.c"
}


struct CertSet {
  size_t num_certs;
  const unsigned char* const* certs;
  const size_t* lens;
  uint64 hash;
};

static const CertSet kSets[] = {
  {
    common_cert_set_0::kNumCerts,
    common_cert_set_0::kCerts,
    common_cert_set_0::kLens,
    common_cert_set_0::kHash,
  },
};

static const uint64 kSetHashes[] = {
  common_cert_set_0::kHash,
};

CommonCertSet::~CommonCertSet() {
}

CommonCertSetQUIC::CommonCertSetQUIC() {
}

StringPiece CommonCertSetQUIC::GetCommonHashes() {
  return StringPiece(reinterpret_cast<const char*>(kSetHashes),
                     sizeof(uint64) * arraysize(kSetHashes));
}

StringPiece CommonCertSetQUIC::GetCert(uint64 hash, uint32 index) {
  for (size_t i = 0; i < arraysize(kSets); i++) {
    if (kSets[i].hash == hash) {
      if (index >= kSets[i].num_certs) {
        return StringPiece();
      }
      return StringPiece(reinterpret_cast<const char*>(kSets[i].certs[index]),
                         kSets[i].lens[index]);
    }
  }

  return StringPiece();
}

// Compare returns a value less than, equal to or greater than zero if |a| is
// lexicographically less than, equal to or greater than |b|, respectively.
static int Compare(StringPiece a, const unsigned char* b, size_t b_len) {
  size_t len = a.size();
  if (len > b_len) {
    len = b_len;
  }
  int n = memcmp(a.data(), b, len);
  if (n != 0) {
    return n;
  }

  if (a.size() < b_len) {
    return -1;
  } else if (a.size() > b_len) {
    return 1;
  }
  return 0;
}

bool CommonCertSetQUIC::MatchCert(StringPiece cert,
                                  StringPiece common_set_hashes,
                                  uint64* out_hash,
                                  uint32* out_index) {
  if (common_set_hashes.size() % sizeof(uint64) != 0) {
    return false;
  }

  for (size_t i = 0; i < common_set_hashes.size() / sizeof(uint64); i++) {
    uint64 hash;
    memcpy(&hash, common_set_hashes.data() + i*sizeof(uint64), sizeof(uint64));

    for (size_t j = 0; j < arraysize(kSets); j++) {
      if (kSets[j].hash != hash) {
        continue;
      }

      if (kSets[j].num_certs == 0) {
        continue;
      }

      // Binary search for a matching certificate.
      size_t min = 0;
      size_t max = kSets[j].num_certs - 1;
      for (;;) {
        if (max < min) {
          break;
        }

        size_t mid = min + ((max - min) / 2);
        int n = Compare(cert, kSets[j].certs[mid], kSets[j].lens[mid]);
        if (n < 0) {
          if (mid == 0) {
            break;
          }
          max = mid - 1;
        } else if (n > 0) {
          min = mid + 1;
        } else {
          *out_hash = hash;
          *out_index = mid;
          return true;
        }
      }
    }
  }

  return false;
}

}  // namespace net
