// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aes_128_gcm_encrypter.h"

#include <openssl/evp.h>
#include <string.h>

#include "base/memory/scoped_ptr.h"
#include "net/quic/crypto/scoped_evp_cipher_ctx.h"

using base::StringPiece;

namespace net {

namespace {

const size_t kKeySize = 16;
const size_t kNoncePrefixSize = 4;
const size_t kAuthTagSize = 16;

}  // namespace

bool Aes128GcmEncrypter::SetKey(StringPiece key) {
  DCHECK_EQ(key.size(), sizeof(key_));
  if (key.size() != sizeof(key_)) {
    return false;
  }
  memcpy(key_, key.data(), key.size());
  return true;
}

bool Aes128GcmEncrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  DCHECK_EQ(nonce_prefix.size(), kNoncePrefixSize);
  if (nonce_prefix.size() != kNoncePrefixSize) {
    return false;
  }
  memcpy(nonce_, nonce_prefix.data(), nonce_prefix.size());
  return true;
}

QuicData* Aes128GcmEncrypter::Encrypt(QuicPacketSequenceNumber sequence_number,
                                      StringPiece associated_data,
                                      StringPiece plaintext) {
  COMPILE_ASSERT(sizeof(nonce_) == kNoncePrefixSize + sizeof(sequence_number),
                 incorrect_nonce_size);
  memcpy(nonce_ + kNoncePrefixSize, &sequence_number, sizeof(sequence_number));
  return EncryptWithNonce(StringPiece(reinterpret_cast<char*>(nonce_),
                                      sizeof(nonce_)),
                          associated_data, plaintext);
}

size_t Aes128GcmEncrypter::GetKeySize() const {
  return kKeySize;
}

size_t Aes128GcmEncrypter::GetNoncePrefixSize() const {
  return kNoncePrefixSize;
}

size_t Aes128GcmEncrypter::GetMaxPlaintextSize(size_t ciphertext_size) const {
  return ciphertext_size - kAuthTagSize;
}

// An AEAD_AES_128_GCM ciphertext is exactly 16 bytes longer than its
// corresponding plaintext.
size_t Aes128GcmEncrypter::GetCiphertextSize(size_t plaintext_size) const {
  return plaintext_size + kAuthTagSize;
}

QuicData* Aes128GcmEncrypter::EncryptWithNonce(StringPiece nonce,
                                               StringPiece associated_data,
                                               StringPiece plaintext) {
  size_t ciphertext_size = GetCiphertextSize(plaintext.length());
  scoped_ptr<char[]> ciphertext(new char[ciphertext_size]);

  // |output| points to the position in the |ciphertext| buffer to receive
  // the next output.
  unsigned char* output = reinterpret_cast<unsigned char*>(ciphertext.get());
  // |output_len| is passed to an OpenSSL function to receive the output
  // length.
  int output_len;

  ScopedEVPCipherCtx ctx;

  // Set the cipher type and the key. The IV (nonce) is set below.
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), NULL, key_,
                         NULL) == 0) {
    return NULL;
  }

  // Set the IV (nonce) length.
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                          NULL) == 0) {
    return NULL;
  }
  // Set the IV (nonce).
  if (EVP_EncryptInit_ex(ctx.get(), NULL, NULL, NULL,
                         reinterpret_cast<const unsigned char*>(
                             nonce.data())) == 0) {
    return NULL;
  }

  // Set the associated data. The second argument (output buffer) must be
  // NULL.
  if (EVP_EncryptUpdate(ctx.get(), NULL, &output_len,
                        reinterpret_cast<const unsigned char*>(
                            associated_data.data()),
                        associated_data.size()) == 0) {
    return NULL;
  }

  if (EVP_EncryptUpdate(ctx.get(), output, &output_len,
                        reinterpret_cast<const unsigned char*>(
                            plaintext.data()),
                        plaintext.size()) == 0) {
    return NULL;
  }
  output += output_len;

  if (EVP_EncryptFinal_ex(ctx.get(), output, &output_len) == 0) {
    return NULL;
  }
  output += output_len;

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAuthTagSize,
                          output) == 0) {
    return NULL;
  }

  return new QuicData(ciphertext.release(), ciphertext_size, true);
}

StringPiece Aes128GcmEncrypter::GetKey() const {
  return StringPiece(reinterpret_cast<const char*>(key_), sizeof(key_));
}

StringPiece Aes128GcmEncrypter::GetNoncePrefix() const {
  return StringPiece(reinterpret_cast<const char*>(nonce_), kNoncePrefixSize);
}

}  // namespace net
