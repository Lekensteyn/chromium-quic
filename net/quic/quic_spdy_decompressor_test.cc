// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "net/quic/quic_spdy_compressor.h"
#include "net/quic/quic_spdy_decompressor.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

class QuicSpdyDecompressorTest : public ::testing::Test {
 protected:
  QuicSpdyDecompressor decompressor_;
  QuicSpdyCompressor compressor_;
  TestDecompressorVisitor visitor_;
};

TEST_F(QuicSpdyDecompressorTest, Decompress) {
  SpdyHeaderBlock headers;
  headers[":host"] = "www.google.com";
  headers[":path"] = "/index.hml";
  headers[":scheme"] = "https";

  EXPECT_EQ(1u, decompressor_.current_header_id());
  string compressed_headers = compressor_.CompressHeaders(headers).substr(4);
  EXPECT_EQ(compressed_headers.length(),
            decompressor_.DecompressData(compressed_headers, &visitor_));

  EXPECT_EQ(SpdyUtils::SerializeUncompressedHeaders(headers), visitor_.data());
  EXPECT_EQ(2u, decompressor_.current_header_id());
}

TEST_F(QuicSpdyDecompressorTest, DecompressAndIgnoreTrailingData) {
  SpdyHeaderBlock headers;
  headers[":host"] = "www.google.com";
  headers[":path"] = "/index.hml";
  headers[":scheme"] = "https";

  string compressed_headers = compressor_.CompressHeaders(headers).substr(4);
  EXPECT_EQ(compressed_headers.length(),
            decompressor_.DecompressData(compressed_headers + "abc123",
                                        &visitor_));

  EXPECT_EQ(SpdyUtils::SerializeUncompressedHeaders(headers), visitor_.data());
}

}  // namespace
}  // namespace test
}  // namespace net
