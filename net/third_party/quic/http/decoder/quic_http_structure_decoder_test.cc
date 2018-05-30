// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quic/http/decoder/quic_http_structure_decoder.h"

// Tests decoding all of the fixed size HTTP/2 structures (i.e. those defined in
// gfe/quic/http/quic_http_structures.h) using QuicHttpStructureDecoder, which
// handles buffering of structures split across input buffer boundaries, and in
// turn uses DoDecode when it has all of a structure in a contiguous buffer.

// NOTE: This tests the first pair of Start and Resume, which don't take
// a remaining_payload parameter. The other pair are well tested via the
// payload decoder tests, though...
// TODO(jamessynge): Create type parameterized tests for
// QuicHttpStructureDecoder where the type is the type of structure, and with
// testing of both pairs of Start and Resume methods; note that it appears that
// the first pair will be used only for QuicHttpFrameHeader, and the other pair
// only for structures in the frame payload.

#include <stddef.h>

#include <cstdint>

#include "base/logging.h"
#include "net/third_party/quic/http/decoder/quic_http_decode_buffer.h"
#include "net/third_party/quic/http/decoder/quic_http_decode_status.h"
#include "net/third_party/quic/http/quic_http_constants.h"
#include "net/third_party/quic/http/quic_http_structures_test_util.h"
#include "net/third_party/quic/http/tools/quic_http_random_decoder_test.h"
#include "net/third_party/quic/platform/api/quic_reconstruct_object.h"
#include "net/third_party/quic/platform/api/quic_string.h"
#include "net/third_party/quic/platform/api/quic_string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionFailure;
using ::testing::AssertionResult;
using ::testing::AssertionSuccess;

namespace quic {
namespace test {
namespace {
const bool kMayReturnZeroOnFirst = false;

template <class S>
class QuicHttpStructureDecoderTest : public QuicHttpRandomDecoderTest {
 protected:
  typedef S Structure;

  QuicHttpStructureDecoderTest() {
    // IF the test adds more data after the encoded structure, stop as
    // soon as the structure is decoded.
    stop_decode_on_done_ = true;
  }

  QuicHttpDecodeStatus StartDecoding(QuicHttpDecodeBuffer* b) override {
    // Overwrite the current contents of |structure_|, in to which we'll
    // decode the buffer, so that we can be confident that we really decoded
    // the structure every time.
    QuicDefaultReconstructObject(&structure_, RandomPtr());
    uint32_t old_remaining = b->Remaining();
    if (structure_decoder_.Start(&structure_, b)) {
      EXPECT_EQ(old_remaining - S::EncodedSize(), b->Remaining());
      ++fast_decode_count_;
      return QuicHttpDecodeStatus::kDecodeDone;
    } else {
      EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
      EXPECT_EQ(0u, b->Remaining());
      EXPECT_EQ(old_remaining - structure_decoder_.offset(), b->Remaining());
      ++incomplete_start_count_;
      return QuicHttpDecodeStatus::kDecodeInProgress;
    }
  }

  QuicHttpDecodeStatus ResumeDecoding(QuicHttpDecodeBuffer* b) override {
    uint32_t old_offset = structure_decoder_.offset();
    EXPECT_LT(old_offset, S::EncodedSize());
    uint32_t avail = b->Remaining();
    if (structure_decoder_.Resume(&structure_, b)) {
      EXPECT_LE(S::EncodedSize(), old_offset + avail);
      EXPECT_EQ(b->Remaining(), avail - (S::EncodedSize() - old_offset));
      ++slow_decode_count_;
      return QuicHttpDecodeStatus::kDecodeDone;
    } else {
      EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
      EXPECT_EQ(0u, b->Remaining());
      EXPECT_GT(S::EncodedSize(), old_offset + avail);
      ++incomplete_resume_count_;
      return QuicHttpDecodeStatus::kDecodeInProgress;
    }
  }

  // Fully decodes the Structure at the start of data, and confirms it matches
  // *expected (if provided).
  AssertionResult DecodeLeadingStructure(const S* expected,
                                         QuicStringPiece data) {
    VERIFY_LE(S::EncodedSize(), data.size());
    QuicHttpDecodeBuffer original(data);

    // The validator is called after each of the several times that the input
    // QuicHttpDecodeBuffer is decoded, each with a different segmentation of
    // the input. Validate that structure_ matches the expected value, if
    // provided.
    Validator validator;
    if (expected != nullptr) {
      validator = [expected, this](
                      const QuicHttpDecodeBuffer& db,
                      QuicHttpDecodeStatus status) -> AssertionResult {
        VERIFY_EQ(*expected, structure_);
        return AssertionSuccess();
      };
    }

    // Before that, validate that decoding is done and that we've advanced
    // the cursor the expected amount.
    validator = ValidateDoneAndOffset(S::EncodedSize(), validator);

    // Decode several times, with several segmentations of the input buffer.
    fast_decode_count_ = 0;
    slow_decode_count_ = 0;
    incomplete_start_count_ = 0;
    incomplete_resume_count_ = 0;
    VERIFY_SUCCESS(DecodeAndValidateSeveralWays(
        &original, kMayReturnZeroOnFirst, validator));
    VERIFY_FALSE(HasFailure());
    VERIFY_EQ(S::EncodedSize(), structure_decoder_.offset());
    VERIFY_EQ(S::EncodedSize(), original.Offset());
    VERIFY_LT(0u, fast_decode_count_);
    VERIFY_LT(0u, slow_decode_count_);
    VERIFY_LT(0u, incomplete_start_count_);

    // If the structure is large enough so that SelectZeroOrOne will have
    // caused Resume to return false, check that occurred.
    if (S::EncodedSize() >= 2) {
      VERIFY_LE(0u, incomplete_resume_count_);
    } else {
      VERIFY_EQ(0u, incomplete_resume_count_);
    }
    if (expected != nullptr) {
      DVLOG(1) << "DecodeLeadingStructure expected: " << *expected;
      DVLOG(1) << "DecodeLeadingStructure   actual: " << structure_;
      VERIFY_EQ(*expected, structure_);
    }
    return AssertionSuccess();
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const char (&data)[N]) {
    VERIFY_AND_RETURN_SUCCESS(
        DecodeLeadingStructure(nullptr, QuicStringPiece(data, N)));
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const unsigned char (&data)[N]) {
    VERIFY_AND_RETURN_SUCCESS(
        DecodeLeadingStructure(nullptr, ToStringPiece(data)));
  }

  // Encode the structure |in_s| into bytes, then decode the bytes
  // and validate that the decoder produced the same field values.
  AssertionResult EncodeThenDecode(const S& in_s) {
    QuicString bytes = SerializeStructure(in_s);
    VERIFY_EQ(S::EncodedSize(), bytes.size());
    VERIFY_AND_RETURN_SUCCESS(DecodeLeadingStructure(&in_s, bytes));
  }

  // Repeatedly fill a structure with random but valid contents, encode it, then
  // decode it, and finally validate that the decoded structure matches the
  // random input. Lather-rinse-and-repeat.
  AssertionResult TestDecodingRandomizedStructures(size_t count) {
    for (size_t i = 0; i < count; ++i) {
      Structure input;
      Randomize(&input, RandomPtr());
      VERIFY_SUCCESS(EncodeThenDecode(input));
    }
    return AssertionSuccess();
  }

  AssertionResult TestDecodingRandomizedStructures() {
    VERIFY_SUCCESS(TestDecodingRandomizedStructures(100));
    return AssertionSuccess();
  }

  S structure_;
  QuicHttpStructureDecoder structure_decoder_;
  size_t fast_decode_count_ = 0;
  size_t slow_decode_count_ = 0;
  size_t incomplete_start_count_ = 0;
  size_t incomplete_resume_count_ = 0;
};

class QuicHttpFrameHeaderDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpFrameHeader> {};

TEST_F(QuicHttpFrameHeaderDecoderTest, DecodesLiteral) {
  {
    // Realistic input.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x05,        // Payload length: 5
        0x01,                    // Frame type: HEADERS
        0x08,                    // Flags: QUIC_HTTP_PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream ID: 1
        0x04,                    // Padding length: 4
        0x00, 0x00, 0x00, 0x00,  // Padding bytes
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_.payload_length);
    EXPECT_EQ(QuicHttpFrameType::HEADERS, structure_.type);
    EXPECT_EQ(QuicHttpFrameFlag::QUIC_HTTP_PADDED, structure_.flags);
    EXPECT_EQ(1u, structure_.stream_id);
  }
  {
    // Unlikely input.
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff,        // Payload length: uint24 max
        0xff,                    // Frame type: Unknown
        0xff,                    // Flags: Unknown/All
        0xff, 0xff, 0xff, 0xff,  // Stream ID: uint31 max, plus R-bit
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ((1 << 24) - 1u, structure_.payload_length);
    EXPECT_EQ(static_cast<QuicHttpFrameType>(255), structure_.type);
    EXPECT_EQ(255, structure_.flags);
    EXPECT_EQ(0x7fffffffu, structure_.stream_id);
  }
}

TEST_F(QuicHttpFrameHeaderDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpPriorityFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpPriorityFields> {};

TEST_F(QuicHttpPriorityFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x80, 0x00, 0x00, 0x05,  // Exclusive (yes) and Dependency (5)
        0xff,                    // Weight: 256 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_.stream_dependency);
    EXPECT_EQ(256u, structure_.weight);
    EXPECT_EQ(true, structure_.is_exclusive);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x7f, 0xff, 0xff, 0xff,  // Excl. (no) and Dependency (uint31 max)
        0x00,                    // Weight: 1 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(QuicHttpStreamIdMask(), structure_.stream_dependency);
    EXPECT_EQ(1u, structure_.weight);
    EXPECT_EQ(false, structure_.is_exclusive);
  }
}

TEST_F(QuicHttpPriorityFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpRstStreamFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpRstStreamFields> {};

TEST_F(QuicHttpRstStreamFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Error: PROTOCOL_ERROR
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_.IsSupportedErrorCode());
    EXPECT_EQ(QuicHttpErrorCode::PROTOCOL_ERROR, structure_.error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_.IsSupportedErrorCode());
    EXPECT_EQ(static_cast<QuicHttpErrorCode>(0xffffffff),
              structure_.error_code);
  }
}

TEST_F(QuicHttpRstStreamFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpSettingFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpSettingFields> {};

TEST_F(QuicHttpSettingFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01,              // Setting: HEADER_TABLE_SIZE
        0x00, 0x00, 0x40, 0x00,  // Value: 16K
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_.IsSupportedParameter());
    EXPECT_EQ(QuicHttpSettingsParameter::HEADER_TABLE_SIZE,
              structure_.parameter);
    EXPECT_EQ(1u << 14, structure_.value);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x00,              // Setting: Unknown (0)
        0xff, 0xff, 0xff, 0xff,  // Value: max uint32
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_.IsSupportedParameter());
    EXPECT_EQ(static_cast<QuicHttpSettingsParameter>(0), structure_.parameter);
  }
}

TEST_F(QuicHttpSettingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpPushPromiseFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpPushPromiseFields> {};

TEST_F(QuicHttpPushPromiseFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x01, 0x8a, 0x92,  // Promised Stream ID: 101010
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(101010u, structure_.promised_stream_id);
  }
  {
    // Promised stream id has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
        // Promised Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(QuicHttpStreamIdMask(), structure_.promised_stream_id);
  }
}

TEST_F(QuicHttpPushPromiseFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpPingFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpPingFields> {};

TEST_F(QuicHttpPingFieldsDecoderTest, DecodesLiteral) {
  {
    // Each byte is different, so can detect if order changed.
    const char kData[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_.opaque_bytes));
  }
  {
    // All zeros, detect problems handling NULs.
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_.opaque_bytes));
  }
  {
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_.opaque_bytes));
  }
}

TEST_F(QuicHttpPingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpGoAwayFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpGoAwayFields> {};

TEST_F(QuicHttpGoAwayFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Last Stream ID: 0
        0x00, 0x00, 0x00, 0x00,  // Error: NO_ERROR (0)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_.last_stream_id);
    EXPECT_TRUE(structure_.IsSupportedErrorCode());
    EXPECT_EQ(QuicHttpErrorCode::HTTP2_NO_ERROR, structure_.error_code);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Last Stream ID: 1
        0x00, 0x00, 0x00, 0x0d,  // Error: HTTP_1_1_REQUIRED
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u, structure_.last_stream_id);
    EXPECT_TRUE(structure_.IsSupportedErrorCode());
    EXPECT_EQ(QuicHttpErrorCode::HTTP_1_1_REQUIRED, structure_.error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Last Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(QuicHttpStreamIdMask(),
              structure_.last_stream_id);  // No high-bit.
    EXPECT_FALSE(structure_.IsSupportedErrorCode());
    EXPECT_EQ(static_cast<QuicHttpErrorCode>(0xffffffff),
              structure_.error_code);
  }
}

TEST_F(QuicHttpGoAwayFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpWindowUpdateFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpWindowUpdateFields> {};

TEST_F(QuicHttpWindowUpdateFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01, 0x00, 0x00,  // Window Size Increment: 2 ^ 16
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u << 16, structure_.window_size_increment);
  }
  {
    // Increment must be non-zero, but we need to be able to decode the invalid
    // zero to detect it.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Window Size Increment: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_.window_size_increment);
  }
  {
    // Increment has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
      // Window Size Increment: max uint31 and R-bit
      0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(QuicHttpStreamIdMask(), structure_.window_size_increment);
  }
}

TEST_F(QuicHttpWindowUpdateFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class QuicHttpAltSvcFieldsDecoderTest
    : public QuicHttpStructureDecoderTest<QuicHttpAltSvcFields> {};

TEST_F(QuicHttpAltSvcFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00,  // Origin Length: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_.origin_length);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x14,  // Origin Length: 20
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(20u, structure_.origin_length);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff,  // Origin Length: uint16 max
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(65535u, structure_.origin_length);
  }
}

TEST_F(QuicHttpAltSvcFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

}  // namespace
}  // namespace test
}  // namespace quic