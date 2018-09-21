// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "net/quic/quic_write_blocked_list.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicWriteBlockedListTest, PriorityOrder) {
  QuicWriteBlockedList write_blocked_list;

  // Mark streams blocked in roughly reverse priority order, and
  // verify that streams are sorted.
  write_blocked_list.PushBack(40,
                              QuicWriteBlockedList::kLowestPriority,
                              QUIC_VERSION_13);
  write_blocked_list.PushBack(23,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);
  write_blocked_list.PushBack(17,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);
  write_blocked_list.PushBack(kHeadersStreamId,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);
  write_blocked_list.PushBack(kCryptoStreamId,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);

  EXPECT_EQ(5u, write_blocked_list.NumBlockedStreams());
  EXPECT_TRUE(write_blocked_list.HasWriteBlockedStreams());
  // The Crypto stream is highest priority.
  EXPECT_EQ(kCryptoStreamId, write_blocked_list.PopFront());
  // Followed by the Headers stream.
  EXPECT_EQ(kHeadersStreamId, write_blocked_list.PopFront());
  // Streams with same priority are popped in the order they were inserted.
  EXPECT_EQ(23u, write_blocked_list.PopFront());
  EXPECT_EQ(17u, write_blocked_list.PopFront());
  // Low priority stream appears last.
  EXPECT_EQ(40u, write_blocked_list.PopFront());

  EXPECT_EQ(0u, write_blocked_list.NumBlockedStreams());
  EXPECT_FALSE(write_blocked_list.HasWriteBlockedStreams());
}

TEST(QuicWriteBlockedListTest, CryptoStream) {
  QuicWriteBlockedList write_blocked_list;
  write_blocked_list.PushBack(kCryptoStreamId,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);

  EXPECT_EQ(1u, write_blocked_list.NumBlockedStreams());
  EXPECT_TRUE(write_blocked_list.HasWriteBlockedStreams());
  EXPECT_EQ(kCryptoStreamId, write_blocked_list.PopFront());
  EXPECT_EQ(0u, write_blocked_list.NumBlockedStreams());
  EXPECT_FALSE(write_blocked_list.HasWriteBlockedStreams());
}

TEST(QuicWriteBlockedListTest, HeadersStream) {
  QuicWriteBlockedList write_blocked_list;
  write_blocked_list.PushBack(kHeadersStreamId,
                              QuicWriteBlockedList::kHighestPriority,
                              QUIC_VERSION_13);

  EXPECT_EQ(1u, write_blocked_list.NumBlockedStreams());
  EXPECT_TRUE(write_blocked_list.HasWriteBlockedStreams());
  EXPECT_EQ(kHeadersStreamId, write_blocked_list.PopFront());
  EXPECT_EQ(0u, write_blocked_list.NumBlockedStreams());
  EXPECT_FALSE(write_blocked_list.HasWriteBlockedStreams());
}

TEST(QuicWriteBlockedListTest, NoHeadersStreamInVersion12) {
  for (int idx = 0; idx < 2; ++idx) {
    QuicVersion version = ((idx == 0) ? QUIC_VERSION_13 : QUIC_VERSION_12);
    QuicWriteBlockedList write_blocked_list;
    write_blocked_list.PushBack(5,
                                QuicWriteBlockedList::kHighestPriority,
                                version);
    write_blocked_list.PushBack(kHeadersStreamId,
                                QuicWriteBlockedList::kHighestPriority,
                                version);

    EXPECT_EQ(2u, write_blocked_list.NumBlockedStreams());
    EXPECT_TRUE(write_blocked_list.HasWriteBlockedStreams());
    if (version > QUIC_VERSION_12) {
      // In newer QUIC versions, there is a headers stream which is
      // higher priority than data streams.
      EXPECT_EQ(kHeadersStreamId, write_blocked_list.PopFront());
      EXPECT_EQ(5u, write_blocked_list.PopFront());
    } else {
      // In older QUIC versions, there is no reserved headers stream id.
      EXPECT_EQ(5u, write_blocked_list.PopFront());
      EXPECT_EQ(kHeadersStreamId, write_blocked_list.PopFront());
    }
    EXPECT_EQ(0u, write_blocked_list.NumBlockedStreams());
    EXPECT_FALSE(write_blocked_list.HasWriteBlockedStreams());
  }
}

}  // namespace
}  // namespace test
}  // namespace net
