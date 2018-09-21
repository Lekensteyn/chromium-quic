// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <vector>

#include "base/hash_tables.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/port.h"
#include "base/stl_util.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"

using base::hash_set;
using base::StringPiece;
using std::string;
using std::vector;

namespace net {

namespace test {

class TestEncrypter : public QuicEncrypter {
 public:
  virtual ~TestEncrypter() {}
  virtual QuicData* Encrypt(StringPiece associated_data,
                            StringPiece plaintext) {
    associated_data_ = associated_data.as_string();
    plaintext_ = plaintext.as_string();
    return new QuicData(plaintext.data(), plaintext.length());
  }
  virtual size_t GetMaxPlaintextSize(size_t ciphertext_size) {
    return ciphertext_size;
  }
  virtual size_t GetCiphertextSize(size_t plaintext_size) {
    return plaintext_size;
  }
  string associated_data_;
  string plaintext_;
};

class TestDecrypter : public QuicDecrypter {
 public:
  virtual ~TestDecrypter() {}
  virtual QuicData* Decrypt(StringPiece associated_data,
                            StringPiece ciphertext) {
    associated_data_ = associated_data.as_string();
    ciphertext_ = ciphertext.as_string();
    return new QuicData(ciphertext.data(), ciphertext.length());
  }
  string associated_data_;
  string ciphertext_;
};

// The offset of congestion info in our tests, given the size of our usual ack
// frame.  This does NOT work for all packets.
const int kCongestionInfoOffset = kPacketHeaderSize + 54;

class TestQuicVisitor : public ::net::QuicFramerVisitorInterface {
 public:
  TestQuicVisitor()
      : error_count_(0),
        packet_count_(0),
        frame_count_(0),
        fec_count_(0),
        complete_packets_(0),
        accept_packet_(true) {
  }

  ~TestQuicVisitor() {
    STLDeleteElements(&stream_frames_);
    STLDeleteElements(&ack_frames_);
    STLDeleteElements(&fec_data_);
  }

  virtual void OnError(QuicFramer* f) {
    DLOG(INFO) << "QuicFramer Error: " << QuicUtils::ErrorToString(f->error())
               << " (" << f->error() << ")";
    error_count_++;
  }

  virtual void OnPacket(const IPEndPoint& client_address) {
    address_ = client_address;
  }

  virtual bool OnPacketHeader(const QuicPacketHeader& header) {
    packet_count_++;
    header_.reset(new QuicPacketHeader(header));
    return accept_packet_;
  }

  virtual void OnStreamFrame(const QuicStreamFrame& frame) {
    frame_count_++;
    stream_frames_.push_back(new QuicStreamFrame(frame));
  }

  virtual void OnFecProtectedPayload(StringPiece payload) {
    fec_protected_payload_ = payload.as_string();
  }

  virtual void OnAckFrame(const QuicAckFrame& frame) {
    frame_count_++;
    ack_frames_.push_back(new QuicAckFrame(frame));
  }

  virtual void OnFecData(const QuicFecData& fec) {
    fec_count_++;
    fec_data_.push_back(new QuicFecData(fec));
  }

  virtual void OnPacketComplete() {
    complete_packets_++;
  }

  virtual void OnRstStreamFrame(const QuicRstStreamFrame& frame) {
    rst_stream_frame_ = frame;
  }

  virtual void OnConnectionCloseFrame(
      const QuicConnectionCloseFrame& frame) {
    connection_close_frame_ = frame;
  }

  // Counters from the visitor_ callbacks.
  int error_count_;
  int packet_count_;
  int frame_count_;
  int fec_count_;
  int complete_packets_;
  bool accept_packet_;

  IPEndPoint address_;
  scoped_ptr<QuicPacketHeader> header_;
  vector<QuicStreamFrame*> stream_frames_;
  vector<QuicAckFrame*> ack_frames_;
  vector<QuicFecData*> fec_data_;
  string fec_protected_payload_;
  QuicRstStreamFrame rst_stream_frame_;
  QuicConnectionCloseFrame connection_close_frame_;
};

class QuicFramerTest : public ::testing::Test {
 public:
  QuicFramerTest()
      : encrypter_(new test::TestEncrypter()),
        decrypter_(new test::TestDecrypter()),
        framer_(decrypter_, encrypter_) {
    framer_.set_visitor(&visitor_);
  }

  bool CheckEncryption(StringPiece packet) {
    StringPiece associated_data(
        packet.substr(kStartOfHashData,
                      kStartOfEncryptedData - kStartOfHashData));
    if (associated_data != encrypter_->associated_data_) {
      LOG(ERROR) << "Encrypted incorrect associated data.  expected "
                 << associated_data << " actual: "
                 << encrypter_->associated_data_;
      return false;
    }
    StringPiece plaintext(packet.substr(kStartOfEncryptedData));
    if (plaintext != encrypter_->plaintext_) {
      LOG(ERROR) << "Encrypted incorrect plaintext data.  expected "
                 << plaintext << " actual: "
                 << encrypter_->plaintext_;
      return false;
    }
    return true;
  }

  bool CheckDecryption(StringPiece packet) {
    StringPiece associated_data(
        packet.substr(kStartOfHashData,
                      kStartOfEncryptedData - kStartOfHashData));
    if (associated_data != decrypter_->associated_data_) {
      LOG(ERROR) << "Decrypted incorrect associated data.  expected "
                 << associated_data << " actual: "
                 << decrypter_->associated_data_;
      return false;
    }
    StringPiece plaintext(packet.substr(kStartOfEncryptedData));
    if (plaintext != decrypter_->ciphertext_) {
      LOG(ERROR) << "Decrypted incorrect chipertext data.  expected "
                 << plaintext << " actual: "
                 << decrypter_->ciphertext_;
      return false;
    }
    return true;
  }

  char* AsChars(unsigned char* data) {
    return reinterpret_cast<char*>(data);
  }

  test::TestEncrypter* encrypter_;
  test::TestDecrypter* decrypter_;
  QuicFramer framer_;
  test::TestQuicVisitor visitor_;
  IPEndPoint address_;
};

TEST_F(QuicFramerTest, EmptyPacket) {
  char packet[] = { 0x00 };
  QuicEncryptedPacket encrypted(packet, 0, false);
  EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
  EXPECT_EQ(QUIC_INVALID_PACKET_HEADER, framer_.error());
}

TEST_F(QuicFramerTest, LargePacket) {
  unsigned char packet[kMaxPacketSize + 1] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,
    // frame count
    0x01,
  };

  memset(packet + kPacketHeaderSize, 0, kMaxPacketSize - kPacketHeaderSize + 1);

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));

  ASSERT_TRUE(visitor_.header_.get());
  // Make sure we've parsed the packet header, so we can send an error.
  EXPECT_EQ(GG_UINT64_C(0xFEDCBA9876543210), visitor_.header_->guid);
  // Make sure the correct error is propogated.
  EXPECT_EQ(QUIC_PACKET_TOO_LARGE, framer_.error());
}

TEST_F(QuicFramerTest, PacketHeader) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(GG_UINT64_C(0xFEDCBA9876543210), visitor_.header_->guid);
  EXPECT_EQ(0x1, visitor_.header_->retransmission_count);
  EXPECT_EQ(GG_UINT64_C(0x123456789ABC),
            visitor_.header_->packet_sequence_number);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            visitor_.header_->transmission_time);
  EXPECT_EQ(0x00, visitor_.header_->flags);
  EXPECT_EQ(0x00, visitor_.header_->fec_group);

  // Now test framing boundaries
  for (int i = 0; i < 25; ++i) {
    string expected_error;
    if (i < 8) {
      expected_error = "Unable to read GUID.";
    } else if (i < 14) {
      expected_error = "Unable to read sequence number.";
    } else if (i < 15) {
      expected_error = "Unable to read retransmission count.";
    } else if (i < 23) {
      expected_error = "Unable to read transmission time.";
    } else if (i < 24) {
      expected_error = "Unable to read flags.";
    } else if (i < 25) {
      expected_error = "Unable to read fec group.";
    }

    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_PACKET_HEADER, framer_.error());
  }
}

TEST_F(QuicFramerTest, StreamFrame) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (stream frame)
    0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // fin
    0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  ASSERT_EQ(address_, visitor_.address_);

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(static_cast<uint64>(0x01020304),
            visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(GG_UINT64_C(0xBA98FEDC32107654),
            visitor_.stream_frames_[0]->offset);
  EXPECT_EQ("hello world!", visitor_.stream_frames_[0]->data);

  // Now test framing boundaries
  for (size_t i = kPacketHeaderSize; i < kPacketHeaderSize + 29; ++i) {
    string expected_error;
    if (i < kPacketHeaderSize + 1) {
      expected_error = "Unable to read frame count.";
    } else if (i < kPacketHeaderSize + 2) {
      expected_error = "Unable to read frame type.";
    } else if (i < kPacketHeaderSize + 6) {
      expected_error = "Unable to read stream_id.";
    } else if (i < kPacketHeaderSize + 7) {
      expected_error = "Unable to read fin.";
    } else if (i < kPacketHeaderSize + 15) {
      expected_error = "Unable to read offset.";
    } else if (i < kPacketHeaderSize + 29) {
      expected_error = "Unable to read frame data.";
    }

    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, RejectPacket) {
  visitor_.accept_packet_ = false;

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (stream frame)
    0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // fin
    0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  ASSERT_EQ(address_, visitor_.address_);

  ASSERT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
}

TEST_F(QuicFramerTest, RevivedStreamFrame) {
  unsigned char payload[] = {
    // frame count
    0x01,
    // frame type (stream frame)
    0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // fin
    0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  // Do not encrypt the payload because the revived payload is post-encryption.
  EXPECT_TRUE(framer_.ProcessRevivedPacket(address_,
                                           header,
                                           StringPiece(AsChars(payload),
                                                       arraysize(payload))));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_EQ(address_, visitor_.address_);
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(GG_UINT64_C(0xFEDCBA9876543210), visitor_.header_->guid);
  EXPECT_EQ(0x1, visitor_.header_->retransmission_count);
  EXPECT_EQ(GG_UINT64_C(0x123456789ABC),
            visitor_.header_->packet_sequence_number);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            visitor_.header_->transmission_time);
  EXPECT_EQ(0x00, visitor_.header_->flags);
  EXPECT_EQ(0x00, visitor_.header_->fec_group);


  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(GG_UINT64_C(0x01020304), visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(GG_UINT64_C(0xBA98FEDC32107654),
            visitor_.stream_frames_[0]->offset);
  EXPECT_EQ("hello world!", visitor_.stream_frames_[0]->data);
}

TEST_F(QuicFramerTest, StreamFrameInFecGroup) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x12, 0x34,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x02,

    // frame count
    0x01,
    // frame type (stream frame)
    0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // fin
    0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(2, visitor_.header_->fec_group);
  EXPECT_EQ(string(AsChars(packet) + kStartOfFecProtectedData,
                   arraysize(packet) - kStartOfFecProtectedData),
            visitor_.fec_protected_payload_);
  ASSERT_EQ(address_, visitor_.address_);

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(GG_UINT64_C(0x01020304), visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(GG_UINT64_C(0xBA98FEDC32107654),
            visitor_.stream_frames_[0]->offset);
  EXPECT_EQ("hello world!", visitor_.stream_frames_[0]->data);
}

TEST_F(QuicFramerTest, AckFrame) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (none)
    0x00,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABC),
            frame.received_info.largest_received);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            frame.received_info.time_received);

  const hash_set<QuicPacketSequenceNumber>* sequence_nums =
      &frame.received_info.missing_packets;
  ASSERT_EQ(2u, sequence_nums->size());
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABB)));
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABA)));
  EXPECT_EQ(GG_UINT64_C(0x0123456789AA0), frame.sent_info.least_unacked);
  ASSERT_EQ(3u, frame.sent_info.non_retransmiting.size());
  const hash_set<QuicPacketSequenceNumber>* non_retrans =
      &frame.sent_info.non_retransmiting;
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AB0)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAF)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAE)));
  ASSERT_EQ(kNone, frame.congestion_info.type);

  // Now test framing boundaries
  for (size_t i = kPacketHeaderSize; i < kPacketHeaderSize + 55; ++i) {
    string expected_error;
    if (i < kPacketHeaderSize + 1) {
      expected_error = "Unable to read frame count.";
    } else if (i < kPacketHeaderSize + 2) {
      expected_error = "Unable to read frame type.";
    } else if (i < kPacketHeaderSize + 8) {
      expected_error = "Unable to read largest received.";
    } else if (i < kPacketHeaderSize + 16) {
      expected_error = "Unable to read time received.";
    } else if (i < kPacketHeaderSize + 17) {
      expected_error = "Unable to read num unacked packets.";
    } else if (i < kPacketHeaderSize + 29) {
      expected_error = "Unable to read sequence number in unacked packets.";
    } else if (i < kPacketHeaderSize + 35) {
      expected_error = "Unable to read least unacked.";
    } else if (i < kPacketHeaderSize + 36) {
      expected_error = "Unable to read num non-retransmitting.";
    } else if (i < kPacketHeaderSize + 54) {
      expected_error = "Unable to read sequence number in non-retransmitting.";
    } else if (i < kPacketHeaderSize + 55) {
      expected_error = "Unable to read congestion info type.";
    }

    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, AckFrameTCP) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (tcp)
    0x01,
    // ack_frame.congestion_info.tcp.accumulated_number_of_lost_packets
    0x01, 0x02,
    // ack_frame.congestion_info.tcp.receive_window
    0x03, 0x04,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABC),
            frame.received_info.largest_received);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            frame.received_info.time_received);

  const hash_set<QuicPacketSequenceNumber>* sequence_nums =
      &frame.received_info.missing_packets;
  ASSERT_EQ(2u, sequence_nums->size());
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABB)));
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABA)));
  EXPECT_EQ(GG_UINT64_C(0x0123456789AA0), frame.sent_info.least_unacked);
  ASSERT_EQ(3u, frame.sent_info.non_retransmiting.size());
  const hash_set<QuicPacketSequenceNumber>* non_retrans =
      &frame.sent_info.non_retransmiting;
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AB0)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAF)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAE)));
  ASSERT_EQ(kTCP, frame.congestion_info.type);
  EXPECT_EQ(0x0201,
            frame.congestion_info.tcp.accumulated_number_of_lost_packets);
  EXPECT_EQ(0x0403, frame.congestion_info.tcp.receive_window);

  // Now test framing boundaries
  for (size_t i = kCongestionInfoOffset; i < kCongestionInfoOffset + 5; ++i) {
    string expected_error;
    if (i < kCongestionInfoOffset + 1) {
      expected_error = "Unable to read congestion info type.";
    } else if (i < kCongestionInfoOffset + 3) {
      expected_error = "Unable to read accumulated number of lost packets.";
    } else if (i < kCongestionInfoOffset + 5) {
      expected_error = "Unable to read receive window.";
    }

    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, AckFrameInterArrival) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (inter arrival)
    0x02,
    // accumulated_number_of_lost_packets
    0x02, 0x03,
    // offset_time
    0x04, 0x05,
    // delta_time
    0x06, 0x07,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABC),
            frame.received_info.largest_received);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            frame.received_info.time_received);

  const hash_set<QuicPacketSequenceNumber>* sequence_nums =
      &frame.received_info.missing_packets;
  ASSERT_EQ(2u, sequence_nums->size());
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABB)));
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABA)));
  EXPECT_EQ(GG_UINT64_C(0x0123456789AA0), frame.sent_info.least_unacked);
  ASSERT_EQ(3u, frame.sent_info.non_retransmiting.size());
  const hash_set<QuicPacketSequenceNumber>* non_retrans =
      &frame.sent_info.non_retransmiting;
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AB0)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAF)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAE)));
  ASSERT_EQ(kInterArrival, frame.congestion_info.type);
  EXPECT_EQ(0x0302, frame.congestion_info.inter_arrival.
            accumulated_number_of_lost_packets);
  EXPECT_EQ(0x0504, frame.congestion_info.inter_arrival.offset_time);
  EXPECT_EQ(0x0706, frame.congestion_info.inter_arrival.delta_time);

  // Now test framing boundaries
  for (size_t i = kCongestionInfoOffset; i < kCongestionInfoOffset + 5; ++i) {
    string expected_error;
    if (i < kCongestionInfoOffset + 1) {
      expected_error = "Unable to read congestion info type.";
    } else if (i < kCongestionInfoOffset + 3) {
      expected_error = "Unable to read accumulated number of lost packets.";
    } else if (i < kCongestionInfoOffset + 5) {
      expected_error = "Unable to read offset time.";
    } else if (i < kCongestionInfoOffset + 7) {
      expected_error = "Unable to read delta time.";
    }
    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, AckFrameFixRate) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (fix rate)
    0x03,
    // bitrate_in_bytes_per_second;
    0x01, 0x02, 0x03, 0x04,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABC),
            frame.received_info.largest_received);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            frame.received_info.time_received);

  const hash_set<QuicPacketSequenceNumber>* sequence_nums =
      &frame.received_info.missing_packets;
  ASSERT_EQ(2u, sequence_nums->size());
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABB)));
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABA)));
  EXPECT_EQ(GG_UINT64_C(0x0123456789AA0), frame.sent_info.least_unacked);
  ASSERT_EQ(3u, frame.sent_info.non_retransmiting.size());
  const hash_set<QuicPacketSequenceNumber>* non_retrans =
      &frame.sent_info.non_retransmiting;
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AB0)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAF)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAE)));
  ASSERT_EQ(kFixRate, frame.congestion_info.type);
  EXPECT_EQ(static_cast<uint32>(0x04030201),
            frame.congestion_info.fix_rate.bitrate_in_bytes_per_second);

  // Now test framing boundaries
  for (size_t i = kCongestionInfoOffset; i < kCongestionInfoOffset + 5; ++i) {
    string expected_error;
    if (i < kCongestionInfoOffset + 1) {
      expected_error = "Unable to read congestion info type.";
    } else if (i < kCongestionInfoOffset + 5) {
      expected_error = "Unable to read bitrate.";
    }
    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
  }
}


TEST_F(QuicFramerTest, AckFrameInvalidFeedback) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (invalid)
    0x04,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
}

TEST_F(QuicFramerTest, RstStreamFrame) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (rst stream frame)
    0x03,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // error code
    0x08, 0x07, 0x06, 0x05,

    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  ASSERT_EQ(address_, visitor_.address_);

  EXPECT_EQ(GG_UINT64_C(0x01020304), visitor_.rst_stream_frame_.stream_id);
  EXPECT_EQ(0x05060708, visitor_.rst_stream_frame_.error_code);
  EXPECT_EQ(GG_UINT64_C(0xBA98FEDC32107654),
            visitor_.rst_stream_frame_.offset);
  EXPECT_EQ("because I can", visitor_.rst_stream_frame_.error_details);

  // Now test framing boundaries
  for (size_t i = kPacketHeaderSize + 3; i < kPacketHeaderSize + 33; ++i) {
    string expected_error;
    if (i < kPacketHeaderSize + 6) {
      expected_error = "Unable to read stream_id.";
    } else if (i < kPacketHeaderSize + 14) {
      expected_error = "Unable to read offset in rst frame.";
    } else if (i < kPacketHeaderSize + 18) {
      expected_error = "Unable to read rst stream error code.";
    } else if (i < kPacketHeaderSize + 33) {
      expected_error = "Unable to read rst stream error details.";
    }
    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_RST_STREAM_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, ConnectionCloseFrame) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,


    // frame count
    0x01,
    // frame type (connection close frame)
    0x04,
    // error code
    0x08, 0x07, 0x06, 0x05,

    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',

    // Ack frame.

    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // congestion feedback type (inter arrival)
    0x02,
    // accumulated_number_of_lost_packets
    0x02, 0x03,
    // offset_time
    0x04, 0x05,
    // delta_time
    0x06, 0x07,
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(0x05060708, visitor_.connection_close_frame_.error_code);
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);

  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABC),
            frame.received_info.largest_received);
  EXPECT_EQ(GG_UINT64_C(0xF0E1D2C3B4A59687),
            frame.received_info.time_received);

  const hash_set<QuicPacketSequenceNumber>* sequence_nums =
      &frame.received_info.missing_packets;
  ASSERT_EQ(2u, sequence_nums->size());
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABB)));
  EXPECT_EQ(1u, sequence_nums->count(GG_UINT64_C(0x0123456789ABA)));
  EXPECT_EQ(GG_UINT64_C(0x0123456789AA0), frame.sent_info.least_unacked);
  ASSERT_EQ(3u, frame.sent_info.non_retransmiting.size());
  const hash_set<QuicPacketSequenceNumber>* non_retrans =
      &frame.sent_info.non_retransmiting;
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AB0)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAF)));
  EXPECT_EQ(1u, non_retrans->count(GG_UINT64_C(0x0123456789AAE)));
  ASSERT_EQ(kInterArrival, frame.congestion_info.type);
  EXPECT_EQ(0x0302, frame.congestion_info.inter_arrival.
            accumulated_number_of_lost_packets);
  EXPECT_EQ(0x0504,
            frame.congestion_info.inter_arrival.offset_time);
  EXPECT_EQ(0x0706,
            frame.congestion_info.inter_arrival.delta_time);

  // Now test framing boundaries
  for (size_t i = kPacketHeaderSize + 3; i < kPacketHeaderSize + 21; ++i) {
    string expected_error;
    if (i < kPacketHeaderSize + 6) {
      expected_error = "Unable to read connection close error code.";
    } else if (i < kPacketHeaderSize + 21) {
      expected_error = "Unable to read connection close error details.";
    }

    QuicEncryptedPacket encrypted(AsChars(packet), i, false);
    EXPECT_FALSE(framer_.ProcessPacket(address_, encrypted));
    EXPECT_EQ(expected_error, framer_.detailed_error());
    EXPECT_EQ(QUIC_INVALID_CONNECTION_CLOSE_DATA, framer_.error());
  }
}

TEST_F(QuicFramerTest, FecPacket) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags (FEC)
    0x01,
    // fec group
    0x01,

    // first protected packet
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(address_, encrypted));

  EXPECT_TRUE(CheckDecryption(StringPiece(AsChars(packet), arraysize(packet))));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  ASSERT_EQ(1, visitor_.fec_count_);
  const QuicFecData& fec_data = *visitor_.fec_data_[0];
  EXPECT_EQ(GG_UINT64_C(0x0123456789ABB),
            fec_data.first_protected_packet_sequence_number);
  EXPECT_EQ("abcdefghijklmnop", fec_data.redundancy);
}

TEST_F(QuicFramerTest, ConstructStreamFramePacket) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicStreamFrame stream_frame;
  stream_frame.stream_id = 0x01020304;
  stream_frame.fin = true;
  stream_frame.offset = GG_UINT64_C(0xBA98FEDC32107654);
  stream_frame.data = "hello world!";

  QuicFrame frame;
  frame.type = STREAM_FRAME;
  frame.stream_frame = &stream_frame;

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (stream frame)
    0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // fin
    0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  QuicPacket* data;
  ASSERT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructAckFramePacket) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicAckFrame ack_frame;
  ack_frame.received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame.received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame.sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame.congestion_info.type = kNone;

  QuicFrame frame;
  frame.type = ACK_FRAME;
  frame.ack_frame = &ack_frame;

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
#if defined(OS_WIN)
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
#if defined(OS_WIN)
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // congestion feedback type (none)
    0x00,
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructAckFramePacketTCP) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicAckFrame ack_frame;
  ack_frame.received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame.received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame.sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame.congestion_info.type = kTCP;
  ack_frame.congestion_info.tcp.accumulated_number_of_lost_packets = 0x0201;
  ack_frame.congestion_info.tcp.receive_window = 0x0403;

  QuicFrame frame;
  frame.type = ACK_FRAME;
  frame.ack_frame = &ack_frame;

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
#if defined(OS_WIN)
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
#if defined(OS_WIN)
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // congestion feedback type (tcp)
    0x01,
    // ack_frame.congestion_info.tcp.accumulated_number_of_lost_packets
    0x01, 0x02,
    // ack_frame.congestion_info.tcp.receive_window
    0x03, 0x04,
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructAckFramePacketInterArrival) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicAckFrame ack_frame;
  ack_frame.received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame.received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame.sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame.congestion_info.type = kInterArrival;
  ack_frame.congestion_info.inter_arrival.accumulated_number_of_lost_packets
      = 0x0302;
  ack_frame.congestion_info.inter_arrival.offset_time = 0x0504;
  ack_frame.congestion_info.inter_arrival.delta_time = 0x0706;

  QuicFrame frame;
  frame.type = ACK_FRAME;
  frame.ack_frame = &ack_frame;

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
#if defined(OS_WIN)
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
#if defined(OS_WIN)
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // congestion feedback type (inter arrival)
    0x02,
    // accumulated_number_of_lost_packets
    0x02, 0x03,
    // offset_time
    0x04, 0x05,
    // delta_time
    0x06, 0x07,
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructAckFramePacketFixRate) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicAckFrame ack_frame;
  ack_frame.received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame.received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame.sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame.congestion_info.type = kFixRate;
  ack_frame.congestion_info.fix_rate.bitrate_in_bytes_per_second
      = 0x04030201;

  QuicFrame frame;
  frame.type = ACK_FRAME;
  frame.ack_frame = &ack_frame;

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (ack frame)
    0x02,
    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
#if defined(OS_WIN)
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
#if defined(OS_WIN)
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // congestion feedback type (fix rate)
    0x03,
    // bitrate_in_bytes_per_second;
    0x01, 0x02, 0x03, 0x04,
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructAckFramePacketInvalidFeedback) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicAckFrame ack_frame;
  ack_frame.received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame.received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame.received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame.sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame.sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame.congestion_info.type =
      static_cast<CongestionFeedbackType>(kFixRate + 1);

  QuicFrame frame;
  frame.type = ACK_FRAME;
  frame.ack_frame = &ack_frame;

  QuicFrames frames;
  frames.push_back(frame);

  QuicPacket* data;
  EXPECT_FALSE(framer_.ConstructFragementDataPacket(header, frames, &data));
}

TEST_F(QuicFramerTest, ConstructRstFramePacket) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicRstStreamFrame rst_frame;
  rst_frame.stream_id = 0x01020304;
  rst_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  rst_frame.offset = GG_UINT64_C(0xBA98FEDC32107654);
  rst_frame.error_details = "because I can";

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (rst stream frame)
    0x03,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // error code
    0x08, 0x07, 0x06, 0x05,
    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };

  QuicFrame frame(&rst_frame);

  QuicFrames frames;
  frames.push_back(frame);

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructCloseFramePacket) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicConnectionCloseFrame close_frame;
  close_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  close_frame.error_details = "because I can";

  QuicAckFrame* ack_frame = &close_frame.ack_frame;
  ack_frame->received_info.largest_received = GG_UINT64_C(0x0123456789ABC);
  ack_frame->received_info.time_received = GG_UINT64_C(0xF0E1D2C3B4A59687);
  ack_frame->received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABB));
  ack_frame->received_info.missing_packets.insert(
      GG_UINT64_C(0x0123456789ABA));
  ack_frame->sent_info.least_unacked = GG_UINT64_C(0x0123456789AA0);
  ack_frame->sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AB0));
  ack_frame->sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAF));
  ack_frame->sent_info.non_retransmiting.insert(
      GG_UINT64_C(0x0123456789AAE));
  ack_frame->congestion_info.type = kInterArrival;
  ack_frame->congestion_info.inter_arrival.accumulated_number_of_lost_packets
      = 0x0302;
  ack_frame->congestion_info.inter_arrival.offset_time = 0x0504;
  ack_frame->congestion_info.inter_arrival.delta_time = 0x0706;

  QuicFrame frame(&close_frame);

  QuicFrames frames;
  frames.push_back(frame);

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x00,
    // fec group
    0x00,

    // frame count
    0x01,
    // frame type (connection close frame)
    0x04,
    // error code
    0x08, 0x07, 0x06, 0x05,
    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',

    // Ack frame.

    // largest received packet sequence number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // time delta
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // num_unacked_packets
    0x02,
#if defined(OS_WIN)
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // unacked packet sequence number
    0xBA, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // unacked packet sequence number
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // least packet sequence number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num non retransmitting packets
    0x03,
#if defined(OS_WIN)
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#else
    // non retransmitting packet sequence number
    0xAE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xAF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // non retransmitting packet sequence number
    0xB0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
#endif
    // congestion feedback type (inter arrival)
    0x02,
    // accumulated_number_of_lost_packets
    0x02, 0x03,
    // offset_time
    0x04, 0x05,
    // delta_time
    0x06, 0x07,
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFragementDataPacket(header, frames, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, ConstructFecPacket) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 0x01;
  header.packet_sequence_number = (GG_UINT64_C(0x123456789ABC));
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_FEC;
  header.fec_group = 1;

  QuicFecData fec_data;
  fec_data.fec_group = 1;
  fec_data.first_protected_packet_sequence_number =
      GG_UINT64_C(0x123456789ABB);
  fec_data.redundancy = "abcdefghijklmnop";

  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x01,
    // fec group
    0x01,
    // first protected packet
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };

  QuicPacket* data;
  EXPECT_TRUE(framer_.ConstructFecPacket(header, fec_data, &data));

  test::CompareCharArraysWithHexError("constructed packet",
                                      data->data(), data->length(),
                                      AsChars(packet), arraysize(packet));

  delete data;
}

TEST_F(QuicFramerTest, IncrementRetransmitCount) {
  QuicPacketHeader header;
  header.guid = GG_UINT64_C(0xFEDCBA9876543210);
  header.retransmission_count = 1;
  header.packet_sequence_number = GG_UINT64_C(0x123456789ABC);
  header.transmission_time = GG_UINT64_C(0xF0E1D2C3B4A59687);
  header.flags = PACKET_FLAGS_NONE;
  header.fec_group = 0;

  QuicStreamFrame stream_frame;
  stream_frame.stream_id = 0x01020304;
  stream_frame.fin = true;
  stream_frame.offset = GG_UINT64_C(0xBA98FEDC32107654);
  stream_frame.data = "hello world!";

  QuicFrame frame;
  frame.type = STREAM_FRAME;
  frame.stream_frame = &stream_frame;

  QuicFrames frames;
  frames.push_back(frame);

  QuicPacket *original;
  ASSERT_TRUE(framer_.ConstructFragementDataPacket(
      header, frames, &original));
  EXPECT_EQ(header.retransmission_count, framer_.GetRetransmitCount(original));

  header.retransmission_count = 2;
  QuicPacket *retransmitted;
  ASSERT_TRUE(framer_.ConstructFragementDataPacket(
      header, frames, &retransmitted));

  framer_.IncrementRetransmitCount(original);
  EXPECT_EQ(header.retransmission_count, framer_.GetRetransmitCount(original));

  test::CompareCharArraysWithHexError(
      "constructed packet", original->data(), original->length(),
      retransmitted->data(), retransmitted->length());
  delete original;
  delete retransmitted;
}

TEST_F(QuicFramerTest, EncryptPacket) {
  unsigned char packet[] = {
    // guid
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet id
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // retransmission count
    0x01,
    // transmission time
    0x87, 0x96, 0xA5, 0xB4,
    0xC3, 0xD2, 0xE1, 0xF0,
    // flags
    0x01,
    // fec group
    0x01,
    // first protected packet
    0xBB, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };

  QuicPacket raw(AsChars(packet), arraysize(packet), false);
  scoped_ptr<QuicEncryptedPacket> encrypted(framer_.EncryptPacket(raw));

  ASSERT_TRUE(encrypted.get() != NULL);
  EXPECT_TRUE(CheckEncryption(StringPiece(AsChars(packet), arraysize(packet))));
}

}  // namespace test

}  // namespace net
