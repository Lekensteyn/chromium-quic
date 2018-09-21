// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_data_stream.h"

#include "net/quic/quic_ack_notifier.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_write_blocked_list.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"

using base::StringPiece;
using std::min;
using testing::_;
using testing::AnyNumber;
using testing::InSequence;
using testing::Return;
using testing::SaveArg;
using testing::StrictMock;

namespace net {
namespace test {
namespace {

const QuicConnectionId kStreamId = 3;
const bool kIsServer = true;
const bool kShouldProcessData = true;

class TestStream : public QuicDataStream {
 public:
  TestStream(QuicStreamId id,
             QuicSession* session,
             bool should_process_data)
      : QuicDataStream(id, session),
        should_process_data_(should_process_data) {}

  virtual uint32 ProcessData(const char* data, uint32 data_len) OVERRIDE {
    EXPECT_NE(0u, data_len);
    DVLOG(1) << "ProcessData data_len: " << data_len;
    data_ += string(data, data_len);
    return should_process_data_ ? data_len : 0;
  }

  using ReliableQuicStream::WriteOrBufferData;
  using ReliableQuicStream::CloseReadSide;
  using ReliableQuicStream::CloseWriteSide;

  const string& data() const { return data_; }

 private:
  bool should_process_data_;
  string data_;
};

class QuicDataStreamTest : public ::testing::TestWithParam<QuicVersion> {
 public:
  QuicDataStreamTest() {
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "https";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
  }

  void Initialize(bool stream_should_process_data) {
    connection_ = new testing::StrictMock<MockConnection>(
        kIsServer, SupportedVersions(GetParam()));
    session_.reset(new testing::StrictMock<MockSession>(connection_));
    stream_.reset(new TestStream(kStreamId, session_.get(),
                                 stream_should_process_data));
    stream2_.reset(new TestStream(kStreamId + 2, session_.get(),
                                 stream_should_process_data));
    write_blocked_list_ =
        QuicSessionPeer::GetWriteblockedStreams(session_.get());
  }

 protected:
  MockConnection* connection_;
  scoped_ptr<MockSession> session_;
  scoped_ptr<TestStream> stream_;
  scoped_ptr<TestStream> stream2_;
  SpdyHeaderBlock headers_;
  QuicWriteBlockedList* write_blocked_list_;
};

INSTANTIATE_TEST_CASE_P(Tests, QuicDataStreamTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicDataStreamTest, ProcessHeaders) {
  Initialize(kShouldProcessData);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  stream_->OnStreamHeadersPriority(QuicUtils::HighestPriority());
  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());
  EXPECT_EQ(QuicUtils::HighestPriority(), stream_->EffectivePriority());
  EXPECT_EQ(headers, stream_->data());
  EXPECT_FALSE(stream_->IsDoneReading());
}

TEST_P(QuicDataStreamTest, ProcessHeadersAndBody) {
  Initialize(kShouldProcessData);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";

  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());
  QuicStreamFrame frame(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame);

  EXPECT_EQ(headers + body, stream_->data());
}

TEST_P(QuicDataStreamTest, ProcessHeadersAndBodyFragments) {
  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";

  for (size_t fragment_size = 1; fragment_size < body.size();
       ++fragment_size) {
    Initialize(kShouldProcessData);
    for (size_t offset = 0; offset < headers.size();
         offset += fragment_size) {
      size_t remaining_data = headers.size() - offset;
      StringPiece fragment(headers.data() + offset,
                           min(fragment_size, remaining_data));
      stream_->OnStreamHeaders(fragment);
    }
    stream_->OnStreamHeadersComplete(false, headers.size());
    for (size_t offset = 0; offset < body.size(); offset += fragment_size) {
      size_t remaining_data = body.size() - offset;
      StringPiece fragment(body.data() + offset,
                           min(fragment_size, remaining_data));
      QuicStreamFrame frame(kStreamId, false, offset, MakeIOVector(fragment));
      stream_->OnStreamFrame(frame);
    }
    ASSERT_EQ(headers + body,
              stream_->data()) << "fragment_size: " << fragment_size;
  }
}

TEST_P(QuicDataStreamTest, ProcessHeadersAndBodyFragmentsSplit) {
  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";

  for (size_t split_point = 1; split_point < body.size() - 1; ++split_point) {
    Initialize(kShouldProcessData);
    StringPiece headers1(headers.data(), split_point);
    stream_->OnStreamHeaders(headers1);

    StringPiece headers2(headers.data() + split_point,
                         headers.size() - split_point);
    stream_->OnStreamHeaders(headers2);
    stream_->OnStreamHeadersComplete(false, headers.size());

    StringPiece fragment1(body.data(), split_point);
    QuicStreamFrame frame1(kStreamId, false, 0, MakeIOVector(fragment1));
    stream_->OnStreamFrame(frame1);

    StringPiece fragment2(body.data() + split_point,
                          body.size() - split_point);
    QuicStreamFrame frame2(
        kStreamId, false, split_point, MakeIOVector(fragment2));
    stream_->OnStreamFrame(frame2);

    ASSERT_EQ(headers + body,
              stream_->data()) << "split_point: " << split_point;
  }
}

TEST_P(QuicDataStreamTest, ProcessHeadersAndBodyReadv) {
  Initialize(!kShouldProcessData);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";

  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());
  QuicStreamFrame frame(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame);

  char buffer[2048];
  ASSERT_LT(headers.length() + body.length(), arraysize(buffer));
  struct iovec vec;
  vec.iov_base = buffer;
  vec.iov_len = arraysize(buffer);

  size_t bytes_read = stream_->Readv(&vec, 1);
  EXPECT_EQ(headers.length(), bytes_read);
  EXPECT_EQ(headers, string(buffer, bytes_read));

  bytes_read = stream_->Readv(&vec, 1);
  EXPECT_EQ(body.length(), bytes_read);
  EXPECT_EQ(body, string(buffer, bytes_read));
}

TEST_P(QuicDataStreamTest, ProcessHeadersAndBodyIncrementalReadv) {
  Initialize(!kShouldProcessData);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";
  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());
  QuicStreamFrame frame(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame);


  char buffer[1];
  struct iovec vec;
  vec.iov_base = buffer;
  vec.iov_len = arraysize(buffer);

  string data = headers + body;
  for (size_t i = 0; i < data.length(); ++i) {
    size_t bytes_read = stream_->Readv(&vec, 1);
    ASSERT_EQ(1u, bytes_read);
    EXPECT_EQ(data.data()[i], buffer[0]);
  }
}

TEST_P(QuicDataStreamTest, ProcessHeadersUsingReadvWithMultipleIovecs) {
  Initialize(!kShouldProcessData);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body = "this is the body";
  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());
  QuicStreamFrame frame(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame);


  char buffer1[1];
  char buffer2[1];
  struct iovec vec[2];
  vec[0].iov_base = buffer1;
  vec[0].iov_len = arraysize(buffer1);
  vec[1].iov_base = buffer2;
  vec[1].iov_len = arraysize(buffer2);
  string data = headers + body;
  for (size_t i = 0; i < data.length(); i += 2) {
    size_t bytes_read = stream_->Readv(vec, 2);
    ASSERT_EQ(2u, bytes_read) << i;
    ASSERT_EQ(data.data()[i], buffer1[0]) << i;
    ASSERT_EQ(data.data()[i + 1], buffer2[0]) << i;
  }
}

TEST_P(QuicDataStreamTest, StreamFlowControlBlocked) {
  // Tests that we send a BLOCKED frame to the peer when we attempt to write,
  // but are flow control blocked.
  if (GetParam() < QUIC_VERSION_17) {
    return;
  }
  ValueRestore<bool> old_flag(&FLAGS_enable_quic_stream_flow_control, true);

  Initialize(kShouldProcessData);

  // Set a small flow control limit.
  const uint64 kWindow = 36;
  ReliableQuicStreamPeer::SetFlowControlSendOffset(stream_.get(), kWindow);
  EXPECT_EQ(kWindow, ReliableQuicStreamPeer::SendWindowSize(stream_.get()));

  // Try to send more data than the flow control limit allows.
  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body;
  const uint64 kOverflow = 15;
  GenerateBody(&body, kWindow + kOverflow);

  EXPECT_CALL(*connection_, SendBlocked(kStreamId));
  EXPECT_CALL(*session_, WritevData(kStreamId, _, _, _, _)).WillOnce(
      Return(QuicConsumedData(kWindow, true)));
  stream_->WriteOrBufferData(body, false, NULL);

  // Should have sent as much as possible, resulting in no send window left.
  EXPECT_EQ(0u, ReliableQuicStreamPeer::SendWindowSize(stream_.get()));

  // And we should have queued the overflowed data.
  EXPECT_EQ(kOverflow,
            ReliableQuicStreamPeer::SizeOfQueuedData(stream_.get()));
}

TEST_P(QuicDataStreamTest, StreamFlowControlNoWindowUpdateIfNotConsumed) {
  // The flow control receive window decreases whenever we add new bytes to the
  // sequencer, whether they are consumed immediately or buffered. However we
  // only send WINDOW_UPDATE frames based on increasing number of bytes
  // consumed.
  if (GetParam() < QUIC_VERSION_17) {
    return;
  }
  ValueRestore<bool> old_flag(&FLAGS_enable_quic_stream_flow_control, true);

  // Don't process data - it will be buffered instead.
  Initialize(!kShouldProcessData);

  // Expect no WINDOW_UPDATE frames to be sent.
  EXPECT_CALL(*connection_, SendWindowUpdate(_, _)).Times(0);

  // Set a small flow control limit.
  const uint64 kWindow = 36;
  ReliableQuicStreamPeer::SetFlowControlReceiveOffset(stream_.get(),
                                                      kWindow);
  ReliableQuicStreamPeer::SetFlowControlMaxReceiveWindow(stream_.get(),
                                                         kWindow);
  EXPECT_EQ(kWindow, ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));

  // Stream receives enough data to fill a fraction of the receive window.
  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body;
  GenerateBody(&body, kWindow / 3);
  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());

  QuicStreamFrame frame1(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame1);
  EXPECT_EQ(kWindow - (kWindow / 3),
            ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));

  // Now receive another frame which results in the receive window being over
  // half full. This should all be buffered, decreasing the receive window but
  // not sending WINDOW_UPDATE.
  QuicStreamFrame frame2(kStreamId, false, kWindow / 3, MakeIOVector(body));
  stream_->OnStreamFrame(frame2);
  EXPECT_EQ(kWindow - (2 * kWindow / 3),
            ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));
}

TEST_P(QuicDataStreamTest, StreamFlowControlWindowUpdate) {
  // Tests that on receipt of data, the stream updates its receive window offset
  // appropriately, and sends WINDOW_UPDATE frames when its receive window drops
  // too low.
  if (GetParam() < QUIC_VERSION_17) {
    return;
  }
  ValueRestore<bool> old_flag(&FLAGS_enable_quic_stream_flow_control, true);

  Initialize(kShouldProcessData);

  // Set a small flow control limit.
  const uint64 kWindow = 36;
  ReliableQuicStreamPeer::SetFlowControlReceiveOffset(stream_.get(),
                                                      kWindow);
  ReliableQuicStreamPeer::SetFlowControlMaxReceiveWindow(stream_.get(),
                                                         kWindow);
  EXPECT_EQ(kWindow, ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));

  // Stream receives enough data to fill a fraction of the receive window.
  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body;
  GenerateBody(&body, kWindow / 3);
  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());

  QuicStreamFrame frame1(kStreamId, false, 0, MakeIOVector(body));
  stream_->OnStreamFrame(frame1);
  EXPECT_EQ(kWindow - (kWindow / 3),
            ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));

  // Now receive another frame which results in the receive window being over
  // half full.  This will trigger the stream to increase its receive window
  // offset and send a WINDOW_UPDATE. The result will be again an available
  // window of kWindow bytes.
  QuicStreamFrame frame2(kStreamId, false, kWindow / 3, MakeIOVector(body));
  EXPECT_CALL(
      *connection_,
      SendWindowUpdate(
          kStreamId,
          ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()) + kWindow));
  stream_->OnStreamFrame(frame2);
  EXPECT_EQ(kWindow,
            ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));
}

TEST_P(QuicDataStreamTest, StreamFlowControlViolation) {
  // Tests that on if the peer sends too much data (i.e. violates the flow
  // control protocol), then we terminate the connection.
  if (GetParam() < QUIC_VERSION_17) {
    return;
  }
  ValueRestore<bool> old_flag(&FLAGS_enable_quic_stream_flow_control, true);

  // Stream should not process data, so that data gets buffered in the
  // sequencer, triggering flow control limits.
  Initialize(!kShouldProcessData);

  // Set a small flow control limit.
  const uint64 kWindow = 50;
  ReliableQuicStreamPeer::SetFlowControlReceiveOffset(stream_.get(),
                                                      kWindow);

  string headers = SpdyUtils::SerializeUncompressedHeaders(headers_);
  string body;
  GenerateBody(&body, kWindow + 1);

  stream_->OnStreamHeaders(headers);
  EXPECT_EQ(headers, stream_->data());
  stream_->OnStreamHeadersComplete(false, headers.size());

  // Receive data to overflow the window, violating flow control.
  QuicStreamFrame frame(kStreamId, false, 0, MakeIOVector(body));
  EXPECT_CALL(*connection_, SendConnectionClose(QUIC_FLOW_CONTROL_ERROR));
  EXPECT_DFATAL(stream_->OnStreamFrame(frame),
                "Server: Flow control violation on stream: 3, our receive "
                "offset is: 50, we have consumed: 0, we have buffered: 51, "
                "total: 51");
}

TEST_P(QuicDataStreamTest, StreamFlowControlFinNotBlocked) {
  // An attempt to write a FIN with no data should not be flow control blocked,
  // even if the send window is 0.
  if (GetParam() < QUIC_VERSION_17) {
    return;
  }
  ValueRestore<bool> old_flag(&FLAGS_enable_quic_stream_flow_control, true);

  Initialize(kShouldProcessData);

  // Set a flow control limit of zero.
  ReliableQuicStreamPeer::SetFlowControlReceiveOffset(stream_.get(), 0);
  EXPECT_EQ(0u, ReliableQuicStreamPeer::ReceiveWindowSize(stream_.get()));

  // Send a frame with a FIN but no data. This should not be blocked.
  string body = "";
  bool fin = true;

  EXPECT_CALL(*connection_, SendBlocked(kStreamId)).Times(0);
  EXPECT_CALL(*session_, WritevData(kStreamId, _, _, _, _)).WillOnce(
      Return(QuicConsumedData(0, fin)));

  stream_->WriteOrBufferData(body, fin, NULL);
}

}  // namespace
}  // namespace test
}  // namespace net
