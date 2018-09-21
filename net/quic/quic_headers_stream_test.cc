// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_headers_stream.h"

#include <string>

#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_utils.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_flags.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::ostream;
using std::string;
using std::vector;
using testing::ElementsAre;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;
using testing::WithArgs;
using testing::_;

namespace net {
namespace test {

class MockHpackDebugVisitor : public QuicHeadersStream::HpackDebugVisitor {
 public:
  explicit MockHpackDebugVisitor() : HpackDebugVisitor() {}

  MOCK_METHOD1(OnUseEntry, void(QuicTime::Delta elapsed));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockHpackDebugVisitor);
};

class QuicHeadersStreamPeer {
 public:
  static const SpdyFramer& GetSpdyFramer(QuicHeadersStream* stream) {
    return stream->spdy_framer_;
  }
};

namespace {

// TODO(ckrasic):  this workaround is due to absence of std::initializer_list
const bool kFins[] = {false, true};

class MockVisitor : public SpdyFramerVisitorInterface {
 public:
  MOCK_METHOD1(OnError, void(SpdyFramer* framer));
  MOCK_METHOD3(OnDataFrameHeader,
               void(SpdyStreamId stream_id, size_t length, bool fin));
  MOCK_METHOD3(OnStreamFrameData,
               void(SpdyStreamId stream_id, const char* data, size_t len));
  MOCK_METHOD1(OnStreamEnd, void(SpdyStreamId stream_id));
  MOCK_METHOD2(OnStreamPadding, void(SpdyStreamId stream_id, size_t len));
  MOCK_METHOD1(OnHeaderFrameStart,
               SpdyHeadersHandlerInterface*(SpdyStreamId stream_id));
  MOCK_METHOD2(OnHeaderFrameEnd, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD3(OnControlFrameHeaderData,
               bool(SpdyStreamId stream_id,
                    const char* header_data,
                    size_t len));
  MOCK_METHOD5(OnSynStream,
               void(SpdyStreamId stream_id,
                    SpdyStreamId associated_stream_id,
                    SpdyPriority priority,
                    bool fin,
                    bool unidirectional));
  MOCK_METHOD2(OnSynReply, void(SpdyStreamId stream_id, bool fin));
  MOCK_METHOD2(OnRstStream,
               void(SpdyStreamId stream_id, SpdyRstStreamStatus status));
  MOCK_METHOD1(OnSettings, void(bool clear_persisted));
  MOCK_METHOD3(OnSetting,
               void(SpdySettingsIds id, uint8_t flags, uint32_t value));
  MOCK_METHOD0(OnSettingsAck, void());
  MOCK_METHOD0(OnSettingsEnd, void());
  MOCK_METHOD2(OnPing, void(SpdyPingId unique_id, bool is_ack));
  MOCK_METHOD2(OnGoAway,
               void(SpdyStreamId last_accepted_stream_id,
                    SpdyGoAwayStatus status));
  MOCK_METHOD7(OnHeaders,
               void(SpdyStreamId stream_id,
                    bool has_priority,
                    int weight,
                    SpdyStreamId parent_stream_id,
                    bool exclusive,
                    bool fin,
                    bool end));
  MOCK_METHOD2(OnWindowUpdate,
               void(SpdyStreamId stream_id, int delta_window_size));
  MOCK_METHOD1(OnBlocked, void(SpdyStreamId stream_id));
  MOCK_METHOD3(OnPushPromise,
               void(SpdyStreamId stream_id,
                    SpdyStreamId promised_stream_id,
                    bool end));
  MOCK_METHOD2(OnContinuation, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD4(OnPriority,
               void(SpdyStreamId stream_id,
                    SpdyStreamId parent_id,
                    int weight,
                    bool exclusive));
  MOCK_METHOD3(OnAltSvc,
               void(SpdyStreamId stream_id,
                    StringPiece origin,
                    const SpdyAltSvcWireFormat::AlternativeServiceVector&
                        altsvc_vector));
  MOCK_METHOD2(OnUnknownFrame, bool(SpdyStreamId stream_id, int frame_type));
};

// Run all tests with each version, perspective (client or server),
// and relevant flag options (false or true)
struct TestParams {
  TestParams(QuicVersion version, Perspective perspective)
      : version(version), perspective(perspective) {}

  friend ostream& operator<<(ostream& os, const TestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version);
    os << ", perspective: " << p.perspective << " }";
    return os;
  }

  QuicVersion version;
  Perspective perspective;
};

// Constructs various test permutations.
vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  QuicVersionVector all_supported_versions = QuicSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(TestParams(version, Perspective::IS_CLIENT));
    params.push_back(TestParams(version, Perspective::IS_SERVER));
  }
  FLAGS_quic_supports_push_promise = true;
  return params;
}

class QuicHeadersStreamTest : public ::testing::TestWithParam<TestParams> {
 public:
  QuicHeadersStreamTest()
      : connection_(new StrictMock<MockQuicConnection>(&helper_,
                                                       &alarm_factory_,
                                                       perspective(),
                                                       GetVersion())),
        session_(connection_),
        headers_stream_(QuicSpdySessionPeer::GetHeadersStream(&session_)),
        body_("hello world"),
        hpack_encoder_visitor_(new StrictMock<MockHpackDebugVisitor>),
        hpack_decoder_visitor_(new StrictMock<MockHpackDebugVisitor>),
        stream_frame_(kHeadersStreamId, /*fin=*/false, /*offset=*/0, ""),
        next_promised_stream_id_(2) {
    FLAGS_quic_always_log_bugs_for_tests = true;
    headers_[":version"] = "HTTP/1.1";
    headers_[":status"] = "200 Ok";
    headers_["content-length"] = "11";
    framer_ = std::unique_ptr<SpdyFramer>(new SpdyFramer(HTTP2));
    framer_->set_visitor(&visitor_);
    EXPECT_EQ(version(), session_.connection()->version());
    EXPECT_TRUE(headers_stream_ != nullptr);
    VLOG(1) << GetParam();
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  }

  QuicConsumedData SaveIov(const QuicIOVector& data) {
    const iovec* iov = data.iov;
    int count = data.iov_count;
    for (int i = 0; i < count; ++i) {
      saved_data_.append(static_cast<char*>(iov[i].iov_base), iov[i].iov_len);
    }
    return QuicConsumedData(saved_data_.length(), false);
  }

  bool SaveHeaderData(const char* data, int len) {
    saved_header_data_.append(data, len);
    return true;
  }

  void SaveHeaderDataStringPiece(StringPiece data) {
    saved_header_data_.append(data.data(), data.length());
  }

  void SavePromiseHeaderList(QuicStreamId /* stream_id */,
                             QuicStreamId /* promised_stream_id */,
                             size_t size,
                             const QuicHeaderList& header_list) {
    SaveToHandler(size, header_list);
  }

  void SaveHeaderList(QuicStreamId /* stream_id */,
                      bool /* fin */,
                      size_t size,
                      const QuicHeaderList& header_list) {
    SaveToHandler(size, header_list);
  }

  void SaveToHandler(size_t size, const QuicHeaderList& header_list) {
    headers_handler_.reset(new TestHeadersHandler);
    headers_handler_->OnHeaderBlockStart();
    for (const auto& p : header_list) {
      headers_handler_->OnHeader(p.first, p.second);
    }
    headers_handler_->OnHeaderBlockEnd(size);
  }

  void WriteHeadersAndExpectSynStream(QuicStreamId stream_id,
                                      bool fin,
                                      SpdyPriority priority) {
    WriteHeadersAndCheckData(stream_id, fin, priority, SYN_STREAM);
  }

  void WriteHeadersAndExpectSynReply(QuicStreamId stream_id, bool fin) {
    WriteHeadersAndCheckData(stream_id, fin, 0, SYN_REPLY);
  }

  void WriteHeadersAndCheckData(QuicStreamId stream_id,
                                bool fin,
                                SpdyPriority priority,
                                SpdyFrameType type) {
    // Write the headers and capture the outgoing data
    EXPECT_CALL(session_, WritevData(headers_stream_, kHeadersStreamId, _, _,
                                     false, nullptr))
        .WillOnce(WithArgs<2>(Invoke(this, &QuicHeadersStreamTest::SaveIov)));
    headers_stream_->WriteHeaders(stream_id, headers_.Clone(), fin, priority,
                                  nullptr);

    // Parse the outgoing data and check that it matches was was written.
    if (type == SYN_STREAM) {
      EXPECT_CALL(visitor_,
                  OnHeaders(stream_id, kHasPriority,
                            Spdy3PriorityToHttp2Weight(priority),
                            /*parent_stream_id=*/0,
                            /*exclusive=*/false, fin, kFrameComplete));
    } else {
      EXPECT_CALL(visitor_,
                  OnHeaders(stream_id, !kHasPriority,
                            /*priority=*/0,
                            /*parent_stream_id=*/0,
                            /*exclusive=*/false, fin, kFrameComplete));
    }
    headers_handler_.reset(new TestHeadersHandler);
    EXPECT_CALL(visitor_, OnHeaderFrameStart(stream_id))
        .WillOnce(Return(headers_handler_.get()));
    EXPECT_CALL(visitor_, OnHeaderFrameEnd(stream_id, true)).Times(1);
    if (fin) {
      EXPECT_CALL(visitor_, OnStreamEnd(stream_id));
    }
    framer_->ProcessInput(saved_data_.data(), saved_data_.length());
    EXPECT_FALSE(framer_->HasError())
        << SpdyFramer::ErrorCodeToString(framer_->error_code());

    CheckHeaders();
    saved_data_.clear();
  }

  void CheckHeaders() {
    EXPECT_EQ(headers_, headers_handler_->decoded_block());
    headers_handler_.reset();
  }

  Perspective perspective() { return GetParam().perspective; }

  QuicVersion version() { return GetParam().version; }

  QuicVersionVector GetVersion() {
    QuicVersionVector versions;
    versions.push_back(version());
    return versions;
  }

  void TearDownLocalConnectionState() {
    QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  }

  QuicStreamId NextPromisedStreamId() { return next_promised_stream_id_ += 2; }

  static const bool kFrameComplete = true;
  static const bool kHasPriority = true;

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  StrictMock<MockQuicSpdySession> session_;
  QuicHeadersStream* headers_stream_;
  SpdyHeaderBlock headers_;
  std::unique_ptr<TestHeadersHandler> headers_handler_;
  string body_;
  string saved_data_;
  string saved_header_data_;
  std::unique_ptr<SpdyFramer> framer_;
  StrictMock<MockVisitor> visitor_;
  std::unique_ptr<StrictMock<MockHpackDebugVisitor>> hpack_encoder_visitor_;
  std::unique_ptr<StrictMock<MockHpackDebugVisitor>> hpack_decoder_visitor_;
  QuicStreamFrame stream_frame_;
  QuicStreamId next_promised_stream_id_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicHeadersStreamTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicHeadersStreamTest, StreamId) {
  EXPECT_EQ(3u, headers_stream_->id());
}

TEST_P(QuicHeadersStreamTest, WriteHeaders) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : kFins) {
      if (perspective() == Perspective::IS_SERVER) {
        WriteHeadersAndExpectSynReply(stream_id, fin);
      } else {
        for (SpdyPriority priority = 0; priority < 7; ++priority) {
          // TODO(rch): implement priorities correctly.
          WriteHeadersAndExpectSynStream(stream_id, fin, 0);
        }
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, WritePushPromises) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    QuicStreamId promised_stream_id = NextPromisedStreamId();
    if (perspective() == Perspective::IS_SERVER) {
      // Write the headers and capture the outgoing data
      EXPECT_CALL(session_, WritevData(headers_stream_, kHeadersStreamId, _, _,
                                       false, nullptr))
          .WillOnce(WithArgs<2>(Invoke(this, &QuicHeadersStreamTest::SaveIov)));
      headers_stream_->WritePushPromise(stream_id, promised_stream_id,
                                        headers_.Clone(), nullptr);

      // Parse the outgoing data and check that it matches was was written.
      EXPECT_CALL(visitor_,
                  OnPushPromise(stream_id, promised_stream_id, kFrameComplete));
      headers_handler_.reset(new TestHeadersHandler);
      EXPECT_CALL(visitor_, OnHeaderFrameStart(stream_id))
          .WillOnce(Return(headers_handler_.get()));
      EXPECT_CALL(visitor_, OnHeaderFrameEnd(stream_id, true)).Times(1);
      framer_->ProcessInput(saved_data_.data(), saved_data_.length());
      EXPECT_FALSE(framer_->HasError())
          << SpdyFramer::ErrorCodeToString(framer_->error_code());
      CheckHeaders();
      saved_data_.clear();
    } else {
      EXPECT_DFATAL(
          headers_stream_->WritePushPromise(stream_id, promised_stream_id,
                                            headers_.Clone(), nullptr),
          "Client shouldn't send PUSH_PROMISE");
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessRawData) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
        } else {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_,
                    OnStreamHeaderList(stream_id, fin, frame.size(), _))
            .WillOnce(Invoke(this, &QuicHeadersStreamTest::SaveHeaderList));
        stream_frame_.data_buffer = frame.data();
        stream_frame_.data_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessPushPromise) {
  if (perspective() == Perspective::IS_SERVER)
    return;
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    QuicStreamId promised_stream_id = NextPromisedStreamId();
    SpdyPushPromiseIR push_promise(stream_id, promised_stream_id,
                                   headers_.Clone());
    SpdySerializedFrame frame(framer_->SerializeFrame(push_promise));
    if (perspective() == Perspective::IS_SERVER) {
      EXPECT_CALL(*connection_,
                  CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                  "PUSH_PROMISE not supported.", _))
          .WillRepeatedly(InvokeWithoutArgs(
              this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
    } else {
      EXPECT_CALL(session_, OnPromiseHeaderList(stream_id, promised_stream_id,
                                                frame.size(), _))
          .WillOnce(
              Invoke(this, &QuicHeadersStreamTest::SavePromiseHeaderList));
    }
    stream_frame_.data_buffer = frame.data();
    stream_frame_.data_length = frame.size();
    headers_stream_->OnStreamFrame(stream_frame_);
    if (perspective() == Perspective::IS_CLIENT) {
      stream_frame_.offset += frame.size();
      CheckHeaders();
    }
  }
}

TEST_P(QuicHeadersStreamTest, EmptyHeaderHOLBlockedTime) {
  if (!FLAGS_quic_measure_headers_hol_blocking_time) {
    return;
  }
  EXPECT_CALL(session_, OnHeadersHeadOfLineBlocking(_)).Times(0);
  testing::InSequence seq;
  bool fin = true;
  for (int stream_num = 0; stream_num < 10; stream_num++) {
    QuicStreamId stream_id = QuicClientDataStreamId(stream_num);
    // Replace with "WriteHeadersAndSaveData"
    SpdySerializedFrame frame;
    if (perspective() == Perspective::IS_SERVER) {
      SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
      headers_frame.set_fin(fin);
      headers_frame.set_has_priority(true);
      headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
      frame = framer_->SerializeFrame(headers_frame);
      EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
    } else {
      SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
      headers_frame.set_fin(fin);
      frame = framer_->SerializeFrame(headers_frame);
    }
    EXPECT_CALL(session_, OnStreamHeaderList(stream_id, fin, frame.size(), _))
        .Times(1);
    stream_frame_.data_buffer = frame.data();
    stream_frame_.data_length = frame.size();
    headers_stream_->OnStreamFrame(stream_frame_);
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
    stream_frame_.offset += frame.size();
  }
}

TEST_P(QuicHeadersStreamTest, NonEmptyHeaderHOLBlockedTime) {
  if (!FLAGS_quic_measure_headers_hol_blocking_time) {
    return;
  }
  QuicStreamId stream_id;
  bool fin = true;
  QuicStreamFrame stream_frames[10];
  SpdySerializedFrame frames[10];
  // First create all the frames in order
  {
    InSequence seq;
    for (int stream_num = 0; stream_num < 10; ++stream_num) {
      stream_id = QuicClientDataStreamId(stream_num);
      if (perspective() == Perspective::IS_SERVER) {
        SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
        headers_frame.set_fin(fin);
        headers_frame.set_has_priority(true);
        headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
        frames[stream_num] = framer_->SerializeFrame(headers_frame);
        EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0)).Times(1);
      } else {
        SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
        headers_frame.set_fin(fin);
        frames[stream_num] = framer_->SerializeFrame(headers_frame);
      }
      stream_frames[stream_num].stream_id = stream_frame_.stream_id;
      stream_frames[stream_num].offset = stream_frame_.offset;
      stream_frames[stream_num].data_buffer = frames[stream_num].data();
      stream_frames[stream_num].data_length = frames[stream_num].size();
      DVLOG(1) << "make frame for stream " << stream_num << " offset "
               << stream_frames[stream_num].offset;
      stream_frame_.offset += frames[stream_num].size();
      EXPECT_CALL(session_, OnStreamHeaderList(stream_id, fin, _, _)).Times(1);
    }
  }

  // Actually writing the frames in reverse order will cause HOL blocking.
  EXPECT_CALL(session_, OnHeadersHeadOfLineBlocking(_)).Times(9);

  for (int stream_num = 9; stream_num >= 0; --stream_num) {
    DVLOG(1) << "OnStreamFrame for stream " << stream_num << " offset "
             << stream_frames[stream_num].offset;
    headers_stream_->OnStreamFrame(stream_frames[stream_num]);
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  }
}

TEST_P(QuicHeadersStreamTest, ProcessLargeRawData) {
  // We want to create a frame that is more than the SPDY Framer's max control
  // frame size, which is 16K, but less than the HPACK decoders max decode
  // buffer size, which is 32K.
  headers_["key0"] = string(1 << 13, '.');
  headers_["key1"] = string(1 << 13, '.');
  headers_["key2"] = string(1 << 13, '.');
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
        } else {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_,
                    OnStreamHeaderList(stream_id, fin, frame.size(), _))
            .WillOnce(Invoke(this, &QuicHeadersStreamTest::SaveHeaderList));
        stream_frame_.data_buffer = frame.data();
        stream_frame_.data_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessBadData) {
  const char kBadData[] = "blah blah blah";
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA, _, _))
      .Times(::testing::AnyNumber());
  stream_frame_.data_buffer = kBadData;
  stream_frame_.data_length = strlen(kBadData);
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyDataFrame) {
  SpdyDataIR data(2, "");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY DATA frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyRstStreamFrame) {
  SpdyRstStreamIR data(2, RST_STREAM_PROTOCOL_ERROR);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY RST_STREAM frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdySettingsFrame) {
  FLAGS_quic_respect_http2_settings_frame = false;
  SpdySettingsIR data;
  data.AddSetting(SETTINGS_HEADER_TABLE_SIZE, true, true, 0);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY SETTINGS frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, RespectHttp2SettingsFrameSupportedFields) {
  FLAGS_quic_respect_http2_settings_frame = true;
  const uint32_t kTestHeaderTableSize = 1000;
  SpdySettingsIR data;
  // Respect supported settings frames SETTINGS_HEADER_TABLE_SIZE.
  data.AddSetting(SETTINGS_HEADER_TABLE_SIZE, true, true, kTestHeaderTableSize);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
  EXPECT_EQ(kTestHeaderTableSize,
            QuicHeadersStreamPeer::GetSpdyFramer(headers_stream_)
                .header_encoder_table_size());
}

TEST_P(QuicHeadersStreamTest, RespectHttp2SettingsFrameUnsupportedFields) {
  FLAGS_quic_respect_http2_settings_frame = true;
  SpdySettingsIR data;
  // Does not support SETTINGS_MAX_HEADER_LIST_SIZE,
  // SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
  // SETTINGS_ENABLE_PUSH and SETTINGS_MAX_FRAME_SIZE.
  data.AddSetting(SETTINGS_MAX_HEADER_LIST_SIZE, true, true, 2000);
  data.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, true, true, 100);
  data.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, true, true, 100);
  data.AddSetting(SETTINGS_ENABLE_PUSH, true, true, 1);
  data.AddSetting(SETTINGS_MAX_FRAME_SIZE, true, true, 1250);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                      "Unsupported field of HTTP/2 SETTINGS frame: " +
                          base::IntToString(SETTINGS_MAX_HEADER_LIST_SIZE),
                      _));
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                      "Unsupported field of HTTP/2 SETTINGS frame: " +
                          base::IntToString(SETTINGS_MAX_CONCURRENT_STREAMS),
                      _));
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                      "Unsupported field of HTTP/2 SETTINGS frame: " +
                          base::IntToString(SETTINGS_INITIAL_WINDOW_SIZE),
                      _));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "Unsupported field of HTTP/2 SETTINGS frame: " +
                                  base::IntToString(SETTINGS_ENABLE_PUSH),
                              _));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "Unsupported field of HTTP/2 SETTINGS frame: " +
                                  base::IntToString(SETTINGS_MAX_FRAME_SIZE),
                              _));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyPingFrame) {
  SpdyPingIR data(1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY PING frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyGoAwayFrame) {
  SpdyGoAwayIR data(1, GOAWAY_PROTOCOL_ERROR, "go away");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY GOAWAY frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyWindowUpdateFrame) {
  SpdyWindowUpdateIR data(1, 1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY WINDOW_UPDATE frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, NoConnectionLevelFlowControl) {
  EXPECT_FALSE(ReliableQuicStreamPeer::StreamContributesToConnectionFlowControl(
      headers_stream_));
}

TEST_P(QuicHeadersStreamTest, HpackDecoderDebugVisitor) {
  if (FLAGS_use_nested_spdy_framer_decoder)
    return;

  StrictMock<MockHpackDebugVisitor>* hpack_decoder_visitor =
      hpack_decoder_visitor_.get();
  headers_stream_->SetHpackDecoderDebugVisitor(
      std::move(hpack_decoder_visitor_));

  // Create some headers we expect to generate entries in HPACK's
  // dynamic table, in addition to content-length.
  headers_["key0"] = string(1 << 1, '.');
  headers_["key1"] = string(1 << 2, '.');
  headers_["key2"] = string(1 << 3, '.');
  {
    testing::InSequence seq;
    // Number of indexed representations generated in headers below.
    for (int i = 1; i < 28; i++) {
      EXPECT_CALL(*hpack_decoder_visitor,
                  OnUseEntry(QuicTime::Delta::FromMilliseconds(i)))
          .Times(4);
    }
  }
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
        } else {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_,
                    OnStreamHeaderList(stream_id, fin, frame.size(), _))
            .WillOnce(Invoke(this, &QuicHeadersStreamTest::SaveHeaderList));
        stream_frame_.data_buffer = frame.data();
        stream_frame_.data_length = frame.size();
        connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, HpackEncoderDebugVisitor) {
  StrictMock<MockHpackDebugVisitor>* hpack_encoder_visitor =
      hpack_encoder_visitor_.get();
  headers_stream_->SetHpackEncoderDebugVisitor(
      std::move(hpack_encoder_visitor_));

  if (perspective() == Perspective::IS_SERVER) {
    testing::InSequence seq;
    for (int i = 1; i < 4; i++) {
      EXPECT_CALL(*hpack_encoder_visitor,
                  OnUseEntry(QuicTime::Delta::FromMilliseconds(i)));
    }
  } else {
    testing::InSequence seq;
    for (int i = 1; i < 28; i++) {
      EXPECT_CALL(*hpack_encoder_visitor,
                  OnUseEntry(QuicTime::Delta::FromMilliseconds(i)));
    }
  }
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      if (perspective() == Perspective::IS_SERVER) {
        WriteHeadersAndExpectSynReply(stream_id, fin);
        connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
      } else {
        for (SpdyPriority priority = 0; priority < 7; ++priority) {
          // TODO(rch): implement priorities correctly.
          WriteHeadersAndExpectSynStream(stream_id, fin, 0);
          connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
        }
      }
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace net
