// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_http_stream.h"

#include <vector>

#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_response_headers.h"
#include "net/quic/congestion_control/receive_algorithm_interface.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_client_session.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_connection_helper.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/test_task_runner.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;

namespace net {
namespace test {
namespace {

const char kUploadData[] = "hello world!";

class TestQuicConnection : public QuicConnection {
 public:
  TestQuicConnection(QuicGuid guid,
                     IPEndPoint address,
                     QuicConnectionHelper* helper)
      : QuicConnection(guid, address, helper) {
  }

  void SetSendAlgorithm(SendAlgorithmInterface* send_algorithm) {
    QuicConnectionPeer::SetSendAlgorithm(this, send_algorithm);
  }

  void SetReceiveAlgorithm(ReceiveAlgorithmInterface* receive_algorithm) {
    QuicConnectionPeer::SetReceiveAlgorithm(this, receive_algorithm);
  }
};

class TestReceiveAlgorithm : public ReceiveAlgorithmInterface {
 public:
  explicit TestReceiveAlgorithm(QuicCongestionFeedbackFrame* feedback)
      : feedback_(feedback) {
  }

  bool GenerateCongestionFeedback(
      QuicCongestionFeedbackFrame* congestion_feedback) {
    if (feedback_ == NULL) {
      return false;
    }
    *congestion_feedback = *feedback_;
    return true;
  }

  MOCK_METHOD4(RecordIncomingPacket,
               void(QuicByteCount, QuicPacketSequenceNumber, QuicTime, bool));

 private:
  MockClock clock_;
  QuicCongestionFeedbackFrame* feedback_;

  DISALLOW_COPY_AND_ASSIGN(TestReceiveAlgorithm);
};

// Subclass of QuicHttpStream that closes itself when the first piece of data
// is received.
class AutoClosingStream : public QuicHttpStream {
 public:
  AutoClosingStream(QuicReliableClientStream* stream, bool use_spdy)
      : QuicHttpStream(stream, use_spdy) {
  }

  virtual int OnDataReceived(const char* data, int length) OVERRIDE {
    Close(false);
    return OK;
  }
};

}  // namespace

class QuicHttpStreamTest : public ::testing::TestWithParam<bool> {
 protected:
  const static bool kFin = true;
  // Holds a packet to be written to the wire, and the IO mode that should
  // be used by the mock socket when performing the write.
  struct PacketToWrite {
    PacketToWrite(IoMode mode, QuicEncryptedPacket* packet)
        : mode(mode),
          packet(packet) {
    }
    IoMode mode;
    QuicEncryptedPacket* packet;
  };

  QuicHttpStreamTest()
      : net_log_(BoundNetLog()),
        use_closing_stream_(false),
        read_buffer_(new IOBufferWithSize(4096)),
        guid_(2),
        framer_(QuicDecrypter::Create(kNULL), QuicEncrypter::Create(kNULL)),
        creator_(guid_, &framer_) {
    IPAddressNumber ip;
    CHECK(ParseIPLiteralToNumber("192.0.2.33", &ip));
    peer_addr_ = IPEndPoint(ip, 443);
    self_addr_ = IPEndPoint(ip, 8435);
    // Do null initialization for simple tests.
    Initialize();
  }

  ~QuicHttpStreamTest() {
    for (size_t i = 0; i < writes_.size(); i++) {
      delete writes_[i].packet;
    }
  }

  // Adds a packet to the list of expected writes.
  void AddWrite(IoMode mode, QuicEncryptedPacket* packet) {
    writes_.push_back(PacketToWrite(mode, packet));
  }

  // Returns the packet to be written at position |pos|.
  QuicEncryptedPacket* GetWrite(size_t pos) {
    return writes_[pos].packet;
  }

  bool AtEof() {
    return socket_data_->at_read_eof() && socket_data_->at_write_eof();
  }

  void ProcessPacket(const QuicEncryptedPacket& packet) {
    connection_->ProcessUdpPacket(self_addr_, peer_addr_, packet);
  }

  // Configures the test fixture to use the list of expected writes.
  void Initialize() {
    mock_writes_.reset(new MockWrite[writes_.size()]);
    for (size_t i = 0; i < writes_.size(); i++) {
      mock_writes_[i] = MockWrite(writes_[i].mode,
                                  writes_[i].packet->data(),
                                  writes_[i].packet->length());
    };

    socket_data_.reset(new StaticSocketDataProvider(NULL, 0, mock_writes_.get(),
                                                    writes_.size()));

    MockUDPClientSocket* socket = new MockUDPClientSocket(socket_data_.get(),
                                                          net_log_.net_log());
    socket->Connect(peer_addr_);
    runner_ = new TestTaskRunner(&clock_);
    send_algorithm_ = new MockSendAlgorithm();
    receive_algorithm_ = new TestReceiveAlgorithm(NULL);
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_)).
        WillRepeatedly(testing::Return(QuicTime::Delta::Zero()));
    helper_ = new QuicConnectionHelper(runner_.get(), &clock_,
                                       &random_generator_, socket);
    connection_ = new TestQuicConnection(guid_, peer_addr_, helper_);
    connection_->set_visitor(&visitor_);
    connection_->SetSendAlgorithm(send_algorithm_);
    connection_->SetReceiveAlgorithm(receive_algorithm_);
    session_.reset(new QuicClientSession(connection_, helper_, NULL,
                                         "www.google.com"));
    CryptoHandshakeMessage message;
    message.tag = kSHLO;
    session_->GetCryptoStream()->OnHandshakeMessage(message);
    EXPECT_TRUE(session_->IsCryptoHandshakeComplete());
    QuicReliableClientStream* stream =
        session_->CreateOutgoingReliableStream();
    stream_.reset(use_closing_stream_ ?
                  new AutoClosingStream(stream, GetParam()) :
                  new QuicHttpStream(stream, GetParam()));
  }

  void SetRequestString(const std::string& method, const std::string& path) {
    if (GetParam() == true) {
      SpdyHeaderBlock headers;
      headers[":method"] = method;
      headers[":host"] = "www.google.com";
      headers[":path"] = path;
      headers[":scheme"] = "http";
      headers[":version"] = "HTTP/1.1";
      request_data_ = SerializeHeaderBlock(headers);
    } else {
      request_data_ = method + " " + path + " HTTP/1.1\r\n\r\n";
    }
  }

  void SetResponseString(const std::string& status, const std::string& body) {
    if (GetParam() == true) {
      SpdyHeaderBlock headers;
      headers[":status"] = status;
      headers[":version"] = "HTTP/1.1";
      headers["content-type"] = "text/plain";
      response_data_ = SerializeHeaderBlock(headers) + body;
    } else {
      response_data_ = "HTTP/1.1 " + status + " \r\n"
          "Content-Type: text/plain\r\n\r\n" + body;
    }
  }

  std::string SerializeHeaderBlock(const SpdyHeaderBlock& headers) {
    size_t len = SpdyFramer::GetSerializedLength(3, &headers);
    SpdyFrameBuilder builder(len);
    SpdyFramer::WriteHeaderBlock(&builder, 3, &headers);
    scoped_ptr<SpdyFrame> frame(builder.take());
    return std::string(frame->data(), len);
  }

  // Returns a newly created packet to send kData on stream 1.
  QuicEncryptedPacket* ConstructDataPacket(
      QuicPacketSequenceNumber sequence_number,
      bool fin,
      QuicStreamOffset offset,
      base::StringPiece data) {
    InitializeHeader(sequence_number);
    QuicStreamFrame frame(3, fin, offset, data);
    return ConstructPacket(header_, QuicFrame(&frame));
  }

  // Returns a newly created packet to send ack data.
  QuicEncryptedPacket* ConstructAckPacket(
      QuicPacketSequenceNumber sequence_number,
      QuicPacketSequenceNumber largest_received,
      QuicPacketSequenceNumber least_unacked) {
    InitializeHeader(sequence_number);

    QuicAckFrame ack(largest_received, least_unacked);
    return ConstructPacket(header_, QuicFrame(&ack));
  }

  // Returns a newly created packet to send ack data.
  QuicEncryptedPacket* ConstructRstPacket(
      QuicPacketSequenceNumber sequence_number,
      QuicStreamId stream_id,
      QuicStreamOffset offset) {
    InitializeHeader(sequence_number);

    QuicRstStreamFrame rst(stream_id, offset, QUIC_NO_ERROR);
    return ConstructPacket(header_, QuicFrame(&rst));
  }

  BoundNetLog net_log_;
  bool use_closing_stream_;
  MockSendAlgorithm* send_algorithm_;
  TestReceiveAlgorithm* receive_algorithm_;
  scoped_refptr<TestTaskRunner> runner_;
  scoped_array<MockWrite> mock_writes_;
  MockClock clock_;
  MockRandom random_generator_;
  TestQuicConnection* connection_;
  QuicConnectionHelper* helper_;
  testing::StrictMock<MockConnectionVisitor> visitor_;
  scoped_ptr<QuicHttpStream> stream_;
  scoped_ptr<QuicClientSession> session_;
  TestCompletionCallback callback_;
  HttpRequestInfo request_;
  HttpRequestHeaders headers_;
  HttpResponseInfo response_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  std::string request_data_;
  std::string response_data_;

 private:
  void InitializeHeader(QuicPacketSequenceNumber sequence_number) {
    header_.public_header.guid = guid_;
    header_.public_header.flags = PACKET_PUBLIC_FLAGS_NONE;
    header_.packet_sequence_number = sequence_number;
    header_.fec_group = 0;
    header_.private_flags = PACKET_PRIVATE_FLAGS_NONE;
  }

  QuicEncryptedPacket* ConstructPacket(const QuicPacketHeader& header,
                                       const QuicFrame& frame) {
    QuicFrames frames;
    frames.push_back(frame);
    scoped_ptr<QuicPacket> packet(
        framer_.ConstructFrameDataPacket(header_, frames));
    return framer_.EncryptPacket(*packet);
  }

  const QuicGuid guid_;
  QuicFramer framer_;
  IPEndPoint self_addr_;
  IPEndPoint peer_addr_;
  QuicPacketCreator creator_;
  QuicPacketHeader header_;
  scoped_ptr<StaticSocketDataProvider> socket_data_;
  std::vector<PacketToWrite> writes_;
};

// All tests are run with two different serializations, HTTP/SPDY
INSTANTIATE_TEST_CASE_P(QuicHttpStreamTests,
                        QuicHttpStreamTest,
                        ::testing::Values(true, false));

TEST_P(QuicHttpStreamTest, RenewStreamForAuth) {
  EXPECT_EQ(NULL, stream_->RenewStreamForAuth());
}

TEST_P(QuicHttpStreamTest, CanFindEndOfResponse) {
  EXPECT_TRUE(stream_->CanFindEndOfResponse());
}

TEST_P(QuicHttpStreamTest, IsMoreDataBuffered) {
  EXPECT_FALSE(stream_->IsMoreDataBuffered());
}

TEST_P(QuicHttpStreamTest, IsConnectionReusable) {
  EXPECT_FALSE(stream_->IsConnectionReusable());
}

TEST_P(QuicHttpStreamTest, GetRequest) {
  SetRequestString("GET", "/");
  AddWrite(SYNCHRONOUS, ConstructDataPacket(1, kFin, 0,
                                            request_data_));
  AddWrite(SYNCHRONOUS, ConstructAckPacket(2, 2, 2));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("http://www.google.com/");

  EXPECT_EQ(OK, stream_->InitializeStream(&request_, net_log_,
                                          callback_.callback()));
  EXPECT_EQ(OK, stream_->SendRequest(headers_, &response_,
                                     callback_.callback()));
  EXPECT_EQ(&response_, stream_->GetResponseInfo());

  // Ack the request.
  scoped_ptr<QuicEncryptedPacket> ack(ConstructAckPacket(1, 1, 1));
  ProcessPacket(*ack);

  EXPECT_EQ(ERR_IO_PENDING,
            stream_->ReadResponseHeaders(callback_.callback()));

  // Send the response without a body.
  SetResponseString("404 Not Found", "");
  scoped_ptr<QuicEncryptedPacket> resp(
      ConstructDataPacket(2, kFin, 0, response_data_));
  ProcessPacket(*resp);

  // Now that the headers have been processed, the callback will return.
  EXPECT_EQ(OK, callback_.WaitForResult());
  ASSERT_TRUE(response_.headers != NULL);
  EXPECT_EQ(404, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // There is no body, so this should return immediately.
  EXPECT_EQ(0, stream_->ReadResponseBody(read_buffer_.get(),
                                         read_buffer_->size(),
                                         callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());
}

TEST_P(QuicHttpStreamTest, GetRequestFullResponseInSinglePacket) {
  SetRequestString("GET", "/");
  AddWrite(SYNCHRONOUS, ConstructDataPacket(1, kFin, 0, request_data_));
  AddWrite(SYNCHRONOUS, ConstructAckPacket(2, 2, 2));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("http://www.google.com/");

  EXPECT_EQ(OK, stream_->InitializeStream(&request_, net_log_,
                                          callback_.callback()));
  EXPECT_EQ(OK, stream_->SendRequest(headers_, &response_,
                                     callback_.callback()));
  EXPECT_EQ(&response_, stream_->GetResponseInfo());

  // Ack the request.
  scoped_ptr<QuicEncryptedPacket> ack(ConstructAckPacket(1, 1, 1));
  ProcessPacket(*ack);

  EXPECT_EQ(ERR_IO_PENDING,
            stream_->ReadResponseHeaders(callback_.callback()));

  // Send the response with a body.
  SetResponseString("200 OK", "hello world!");
  scoped_ptr<QuicEncryptedPacket> resp(
      ConstructDataPacket(2, kFin, 0, response_data_));
  ProcessPacket(*resp);

  // Now that the headers have been processed, the callback will return.
  EXPECT_EQ(OK, callback_.WaitForResult());
  ASSERT_TRUE(response_.headers != NULL);
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // There is no body, so this should return immediately.
  // Since the body has already arrived, this should return immediately.
  EXPECT_EQ(12, stream_->ReadResponseBody(read_buffer_.get(),
                                          read_buffer_->size(),
                                          callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());
}

TEST_P(QuicHttpStreamTest, SendPostRequest) {
  SetRequestString("POST", "/");
  AddWrite(SYNCHRONOUS, ConstructDataPacket(1, !kFin, 0, request_data_));
  AddWrite(SYNCHRONOUS, ConstructDataPacket(2, kFin, request_data_.length(),
                                            kUploadData));
  AddWrite(SYNCHRONOUS, ConstructAckPacket(3, 2, 3));

  Initialize();

  ScopedVector<UploadElementReader> element_readers;
  element_readers.push_back(
      new UploadBytesElementReader(kUploadData, strlen(kUploadData)));
  UploadDataStream upload_data_stream(&element_readers, 0);
  request_.method = "POST";
  request_.url = GURL("http://www.google.com/");
  request_.upload_data_stream = &upload_data_stream;
  ASSERT_EQ(OK, request_.upload_data_stream->Init(CompletionCallback()));

  EXPECT_EQ(OK, stream_->InitializeStream(&request_, net_log_,
                                          callback_.callback()));
  EXPECT_EQ(OK, stream_->SendRequest(headers_, &response_,
                                     callback_.callback()));
  EXPECT_EQ(&response_, stream_->GetResponseInfo());

  // Ack both packets in the request.
  scoped_ptr<QuicEncryptedPacket> ack(ConstructAckPacket(1, 2, 1));
  ProcessPacket(*ack);

  // Send the response headers (but not the body).
  SetResponseString("200 OK", "");
  scoped_ptr<QuicEncryptedPacket> resp(
      ConstructDataPacket(2, !kFin, 0, response_data_));
  ProcessPacket(*resp);

  // Since the headers have already arrived, this should return immediately.
  EXPECT_EQ(OK, stream_->ReadResponseHeaders(callback_.callback()));
  ASSERT_TRUE(response_.headers != NULL);
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  scoped_ptr<QuicEncryptedPacket> resp_body(
      ConstructDataPacket(3, kFin, response_data_.length(), kResponseBody));
  ProcessPacket(*resp_body);

  // Since the body has already arrived, this should return immediately.
  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());
}

TEST_P(QuicHttpStreamTest, DestroyedEarly) {
  SetRequestString("GET", "/");
  AddWrite(SYNCHRONOUS, ConstructDataPacket(1, kFin, 0, request_data_));
  AddWrite(SYNCHRONOUS, ConstructRstPacket(2, 3, request_data_.length()));
  AddWrite(SYNCHRONOUS, ConstructAckPacket(3, 2, 2));
  use_closing_stream_ = true;
  Initialize();

  request_.method = "GET";
  request_.url = GURL("http://www.google.com/");

  EXPECT_EQ(OK, stream_->InitializeStream(&request_, net_log_,
                                         callback_.callback()));
  EXPECT_EQ(OK, stream_->SendRequest(headers_, &response_,
                                    callback_.callback()));
  EXPECT_EQ(&response_, stream_->GetResponseInfo());

  // Ack the request.
  scoped_ptr<QuicEncryptedPacket> ack(ConstructAckPacket(1, 1, 1));
  ProcessPacket(*ack);
  EXPECT_EQ(ERR_IO_PENDING,
            stream_->ReadResponseHeaders(callback_.callback()));

  // Send the response with a body.
  const char kResponseHeaders[] = "HTTP/1.1 404 OK\r\n"
      "Content-Type: text/plain\r\n\r\nhello world!";
  scoped_ptr<QuicEncryptedPacket> resp(
      ConstructDataPacket(2, kFin, 0, kResponseHeaders));

  // In the course of processing this packet, the QuicHttpStream close itself.
  ProcessPacket(*resp);

  EXPECT_TRUE(AtEof());
}

}  // namespace test

}  // namespace net
