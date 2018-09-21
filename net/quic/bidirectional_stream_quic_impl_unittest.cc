// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/bidirectional_stream_quic_impl.h"

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/transport_security_state.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_server_info.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_chromium_client_stream.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_crypto_client_stream_factory.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_test_packet_maker.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/test_task_runner.h"
#include "net/socket/socket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace test {

namespace {

const char kUploadData[] = "Really nifty data!";
const char kDefaultServerHostName[] = "www.google.com";
const uint16_t kDefaultServerPort = 80;
// Size of the buffer to be allocated for each read.
const size_t kReadBufferSize = 4096;

class TestDelegateBase : public BidirectionalStreamImpl::Delegate {
 public:
  TestDelegateBase(IOBuffer* read_buf, int read_buf_len)
      : TestDelegateBase(read_buf,
                         read_buf_len,
                         base::WrapUnique(new base::Timer(false, false))) {}

  TestDelegateBase(IOBuffer* read_buf,
                   int read_buf_len,
                   std::unique_ptr<base::Timer> timer)
      : read_buf_(read_buf),
        read_buf_len_(read_buf_len),
        timer_(std::move(timer)),
        loop_(nullptr),
        error_(OK),
        on_data_read_count_(0),
        on_data_sent_count_(0),
        not_expect_callback_(false),
        disable_auto_flush_(false) {
    loop_.reset(new base::RunLoop);
  }

  ~TestDelegateBase() override {}

  void OnStreamReady() override {
    CHECK(!not_expect_callback_);
    loop_->Quit();
  }

  void OnHeadersReceived(const SpdyHeaderBlock& response_headers) override {
    CHECK(!not_expect_callback_);

    response_headers_ = response_headers;
    loop_->Quit();
  }

  void OnDataRead(int bytes_read) override {
    CHECK(!not_expect_callback_);
    CHECK(!callback_.is_null());

    ++on_data_read_count_;
    CHECK_GE(bytes_read, OK);
    data_received_.append(read_buf_->data(), bytes_read);
    base::ResetAndReturn(&callback_).Run(bytes_read);
  }

  void OnDataSent() override {
    CHECK(!not_expect_callback_);

    ++on_data_sent_count_;
    loop_->Quit();
  }

  void OnTrailersReceived(const SpdyHeaderBlock& trailers) override {
    CHECK(!not_expect_callback_);

    trailers_ = trailers;
    loop_->Quit();
  }

  void OnFailed(int error) override {
    CHECK(!not_expect_callback_);
    CHECK_EQ(OK, error_);
    CHECK_NE(OK, error);

    error_ = error;
    loop_->Quit();
  }

  void Start(const BidirectionalStreamRequestInfo* request_info,
             const BoundNetLog& net_log,
             const base::WeakPtr<QuicChromiumClientSession> session) {
    stream_job_.reset(new BidirectionalStreamQuicImpl(session));
    stream_job_->Start(request_info, net_log, disable_auto_flush_, this,
                       nullptr);
  }

  void SendData(const scoped_refptr<IOBuffer>& data,
                int length,
                bool end_of_stream) {
    not_expect_callback_ = true;
    stream_job_->SendData(data, length, end_of_stream);
    not_expect_callback_ = false;
  }

  void SendvData(const std::vector<scoped_refptr<IOBuffer>>& data,
                 const std::vector<int>& lengths,
                 bool end_of_stream) {
    not_expect_callback_ = true;
    stream_job_->SendvData(data, lengths, end_of_stream);
    not_expect_callback_ = false;
  }

  // Waits until next Delegate callback.
  void WaitUntilNextCallback() {
    loop_->Run();
    loop_.reset(new base::RunLoop);
  }

  // Calls ReadData on the |stream_| and updates |data_received_|.
  int ReadData(const CompletionCallback& callback) {
    not_expect_callback_ = true;
    int rv = stream_job_->ReadData(read_buf_.get(), read_buf_len_);
    not_expect_callback_ = false;
    if (rv > 0)
      data_received_.append(read_buf_->data(), rv);
    if (rv == ERR_IO_PENDING)
      callback_ = callback;
    return rv;
  }

  // Cancels |stream_|.
  void CancelStream() { stream_job_->Cancel(); }

  NextProto GetProtocol() const { return stream_job_->GetProtocol(); }

  int64_t GetTotalReceivedBytes() const {
    return stream_job_->GetTotalReceivedBytes();
  }

  int64_t GetTotalSentBytes() const { return stream_job_->GetTotalSentBytes(); }

  void DisableAutoFlush() { disable_auto_flush_ = true; }

  // Const getters for internal states.
  const std::string& data_received() const { return data_received_; }
  int error() const { return error_; }
  const SpdyHeaderBlock& response_headers() const { return response_headers_; }
  const SpdyHeaderBlock& trailers() const { return trailers_; }
  int on_data_read_count() const { return on_data_read_count_; }
  int on_data_sent_count() const { return on_data_sent_count_; }

 protected:
  // Quits |loop_|.
  void QuitLoop() { loop_->Quit(); }

  // Deletes |stream_|.
  void DeleteStream() { stream_job_.reset(); }

 private:
  std::unique_ptr<BidirectionalStreamQuicImpl> stream_job_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  std::unique_ptr<base::Timer> timer_;
  std::string data_received_;
  std::unique_ptr<base::RunLoop> loop_;
  SpdyHeaderBlock response_headers_;
  SpdyHeaderBlock trailers_;
  int error_;
  int on_data_read_count_;
  int on_data_sent_count_;
  // This is to ensure that delegate callback is not invoked synchronously when
  // calling into |stream_|.
  bool not_expect_callback_;
  CompletionCallback callback_;
  bool disable_auto_flush_;

  DISALLOW_COPY_AND_ASSIGN(TestDelegateBase);
};

// A delegate that deletes the stream in a particular callback.
class DeleteStreamDelegate : public TestDelegateBase {
 public:
  // Specifies in which callback the stream can be deleted.
  enum Phase {
    ON_HEADERS_RECEIVED,
    ON_DATA_READ,
    ON_TRAILERS_RECEIVED,
    ON_FAILED,
  };

  DeleteStreamDelegate(IOBuffer* buf, int buf_len, Phase phase, bool do_cancel)
      : TestDelegateBase(buf, buf_len), phase_(phase), do_cancel_(do_cancel) {}
  ~DeleteStreamDelegate() override {}

  void OnHeadersReceived(const SpdyHeaderBlock& response_headers) override {
    if (phase_ == ON_HEADERS_RECEIVED) {
      DeleteStream();
    }
    TestDelegateBase::OnHeadersReceived(response_headers);
  }

  void OnDataSent() override { NOTREACHED(); }

  void OnDataRead(int bytes_read) override {
    DCHECK_NE(ON_HEADERS_RECEIVED, phase_);
    if (phase_ == ON_DATA_READ)
      DeleteStream();
    TestDelegateBase::OnDataRead(bytes_read);
  }

  void OnTrailersReceived(const SpdyHeaderBlock& trailers) override {
    DCHECK_NE(ON_HEADERS_RECEIVED, phase_);
    DCHECK_NE(ON_DATA_READ, phase_);
    if (phase_ == ON_TRAILERS_RECEIVED)
      DeleteStream();
    TestDelegateBase::OnTrailersReceived(trailers);
  }

  void OnFailed(int error) override {
    DCHECK_EQ(ON_FAILED, phase_);
    DeleteStream();
    TestDelegateBase::OnFailed(error);
  }

 private:
  // Indicates in which callback the delegate should cancel or delete the
  // stream.
  Phase phase_;
  // Indicates whether to cancel or delete the stream.
  bool do_cancel_;

  DISALLOW_COPY_AND_ASSIGN(DeleteStreamDelegate);
};

}  // namespace

class BidirectionalStreamQuicImplTest
    : public ::testing::TestWithParam<QuicVersion> {
 protected:
  static const bool kFin = true;
  static const bool kIncludeVersion = true;
  static const bool kIncludeCongestionFeedback = true;

  // Holds a packet to be written to the wire, and the IO mode that should
  // be used by the mock socket when performing the write.
  struct PacketToWrite {
    PacketToWrite(IoMode mode, QuicReceivedPacket* packet)
        : mode(mode), packet(packet) {}
    PacketToWrite(IoMode mode, int rv) : mode(mode), packet(nullptr), rv(rv) {}
    IoMode mode;
    QuicReceivedPacket* packet;
    int rv;
  };

  BidirectionalStreamQuicImplTest()
      : crypto_config_(CryptoTestUtils::ProofVerifierForTesting()),
        read_buffer_(new IOBufferWithSize(4096)),
        connection_id_(2),
        stream_id_(kClientDataStreamId1),
        client_maker_(GetParam(),
                      connection_id_,
                      &clock_,
                      kDefaultServerHostName,
                      Perspective::IS_CLIENT),
        server_maker_(GetParam(),
                      connection_id_,
                      &clock_,
                      kDefaultServerHostName,
                      Perspective::IS_SERVER),
        random_generator_(0) {
    IPAddress ip(192, 0, 2, 33);
    peer_addr_ = IPEndPoint(ip, 443);
    self_addr_ = IPEndPoint(ip, 8435);
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));
  }

  ~BidirectionalStreamQuicImplTest() {
    session_->CloseSessionOnError(ERR_ABORTED, QUIC_INTERNAL_ERROR);
    for (size_t i = 0; i < writes_.size(); i++) {
      delete writes_[i].packet;
    }
  }

  void TearDown() override {
    EXPECT_TRUE(socket_data_->AllReadDataConsumed());
    EXPECT_TRUE(socket_data_->AllWriteDataConsumed());
  }

  // Adds a packet to the list of expected writes.
  void AddWrite(std::unique_ptr<QuicReceivedPacket> packet) {
    writes_.push_back(PacketToWrite(SYNCHRONOUS, packet.release()));
  }

  void ProcessPacket(std::unique_ptr<QuicReceivedPacket> packet) {
    connection_->ProcessUdpPacket(self_addr_, peer_addr_, *packet);
  }

  // Configures the test fixture to use the list of expected writes.
  void Initialize() {
    mock_writes_.reset(new MockWrite[writes_.size()]);
    for (size_t i = 0; i < writes_.size(); i++) {
      if (writes_[i].packet == nullptr) {
        mock_writes_[i] = MockWrite(writes_[i].mode, writes_[i].rv, i);
      } else {
        mock_writes_[i] = MockWrite(writes_[i].mode, writes_[i].packet->data(),
                                    writes_[i].packet->length());
      }
    };

    socket_data_.reset(new StaticSocketDataProvider(
        nullptr, 0, mock_writes_.get(), writes_.size()));

    std::unique_ptr<MockUDPClientSocket> socket(new MockUDPClientSocket(
        socket_data_.get(), net_log().bound().net_log()));
    socket->Connect(peer_addr_);
    runner_ = new TestTaskRunner(&clock_);
    helper_.reset(
        new QuicChromiumConnectionHelper(&clock_, &random_generator_));
    alarm_factory_.reset(new QuicChromiumAlarmFactory(runner_.get(), &clock_));
    connection_ = new QuicConnection(
        connection_id_, peer_addr_, helper_.get(), alarm_factory_.get(),
        new QuicChromiumPacketWriter(socket.get()), true /* owns_writer */,
        Perspective::IS_CLIENT, SupportedVersions(GetParam()));

    session_.reset(new QuicChromiumClientSession(
        connection_, std::move(socket),
        /*stream_factory=*/nullptr, &crypto_client_stream_factory_, &clock_,
        &transport_security_state_, base::WrapUnique((QuicServerInfo*)nullptr),
        QuicServerId(kDefaultServerHostName, kDefaultServerPort,
                     PRIVACY_MODE_DISABLED),
        kQuicYieldAfterPacketsRead,
        QuicTime::Delta::FromMilliseconds(kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, DefaultQuicConfig(), &crypto_config_,
        "CONNECTION_UNKNOWN", base::TimeTicks::Now(), &push_promise_index_,
        base::ThreadTaskRunnerHandle::Get().get(),
        /*socket_performance_watcher=*/nullptr, net_log().bound().net_log()));
    session_->Initialize();
    session_->GetCryptoStream()->CryptoConnect();
    EXPECT_TRUE(session_->IsCryptoHandshakeConfirmed());
  }

  void SetRequest(const std::string& method,
                  const std::string& path,
                  RequestPriority priority) {
    request_headers_ = client_maker_.GetRequestHeaders(method, "http", path);
  }

  SpdyHeaderBlock ConstructResponseHeaders(const std::string& response_code) {
    return server_maker_.GetResponseHeaders(response_code);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructDataPacket(
      QuicPacketNumber packet_number,
      bool should_include_version,
      bool fin,
      QuicStreamOffset offset,
      base::StringPiece data,
      QuicTestPacketMaker* maker) {
    std::unique_ptr<QuicReceivedPacket> packet(maker->MakeDataPacket(
        packet_number, stream_id_, should_include_version, fin, offset, data));
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << QuicUtils::StringToHexASCIIDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<QuicReceivedPacket> ConstructServerDataPacket(
      QuicPacketNumber packet_number,
      bool should_include_version,
      bool fin,
      QuicStreamOffset offset,
      base::StringPiece data) {
    return ConstructDataPacket(packet_number, should_include_version, fin,
                               offset, data, &server_maker_);
  }

  // Construct a data packet with multiple data frames
  std::unique_ptr<QuicReceivedPacket> ConstructClientMultipleDataFramesPacket(
      QuicPacketNumber packet_number,
      bool should_include_version,
      bool fin,
      QuicStreamOffset offset,
      const std::vector<std::string>& data_writes) {
    std::unique_ptr<QuicReceivedPacket> packet(
        client_maker_.MakeMultipleDataFramesPacket(packet_number, stream_id_,
                                                   should_include_version, fin,
                                                   offset, data_writes));
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << QuicUtils::StringToHexASCIIDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<QuicReceivedPacket> ConstructRequestHeadersPacket(
      QuicPacketNumber packet_number,
      bool fin,
      RequestPriority request_priority,
      size_t* spdy_headers_frame_length) {
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    return client_maker_.MakeRequestHeadersPacket(
        packet_number, stream_id_, kIncludeVersion, fin, priority,
        request_headers_, spdy_headers_frame_length);
  }

  std::unique_ptr<QuicReceivedPacket>
  ConstructRequestHeadersAndMultipleDataFramesPacket(
      QuicPacketNumber packet_number,
      bool fin,
      RequestPriority request_priority,
      size_t* spdy_headers_frame_length,
      const std::vector<std::string>& data) {
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    std::unique_ptr<QuicReceivedPacket> packet(
        client_maker_.MakeRequestHeadersAndMultipleDataFramesPacket(
            packet_number, stream_id_, kIncludeVersion, fin, priority,
            request_headers_, spdy_headers_frame_length, data));
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << QuicUtils::StringToHexASCIIDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<QuicReceivedPacket> ConstructResponseHeadersPacket(
      QuicPacketNumber packet_number,
      bool fin,
      const SpdyHeaderBlock& response_headers,
      size_t* spdy_headers_frame_length,
      QuicStreamOffset* offset) {
    return server_maker_.MakeResponseHeadersPacket(
        packet_number, stream_id_, !kIncludeVersion, fin, response_headers,
        spdy_headers_frame_length, offset);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructResponseTrailersPacket(
      QuicPacketNumber packet_number,
      bool fin,
      const SpdyHeaderBlock& trailers,
      size_t* spdy_headers_frame_length,
      QuicStreamOffset* offset) {
    return server_maker_.MakeResponseHeadersPacket(
        packet_number, stream_id_, !kIncludeVersion, fin, trailers,
        spdy_headers_frame_length, offset);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructClientRstStreamPacket(
      QuicPacketNumber packet_number) {
    return ConstructRstStreamCancelledPacket(packet_number, 0, &client_maker_);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructServerRstStreamPacket(
      QuicPacketNumber packet_number) {
    return ConstructRstStreamCancelledPacket(packet_number, 0, &server_maker_);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructRstStreamCancelledPacket(
      QuicPacketNumber packet_number,
      size_t bytes_written,
      QuicTestPacketMaker* maker) {
    std::unique_ptr<QuicReceivedPacket> packet(
        maker->MakeRstPacket(packet_number, !kIncludeVersion, stream_id_,
                             QUIC_STREAM_CANCELLED, bytes_written));
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << QuicUtils::StringToHexASCIIDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<QuicReceivedPacket> ConstructClientAckAndRstStreamPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber ack_least_unacked,
      QuicPacketNumber stop_least_unacked) {
    return client_maker_.MakeAckAndRstPacket(
        packet_number, !kIncludeVersion, stream_id_, QUIC_STREAM_CANCELLED,
        largest_received, ack_least_unacked, stop_least_unacked,
        !kIncludeCongestionFeedback);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructAckAndDataPacket(
      QuicPacketNumber packet_number,
      bool should_include_version,
      QuicPacketNumber largest_received,
      QuicPacketNumber least_unacked,
      bool fin,
      QuicStreamOffset offset,
      base::StringPiece data,
      QuicTestPacketMaker* maker) {
    std::unique_ptr<QuicReceivedPacket> packet(maker->MakeAckAndDataPacket(
        packet_number, should_include_version, stream_id_, largest_received,
        least_unacked, fin, offset, data));
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << QuicUtils::StringToHexASCIIDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<QuicReceivedPacket> ConstructClientAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber least_unacked) {
    return client_maker_.MakeAckPacket(packet_number, largest_received,
                                       least_unacked,
                                       !kIncludeCongestionFeedback);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructServerAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber least_unacked) {
    return server_maker_.MakeAckPacket(packet_number, largest_received,
                                       least_unacked,
                                       !kIncludeCongestionFeedback);
  }

  const BoundTestNetLog& net_log() const { return net_log_; }

  QuicChromiumClientSession* session() const { return session_.get(); }

 protected:
  BoundTestNetLog net_log_;
  scoped_refptr<TestTaskRunner> runner_;
  std::unique_ptr<MockWrite[]> mock_writes_;
  MockClock clock_;
  QuicConnection* connection_;
  std::unique_ptr<QuicChromiumConnectionHelper> helper_;
  std::unique_ptr<QuicChromiumAlarmFactory> alarm_factory_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<QuicChromiumClientSession> session_;
  QuicCryptoClientConfig crypto_config_;
  HttpRequestHeaders headers_;
  HttpResponseInfo response_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  SpdyHeaderBlock request_headers_;
  const QuicConnectionId connection_id_;
  const QuicStreamId stream_id_;
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  IPEndPoint self_addr_;
  IPEndPoint peer_addr_;
  MockRandom random_generator_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  std::unique_ptr<StaticSocketDataProvider> socket_data_;
  std::vector<PacketToWrite> writes_;
  QuicClientPushPromiseIndex push_promise_index_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        BidirectionalStreamQuicImplTest,
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(BidirectionalStreamQuicImplTest, GetRequest) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));

  AddWrite(ConstructClientAckPacket(2, 3, 1));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  QuicStreamOffset offset = 0;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  ProcessPacket(
      ConstructServerDataPacket(3, !kIncludeVersion, !kFin, 0, kResponseBody));
  EXPECT_EQ(12, cb.WaitForResult());

  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());
  TestCompletionCallback cb2;
  EXPECT_EQ(ERR_IO_PENDING, delegate->ReadData(cb2.callback()));

  SpdyHeaderBlock trailers;
  size_t spdy_trailers_frame_length;
  trailers["foo"] = "bar";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(kResponseBody));
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(
      4, kFin, trailers, &spdy_trailers_frame_length, &offset));

  delegate->WaitUntilNextCallback();  // OnTrailersReceived
  EXPECT_EQ(OK, cb2.WaitForResult());
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate->trailers());

  EXPECT_EQ(OK, delegate->ReadData(cb2.callback()));
  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_response_headers_frame_length +
                           strlen(kResponseBody) + spdy_trailers_frame_length),
      delegate->GetTotalReceivedBytes());
  // Check that NetLog was filled as expected.
  TestNetLogEntry::List entries;
  net_log().GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLog::PHASE_NONE);
  pos = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/pos,
      NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLog::PHASE_NONE);
  ExpectLogContainsSomewhere(
      entries, /*min_offset=*/pos,
      NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLog::PHASE_NONE);
}

TEST_P(BidirectionalStreamQuicImplTest, CoalesceSmallBuffers) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;

  const char kBody1[] = "here are some data";
  const char kBody2[] = "data keep coming";
  std::vector<std::string> two_writes = {kBody1, kBody2};
  AddWrite(ConstructRequestHeadersAndMultipleDataFramesPacket(
      1, !kFin, DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      two_writes));
  // Ack server's data packet.
  AddWrite(ConstructClientAckPacket(2, 3, 1));
  const char kBody3[] = "hello there";
  const char kBody4[] = "another piece of small data";
  const char kBody5[] = "really small";
  QuicStreamOffset data_offset = strlen(kBody1) + strlen(kBody2);
  AddWrite(ConstructClientMultipleDataFramesPacket(
      3, !kIncludeVersion, kFin, data_offset, {kBody3, kBody4, kBody5}));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->DisableAutoFlush();
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Send a Data packet.
  scoped_refptr<StringIOBuffer> buf1(new StringIOBuffer(kBody1));
  scoped_refptr<StringIOBuffer> buf2(new StringIOBuffer(kBody2));

  std::vector<int> lengths = {buf1->size(), buf2->size()};
  delegate->SendvData({buf1, buf2}, lengths, !kFin);
  delegate->WaitUntilNextCallback();  // OnDataSent

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  QuicStreamOffset offset = 0;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  ProcessPacket(
      ConstructServerDataPacket(3, !kIncludeVersion, !kFin, 0, kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  // Send a second Data packet.
  scoped_refptr<StringIOBuffer> buf3(new StringIOBuffer(kBody3));
  scoped_refptr<StringIOBuffer> buf4(new StringIOBuffer(kBody4));
  scoped_refptr<StringIOBuffer> buf5(new StringIOBuffer(kBody5));

  delegate->SendvData({buf3, buf4, buf5},
                      {buf3->size(), buf4->size(), buf5->size()}, kFin);
  delegate->WaitUntilNextCallback();  // OnDataSent

  size_t spdy_trailers_frame_length;
  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(kResponseBody));
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(
      4, kFin, trailers, &spdy_trailers_frame_length, &offset));

  delegate->WaitUntilNextCallback();  // OnTrailersReceived
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_EQ(OK, delegate->ReadData(cb.callback()));

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_request_headers_frame_length + strlen(kBody1) +
                           strlen(kBody2) + strlen(kBody3) + strlen(kBody4) +
                           strlen(kBody5)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_response_headers_frame_length +
                           strlen(kResponseBody) + spdy_trailers_frame_length),
      delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, PostRequest) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructDataPacket(2, kIncludeVersion, kFin, 0, kUploadData,
                               &client_maker_));
  AddWrite(ConstructClientAckPacket(3, 3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf(new StringIOBuffer(kUploadData));

  delegate->SendData(buf, buf->size(), true);
  delegate->WaitUntilNextCallback();  // OnDataSent

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  QuicStreamOffset offset = 0;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  ProcessPacket(
      ConstructServerDataPacket(3, !kIncludeVersion, !kFin, 0, kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  size_t spdy_trailers_frame_length;
  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(kResponseBody));
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(
      4, kFin, trailers, &spdy_trailers_frame_length, &offset));

  delegate->WaitUntilNextCallback();  // OnTrailersReceived
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_EQ(OK, delegate->ReadData(cb.callback()));

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_response_headers_frame_length +
                           strlen(kResponseBody) + spdy_trailers_frame_length),
      delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, InterleaveReadDataAndSendData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructAckAndDataPacket(2, !kIncludeVersion, 2, 1, !kFin, 0,
                                     kUploadData, &client_maker_));
  AddWrite(ConstructAckAndDataPacket(3, !kIncludeVersion, 3, 3, kFin,
                                     strlen(kUploadData), kUploadData,
                                     &client_maker_));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length, 0));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Client sends a data packet.
  scoped_refptr<StringIOBuffer> buf(new StringIOBuffer(kUploadData));

  delegate->SendData(buf, buf->size(), false);
  delegate->WaitUntilNextCallback();  // OnDataSent

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  const char kResponseBody[] = "Hello world!";

  // Server sends a data packet.
  ProcessPacket(ConstructAckAndDataPacket(3, !kIncludeVersion, 2, 1, !kFin, 0,
                                          kResponseBody, &server_maker_));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());
  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());

  // Client sends a data packet.
  delegate->SendData(buf, buf->size(), true);
  delegate->WaitUntilNextCallback();  // OnDataSent

  TestCompletionCallback cb2;
  rv = delegate->ReadData(cb2.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  ProcessPacket(ConstructAckAndDataPacket(4, !kIncludeVersion, 3, 1, kFin,
                                          strlen(kResponseBody), kResponseBody,
                                          &server_maker_));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb2.WaitForResult());

  std::string expected_body(kResponseBody);
  expected_body.append(kResponseBody);
  EXPECT_EQ(expected_body, delegate->data_received());

  EXPECT_EQ(OK, delegate->ReadData(cb.callback()));
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 2 * strlen(kUploadData)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 2 * strlen(kResponseBody)),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, ServerSendsRstAfterHeaders) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server sends a Rst.
  ProcessPacket(ConstructServerRstStreamPacket(1));

  delegate->WaitUntilNextCallback();  // OnFailed
  TestCompletionCallback cb;
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, delegate->ReadData(cb.callback()));

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, delegate->error());
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(0, delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, ServerSendsRstAfterReadData) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  // Why does QUIC ack Rst? Is this expected?
  AddWrite(ConstructClientAckPacket(2, 3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  QuicStreamOffset offset = 0;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  // Server sends a Rst.
  ProcessPacket(ConstructServerRstStreamPacket(3));

  delegate->WaitUntilNextCallback();  // OnFailed

  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, delegate->ReadData(cb.callback()));
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, delegate->error());
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, CancelStreamAfterSendData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructAckAndDataPacket(2, !kIncludeVersion, 2, 1, !kFin, 0,
                                     kUploadData, &client_maker_));
  AddWrite(ConstructRstStreamCancelledPacket(3, strlen(kUploadData),
                                             &client_maker_));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length, 0));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf(new StringIOBuffer(kUploadData));

  delegate->SendData(buf, buf->size(), false);
  delegate->WaitUntilNextCallback();  // OnDataSent

  delegate->CancelStream();
  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, SessionClosedBeforeReadData) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  QuicStreamOffset offset = 0;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  session()->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  delegate->WaitUntilNextCallback();  // OnFailed

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(ERR_UNEXPECTED, delegate->ReadData(cb.callback()));
  EXPECT_EQ(ERR_UNEXPECTED, delegate->error());
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, CancelStreamAfterReadData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckAndRstStreamPacket(2, 2, 1, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length, 0));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Cancel the stream after ReadData returns ERR_IO_PENDING.
  TestCompletionCallback cb;
  EXPECT_EQ(ERR_IO_PENDING, delegate->ReadData(cb.callback()));
  delegate->CancelStream();

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC1SPDY3, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnHeadersReceived) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckAndRstStreamPacket(2, 2, 1, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(new DeleteStreamDelegate(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::ON_HEADERS_RECEIVED, true));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      nullptr));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnDataRead) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, !kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckPacket(2, 3, 1));
  AddWrite(ConstructClientRstStreamPacket(3));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(
      new DeleteStreamDelegate(read_buffer.get(), kReadBufferSize,
                               DeleteStreamDelegate::ON_DATA_READ, true));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      nullptr));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  ProcessPacket(
      ConstructServerDataPacket(3, !kIncludeVersion, !kFin, 0, kResponseBody));
  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnTrailersReceived) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  AddWrite(ConstructRequestHeadersPacket(1, kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckPacket(2, 3, 1));  // Ack the data packet

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(new DeleteStreamDelegate(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::ON_TRAILERS_RECEIVED, true));
  delegate->Start(&request, net_log().bound(), session()->GetWeakPtr());
  delegate->WaitUntilNextCallback();  // OnStreamReady

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 0, 0));

  // Server sends the response headers.
  SpdyHeaderBlock response_headers = ConstructResponseHeaders("200");

  QuicStreamOffset offset = 0;
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, response_headers, &spdy_response_headers_frame_length,
      &offset));

  delegate->WaitUntilNextCallback();  // OnHeadersReceived

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  ProcessPacket(
      ConstructServerDataPacket(3, !kIncludeVersion, !kFin, 0, kResponseBody));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());
  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());

  size_t spdy_trailers_frame_length;
  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(kResponseBody));
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(
      4, kFin, trailers, &spdy_trailers_frame_length, &offset));

  delegate->WaitUntilNextCallback();  // OnTrailersReceived
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate->trailers());

  base::MessageLoop::current()->RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

}  // namespace test

}  // namespace net
