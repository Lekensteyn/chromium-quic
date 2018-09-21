// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_test_client.h"

#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/quic/crypto/proof_verifier.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/balsa/balsa_headers.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"
#include "net/tools/quic/quic_spdy_client_stream.h"
#include "net/tools/quic/test_tools/http_message.h"
#include "net/tools/quic/test_tools/quic_client_peer.h"
#include "url/gurl.h"

using base::StringPiece;
using net::QuicServerId;
using net::test::kInitialFlowControlWindowForTest;
using net::test::QuicConnectionPeer;
using std::string;
using std::vector;

namespace net {
namespace tools {
namespace test {
namespace {

// RecordingProofVerifier accepts any certificate chain and records the common
// name of the leaf.
class RecordingProofVerifier : public ProofVerifier {
 public:
  // ProofVerifier interface.
  virtual Status VerifyProof(const string& hostname,
                             const string& server_config,
                             const vector<string>& certs,
                             const string& signature,
                             const net::ProofVerifyContext* context,
                             string* error_details,
                             scoped_ptr<ProofVerifyDetails>* details,
                             ProofVerifierCallback* callback) OVERRIDE {
    common_name_.clear();
    if (certs.empty()) {
      return FAILURE;
    }

    // Convert certs to X509Certificate.
    vector<StringPiece> cert_pieces(certs.size());
    for (unsigned i = 0; i < certs.size(); i++) {
      cert_pieces[i] = StringPiece(certs[i]);
    }
    scoped_refptr<net::X509Certificate> cert =
        net::X509Certificate::CreateFromDERCertChain(cert_pieces);
    if (!cert.get()) {
      return FAILURE;
    }

    common_name_ = cert->subject().GetDisplayName();
    return SUCCESS;
  }

  const string& common_name() const { return common_name_; }

 private:
  string common_name_;
};

}  // anonymous namespace

BalsaHeaders* MungeHeaders(const BalsaHeaders* const_headers,
                           bool secure) {
  StringPiece uri = const_headers->request_uri();
  if (uri.empty()) {
    return NULL;
  }
  if (const_headers->request_method() == "CONNECT") {
    return NULL;
  }
  BalsaHeaders* headers = new BalsaHeaders;
  headers->CopyFrom(*const_headers);
  if (!uri.starts_with("https://") &&
      !uri.starts_with("http://")) {
    // If we have a relative URL, set some defaults.
    string full_uri = secure ? "https://www.google.com" :
                               "http://www.google.com";
    full_uri.append(uri.as_string());
    headers->SetRequestUri(full_uri);
  }
  return headers;
}

// A quic client which allows mocking out writes.
class MockableQuicClient : public QuicClient {
 public:
  MockableQuicClient(IPEndPoint server_address,
                     const QuicServerId& server_id,
                     const QuicVersionVector& supported_versions,
                     uint32 initial_flow_control_window)
      : QuicClient(server_address,
                   server_id,
                   supported_versions,
                   false,
                   initial_flow_control_window),
        override_connection_id_(0),
        test_writer_(NULL) {}

  MockableQuicClient(IPEndPoint server_address,
                     const QuicServerId& server_id,
                     const QuicConfig& config,
                     const QuicVersionVector& supported_versions,
                     uint32 initial_flow_control_window)
      : QuicClient(server_address,
                   server_id,
                   config,
                   supported_versions,
                   initial_flow_control_window),
        override_connection_id_(0),
        test_writer_(NULL) {}

  virtual ~MockableQuicClient() {
    if (connected()) {
      Disconnect();
    }
  }

  virtual QuicPacketWriter* CreateQuicPacketWriter() OVERRIDE {
    QuicPacketWriter* writer = QuicClient::CreateQuicPacketWriter();
    if (!test_writer_) {
      return writer;
    }
    test_writer_->set_writer(writer);
    return test_writer_;
  }

  virtual QuicConnectionId GenerateConnectionId() OVERRIDE {
    return override_connection_id_ ? override_connection_id_
                                   : QuicClient::GenerateConnectionId();
  }

  // Takes ownership of writer.
  void UseWriter(QuicPacketWriterWrapper* writer) {
    CHECK(test_writer_ == NULL);
    test_writer_ = writer;
  }

  void UseConnectionId(QuicConnectionId connection_id) {
    override_connection_id_ = connection_id;
  }

  virtual int ReadPacket(char* buffer,
                         int buffer_len,
                         IPEndPoint* server_address,
                         IPAddressNumber* client_ip) OVERRIDE {
    return QuicClient::ReadPacket(
        buffer, buffer_len, server_address, client_ip);
  }

 private:
  QuicConnectionId override_connection_id_;  // ConnectionId to use, if nonzero
  QuicPacketWriterWrapper* test_writer_;
};

QuicTestClient::QuicTestClient(IPEndPoint server_address,
                               const string& server_hostname,
                               const QuicVersionVector& supported_versions)
    : client_(new MockableQuicClient(server_address,
                                     QuicServerId(server_hostname,
                                                  server_address.port(),
                                                  false,
                                                  PRIVACY_MODE_DISABLED),
                                     supported_versions,
                                     kInitialFlowControlWindowForTest)) {
  Initialize(server_address, server_hostname, true);
}

QuicTestClient::QuicTestClient(IPEndPoint server_address,
                               const string& server_hostname,
                               bool secure,
                               const QuicVersionVector& supported_versions)
    : client_(new MockableQuicClient(server_address,
                                     QuicServerId(server_hostname,
                                                  server_address.port(),
                                                  secure,
                                                  PRIVACY_MODE_DISABLED),
                                     supported_versions,
                                     kInitialFlowControlWindowForTest)) {
  Initialize(server_address, server_hostname, secure);
}

QuicTestClient::QuicTestClient(
    IPEndPoint server_address,
    const string& server_hostname,
    bool secure,
    const QuicConfig& config,
    const QuicVersionVector& supported_versions,
    uint32 client_initial_flow_control_receive_window)
    : client_(
        new MockableQuicClient(server_address,
                               QuicServerId(server_hostname,
                                            server_address.port(),
                                            secure,
                                            PRIVACY_MODE_DISABLED),
                               config,
                               supported_versions,
                               client_initial_flow_control_receive_window)) {
  Initialize(server_address, server_hostname, secure);
}

void QuicTestClient::Initialize(IPEndPoint address,
                                const string& hostname,
                                bool secure) {
  server_address_ = address;
  priority_ = 3;
  connect_attempted_ = false;
  secure_ = secure;
  auto_reconnect_ = false;
  buffer_body_ = true;
  proof_verifier_ = NULL;
  ClearPerRequestState();
  ExpectCertificates(secure_);
}

QuicTestClient::~QuicTestClient() {
  if (stream_) {
    stream_->set_visitor(NULL);
  }
}

void QuicTestClient::ExpectCertificates(bool on) {
  if (on) {
    proof_verifier_ = new RecordingProofVerifier;
    client_->SetProofVerifier(proof_verifier_);
  } else {
    proof_verifier_ = NULL;
    client_->SetProofVerifier(NULL);
  }
}

ssize_t QuicTestClient::SendRequest(const string& uri) {
  HTTPMessage message(HttpConstants::HTTP_1_1, HttpConstants::GET, uri);
  return SendMessage(message);
}

ssize_t QuicTestClient::SendMessage(const HTTPMessage& message) {
  stream_ = NULL;  // Always force creation of a stream for SendMessage.

  // If we're not connected, try to find an sni hostname.
  if (!connected()) {
    GURL url(message.headers()->request_uri().as_string());
    if (!url.host().empty()) {
      client_->set_server_id(
          QuicServerId(url.host(), url.EffectiveIntPort(),
                       url.SchemeIs("https"), PRIVACY_MODE_DISABLED));
    }
  }

  QuicSpdyClientStream* stream = GetOrCreateStream();
  if (!stream) { return 0; }

  scoped_ptr<BalsaHeaders> munged_headers(MungeHeaders(message.headers(),
                                          secure_));
  ssize_t ret = GetOrCreateStream()->SendRequest(
      munged_headers.get() ? *munged_headers.get() : *message.headers(),
      message.body(),
      message.has_complete_message());
  WaitForWriteToFlush();
  return ret;
}

ssize_t QuicTestClient::SendData(string data, bool last_data) {
  QuicSpdyClientStream* stream = GetOrCreateStream();
  if (!stream) { return 0; }
  GetOrCreateStream()->SendBody(data, last_data);
  WaitForWriteToFlush();
  return data.length();
}

QuicPacketCreator::Options* QuicTestClient::options() {
  return client_->options();
}

string QuicTestClient::SendCustomSynchronousRequest(
    const HTTPMessage& message) {
  SendMessage(message);
  WaitForResponse();
  return response_;
}

string QuicTestClient::SendSynchronousRequest(const string& uri) {
  if (SendRequest(uri) == 0) {
    DLOG(ERROR) << "Failed the request for uri:" << uri;
    return "";
  }
  WaitForResponse();
  return response_;
}

QuicSpdyClientStream* QuicTestClient::GetOrCreateStream() {
  if (!connect_attempted_ || auto_reconnect_) {
    if (!connected()) {
      Connect();
    }
    if (!connected()) {
      return NULL;
    }
  }
  if (!stream_) {
    stream_ = client_->CreateReliableClientStream();
    if (stream_ == NULL) {
      return NULL;
    }
    stream_->set_visitor(this);
    reinterpret_cast<QuicSpdyClientStream*>(stream_)->set_priority(priority_);
  }

  return stream_;
}

QuicErrorCode QuicTestClient::connection_error() {
  return client()->session()->error();
}

QuicClient* QuicTestClient::client() { return client_.get(); }

const string& QuicTestClient::cert_common_name() const {
  return reinterpret_cast<RecordingProofVerifier*>(proof_verifier_)
      ->common_name();
}

QuicTagValueMap QuicTestClient::GetServerConfig() const {
  net::QuicCryptoClientConfig* config =
      QuicClientPeer::GetCryptoConfig(client_.get());
  net::QuicCryptoClientConfig::CachedState* state =
      config->LookupOrCreate(client_->server_id());
  const net::CryptoHandshakeMessage* handshake_msg = state->GetServerConfig();
  if (handshake_msg != NULL) {
    return handshake_msg->tag_value_map();
  } else {
    return QuicTagValueMap();
  }
}

bool QuicTestClient::connected() const {
  return client_->connected();
}

void QuicTestClient::WaitForResponse() {
  if (stream_ == NULL) {
    // The client has likely disconnected.
    return;
  }
  client_->WaitForStreamToClose(stream_->id());
}

void QuicTestClient::Connect() {
  DCHECK(!connected());
  if (!connect_attempted_) {
    client_->Initialize();
  }
  client_->Connect();
  connect_attempted_ = true;
}

void QuicTestClient::ResetConnection() {
  Disconnect();
  Connect();
}

void QuicTestClient::Disconnect() {
  client_->Disconnect();
  connect_attempted_ = false;
}

IPEndPoint QuicTestClient::LocalSocketAddress() const {
  return client_->client_address();
}

void QuicTestClient::ClearPerRequestState() {
  stream_error_ = QUIC_STREAM_NO_ERROR;
  stream_ = NULL;
  response_ = "";
  response_complete_ = false;
  response_headers_complete_ = false;
  headers_.Clear();
  bytes_read_ = 0;
  bytes_written_ = 0;
  response_header_size_ = 0;
  response_body_size_ = 0;
}

void QuicTestClient::WaitForResponseForMs(int timeout_ms) {
  int64 timeout_us = timeout_ms * base::Time::kMicrosecondsPerMillisecond;
  int64 old_timeout_us = client()->epoll_server()->timeout_in_us();
  if (timeout_us > 0) {
    client()->epoll_server()->set_timeout_in_us(timeout_us);
  }
  const QuicClock* clock =
      QuicConnectionPeer::GetHelper(client()->session()->connection())->
          GetClock();
  QuicTime end_waiting_time = clock->Now().Add(
      QuicTime::Delta::FromMicroseconds(timeout_us));
  while (stream_ != NULL &&
         !client_->session()->IsClosedStream(stream_->id()) &&
         (timeout_us < 0 || clock->Now() < end_waiting_time)) {
    client_->WaitForEvents();
  }
  if (timeout_us > 0) {
    client()->epoll_server()->set_timeout_in_us(old_timeout_us);
  }
}

void QuicTestClient::WaitForInitialResponseForMs(int timeout_ms) {
  int64 timeout_us = timeout_ms * base::Time::kMicrosecondsPerMillisecond;
  int64 old_timeout_us = client()->epoll_server()->timeout_in_us();
  if (timeout_us > 0) {
    client()->epoll_server()->set_timeout_in_us(timeout_us);
  }
  const QuicClock* clock =
      QuicConnectionPeer::GetHelper(client()->session()->connection())->
          GetClock();
  QuicTime end_waiting_time = clock->Now().Add(
      QuicTime::Delta::FromMicroseconds(timeout_us));
  while (stream_ != NULL &&
         !client_->session()->IsClosedStream(stream_->id()) &&
         stream_->stream_bytes_read() == 0 &&
         (timeout_us < 0 || clock->Now() < end_waiting_time)) {
    client_->WaitForEvents();
  }
  if (timeout_us > 0) {
    client()->epoll_server()->set_timeout_in_us(old_timeout_us);
  }
}

ssize_t QuicTestClient::Send(const void *buffer, size_t size) {
  return SendData(string(static_cast<const char*>(buffer), size), false);
}

bool QuicTestClient::response_headers_complete() const {
  if (stream_ != NULL) {
    return stream_->headers_decompressed();
  } else {
    return response_headers_complete_;
  }
}

const BalsaHeaders* QuicTestClient::response_headers() const {
  if (stream_ != NULL) {
    return &stream_->headers();
  } else {
    return &headers_;
  }
}

int QuicTestClient::response_size() const {
  return bytes_read_;
}

size_t QuicTestClient::bytes_read() const {
  return bytes_read_;
}

size_t QuicTestClient::bytes_written() const {
  return bytes_written_;
}

void QuicTestClient::OnClose(QuicDataStream* stream) {
  if (stream_ != stream) {
    return;
  }
  if (buffer_body()) {
    // TODO(fnk): The stream still buffers the whole thing. Fix that.
    response_ = stream_->data();
  }
  response_complete_ = true;
  response_headers_complete_ = stream_->headers_decompressed();
  headers_.CopyFrom(stream_->headers());
  stream_error_ = stream_->stream_error();
  bytes_read_ = stream_->stream_bytes_read() + stream_->header_bytes_read();
  bytes_written_ =
      stream_->stream_bytes_written() + stream_->header_bytes_written();
  response_header_size_ = headers_.GetSizeForWriteBuffer();
  response_body_size_ = stream_->data().size();
  stream_ = NULL;
}

void QuicTestClient::UseWriter(QuicPacketWriterWrapper* writer) {
  client_->UseWriter(writer);
}

void QuicTestClient::UseConnectionId(QuicConnectionId connection_id) {
  DCHECK(!connected());
  client_->UseConnectionId(connection_id);
}

void QuicTestClient::WaitForWriteToFlush() {
  while (connected() && client()->session()->HasDataToWrite()) {
    client_->WaitForEvents();
  }
}

}  // namespace test
}  // namespace tools
}  // namespace net
