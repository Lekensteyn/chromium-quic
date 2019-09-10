// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_stream_factory.h"

#include <algorithm>
#include <memory>
#include <tuple>
#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/dns/host_resolver.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/properties_based_quic_server_info.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_server_info.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/socket/udp_client_socket.h"
#include "net/third_party/quiche/src/quic/core/crypto/null_decrypter.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_verifier.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/http/quic_client_promised_info.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_clock.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "third_party/boringssl/src/include/openssl/aead.h"
#include "url/gurl.h"
#include "url/url_constants.h"

using NetworkHandle = net::NetworkChangeNotifier::NetworkHandle;

namespace net {

// Returns the estimate of dynamically allocated memory of an IPEndPoint in
// bytes. Used in tracking IPAliasMap.
size_t EstimateMemoryUsage(const IPEndPoint& end_point) {
  return 0;
}

namespace {

enum CreateSessionFailure {
  CREATION_ERROR_CONNECTING_SOCKET,
  CREATION_ERROR_SETTING_RECEIVE_BUFFER,
  CREATION_ERROR_SETTING_SEND_BUFFER,
  CREATION_ERROR_SETTING_DO_NOT_FRAGMENT,
  CREATION_ERROR_MAX
};

enum InitialRttEstimateSource {
  INITIAL_RTT_DEFAULT,
  INITIAL_RTT_CACHED,
  INITIAL_RTT_2G,
  INITIAL_RTT_3G,
  INITIAL_RTT_SOURCE_MAX,
};

enum class EmptyStaleResultLocation {
  kResolveHost = 0,
  kMatchFreshResult = 1,
  kNotEmpty = 2,
  kMaxValue = kNotEmpty,
};

// The maximum receive window sizes for QUIC sessions and streams.
const int32_t kQuicSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
const int32_t kQuicStreamMaxRecvWindowSize = 6 * 1024 * 1024;    // 6 MB

// QUIC's socket receive buffer size.
// We should adaptively set this buffer size, but for now, we'll use a size
// that seems large enough to receive data at line rate for most connections,
// and does not consume "too much" memory.
const int32_t kQuicSocketReceiveBufferSize = 1024 * 1024;  // 1MB

// Set the maximum number of undecryptable packets the connection will store.
const int32_t kMaxUndecryptablePackets = 100;

base::Value NetLogQuicStreamFactoryJobParams(
    const quic::QuicServerId* server_id) {
  base::DictionaryValue dict;
  dict.SetString(
      "server_id",
      "https://" +
          HostPortPair(server_id->host(), server_id->port()).ToString() +
          (server_id->privacy_mode_enabled() ? "/private" : ""));
  return std::move(dict);
}

// Helper class that is used to log a connection migration event.
class ScopedConnectionMigrationEventLog {
 public:
  ScopedConnectionMigrationEventLog(NetLog* net_log, const char* trigger)
      : net_log_(NetLogWithSource::Make(
            net_log,
            NetLogSourceType::QUIC_CONNECTION_MIGRATION)) {
    net_log_.BeginEventWithStringParams(
        NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED, "trigger",
        trigger);
  }

  ~ScopedConnectionMigrationEventLog() {
    net_log_.EndEvent(NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED);
  }

  const NetLogWithSource& net_log() { return net_log_; }

 private:
  const NetLogWithSource net_log_;
};

void HistogramCreateSessionFailure(enum CreateSessionFailure error) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.CreationError", error,
                            CREATION_ERROR_MAX);
}

void LogPlatformNotificationInHistogram(
    enum QuicPlatformNotification notification) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.PlatformNotification",
                            notification, NETWORK_NOTIFICATION_MAX);
}

void LogConnectionIpPooling(bool pooled) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ConnectionIpPooled", pooled);
}

void LogEmptyStaleResult(EmptyStaleResultLocation location) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.StaleHostResolveFailed", location);
}

void LogSessionAvailabilityWhenValidatingHost(bool available) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.SessionAvailableWhenValidatingDNS",
                        available);
}

void SetInitialRttEstimate(base::TimeDelta estimate,
                           enum InitialRttEstimateSource source,
                           quic::QuicConfig* config) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.InitialRttEsitmateSource", source,
                            INITIAL_RTT_SOURCE_MAX);
  if (estimate != base::TimeDelta())
    config->SetInitialRoundTripTimeUsToSend(estimate.InMicroseconds());
}

quic::QuicConfig InitializeQuicConfig(
    const quic::QuicTagVector& connection_options,
    const quic::QuicTagVector& client_connection_options,
    base::TimeDelta idle_connection_timeout,
    base::TimeDelta max_time_before_crypto_handshake,
    base::TimeDelta max_idle_time_before_crypto_handshake) {
  DCHECK_GT(idle_connection_timeout, base::TimeDelta());
  quic::QuicConfig config;
  config.SetIdleNetworkTimeout(quic::QuicTime::Delta::FromMicroseconds(
                                   idle_connection_timeout.InMicroseconds()),
                               quic::QuicTime::Delta::FromMicroseconds(
                                   idle_connection_timeout.InMicroseconds()));
  config.set_max_time_before_crypto_handshake(
      quic::QuicTime::Delta::FromMicroseconds(
          max_time_before_crypto_handshake.InMicroseconds()));
  config.set_max_idle_time_before_crypto_handshake(
      quic::QuicTime::Delta::FromMicroseconds(
          max_idle_time_before_crypto_handshake.InMicroseconds()));
  config.SetConnectionOptionsToSend(connection_options);
  config.SetClientConnectionOptions(client_connection_options);
  return config;
}

// An implementation of quic::QuicCryptoClientConfig::ServerIdFilter that wraps
// an |origin_filter|.
class ServerIdOriginFilter
    : public quic::QuicCryptoClientConfig::ServerIdFilter {
 public:
  explicit ServerIdOriginFilter(
      const base::RepeatingCallback<bool(const GURL&)> origin_filter)
      : origin_filter_(origin_filter) {}

  bool Matches(const quic::QuicServerId& server_id) const override {
    if (origin_filter_.is_null())
      return true;

    GURL url(base::StringPrintf("%s%s%s:%d", url::kHttpsScheme,
                                url::kStandardSchemeSeparator,
                                server_id.host().c_str(), server_id.port()));
    DCHECK(url.is_valid());
    return origin_filter_.Run(url);
  }

 private:
  const base::Callback<bool(const GURL&)> origin_filter_;
};

}  // namespace

QuicParams::QuicParams()
    : max_packet_length(quic::kDefaultMaxPacketSize),
      reduced_ping_timeout(
          base::TimeDelta::FromSeconds(quic::kPingTimeoutSecs)),
      max_time_before_crypto_handshake(
          base::TimeDelta::FromSeconds(quic::kMaxTimeForCryptoHandshakeSecs)),
      max_idle_time_before_crypto_handshake(
          base::TimeDelta::FromSeconds(quic::kInitialIdleTimeoutSecs)) {
  supported_versions.push_back(quic::ParsedQuicVersion(
      quic::PROTOCOL_QUIC_CRYPTO, quic::QUIC_VERSION_46));
}

QuicParams::QuicParams(const QuicParams& other) = default;

QuicParams::~QuicParams() = default;

// Responsible for verifying the certificates saved in
// quic::QuicCryptoClientConfig, and for notifying any associated requests when
// complete. Results from cert verification are ignored.
class QuicStreamFactory::CertVerifierJob {
 public:
  // ProofVerifierCallbackImpl is passed as the callback method to
  // VerifyCertChain. The quic::ProofVerifier calls this class with the result
  // of cert verification when verification is performed asynchronously.
  class ProofVerifierCallbackImpl : public quic::ProofVerifierCallback {
   public:
    explicit ProofVerifierCallbackImpl(CertVerifierJob* job) : job_(job) {}

    ~ProofVerifierCallbackImpl() override {}

    void Run(bool ok,
             const std::string& error_details,
             std::unique_ptr<quic::ProofVerifyDetails>* details) override {
      if (job_ == nullptr)
        return;
      job_->verify_callback_ = nullptr;
      job_->OnComplete();
    }

    void Cancel() { job_ = nullptr; }

   private:
    CertVerifierJob* job_;
  };

  CertVerifierJob(const quic::QuicServerId& server_id,
                  int cert_verify_flags,
                  const NetLogWithSource& net_log)
      : server_id_(server_id),
        verify_callback_(nullptr),
        verify_context_(
            std::make_unique<ProofVerifyContextChromium>(cert_verify_flags,
                                                         net_log)),
        start_time_(base::TimeTicks::Now()),
        net_log_(net_log) {}

  ~CertVerifierJob() {
    if (verify_callback_)
      verify_callback_->Cancel();
  }

  // Starts verification of certs cached in the |crypto_config|.
  quic::QuicAsyncStatus Run(quic::QuicCryptoClientConfig* crypto_config,
                            CompletionOnceCallback callback) {
    quic::QuicCryptoClientConfig::CachedState* cached =
        crypto_config->LookupOrCreate(server_id_);
    auto verify_callback = std::make_unique<ProofVerifierCallbackImpl>(this);
    auto* verify_callback_ptr = verify_callback.get();
    quic::QuicAsyncStatus status =
        crypto_config->proof_verifier()->VerifyCertChain(
            server_id_.host(), cached->certs(),
            /*ocsp_response=*/std::string(), cached->cert_sct(),
            verify_context_.get(), &verify_error_details_, &verify_details_,
            std::move(verify_callback));
    if (status == quic::QUIC_PENDING) {
      verify_callback_ = verify_callback_ptr;
      callback_ = std::move(callback);
    }
    return status;
  }

  void OnComplete() {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.CertVerifierJob.CompleteTime",
                        base::TimeTicks::Now() - start_time_);
    if (!callback_.is_null())
      std::move(callback_).Run(OK);
  }

  const quic::QuicServerId& server_id() const { return server_id_; }

  size_t EstimateMemoryUsage() const {
    // TODO(xunjieli): crbug.com/669108. Track |verify_context_| and
    // |verify_details_|.
    return base::trace_event::EstimateMemoryUsage(verify_error_details_);
  }

 private:
  const quic::QuicServerId server_id_;
  ProofVerifierCallbackImpl* verify_callback_;
  std::unique_ptr<quic::ProofVerifyContext> verify_context_;
  std::unique_ptr<quic::ProofVerifyDetails> verify_details_;
  std::string verify_error_details_;
  const base::TimeTicks start_time_;
  const NetLogWithSource net_log_;
  CompletionOnceCallback callback_;
  base::WeakPtrFactory<CertVerifierJob> weak_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(CertVerifierJob);
};

// Responsible for creating a new QUIC session to the specified server, and
// for notifying any associated requests when complete.
class QuicStreamFactory::Job {
 public:
  Job(QuicStreamFactory* factory,
      quic::ParsedQuicVersion quic_version,
      HostResolver* host_resolver,
      const QuicSessionAliasKey& key,
      bool was_alternative_service_recently_broken,
      bool retry_on_alternate_network_before_handshake,
      bool race_stale_dns_on_connection,
      RequestPriority priority,
      int cert_verify_flags,
      const NetLogWithSource& net_log);

  ~Job();

  int Run(CompletionOnceCallback callback);

  int DoLoop(int rv);
  int DoResolveHost();
  int DoResolveHostComplete(int rv);
  int DoConnect();
  int DoConnectComplete(int rv);
  int DoConfirmConnection(int rv);
  int DoValidateHost();

  void OnResolveHostComplete(int rv);
  void OnConnectComplete(int rv);
  void OnSessionClosed(QuicChromiumClientSession* session);

  const QuicSessionAliasKey& key() const { return key_; }

  const NetLogWithSource& net_log() const { return net_log_; }

  base::WeakPtr<Job> GetWeakPtr() { return weak_factory_.GetWeakPtr(); }

  void PopulateNetErrorDetails(NetErrorDetails* details) const;

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const;

  void AddRequest(QuicStreamRequest* request) {
    stream_requests_.insert(request);
    if (!host_resolution_finished_) {
      request->ExpectOnHostResolution();
    }
  }

  void RemoveRequest(QuicStreamRequest* request) {
    auto request_iter = stream_requests_.find(request);
    DCHECK(request_iter != stream_requests_.end());
    stream_requests_.erase(request_iter);
  }

  void SetPriority(RequestPriority priority) {
    if (priority_ == priority)
      return;

    priority_ = priority;
    if (resolve_host_request_ && !host_resolution_finished_) {
      if (fresh_resolve_host_request_) {
        fresh_resolve_host_request_->ChangeRequestPriority(priority);
      } else {
        resolve_host_request_->ChangeRequestPriority(priority);
      }
    }
  }

  const std::set<QuicStreamRequest*>& stream_requests() {
    return stream_requests_;
  }

  RequestPriority priority() const { return priority_; }

 private:
  enum IoState {
    STATE_NONE,
    STATE_RESOLVE_HOST,
    STATE_RESOLVE_HOST_COMPLETE,
    STATE_CONNECT,
    STATE_CONNECT_COMPLETE,
    STATE_HOST_VALIDATION,
    STATE_CONFIRM_CONNECTION,
  };

  void CloseStaleHostConnection() {
    DVLOG(1) << "Closing connection from stale host.";
    if (session_) {
      QuicChromiumClientSession* session = session_;
      session_ = nullptr;
      if (session) {
        session->CloseSessionOnErrorLater(
            ERR_ABORTED, quic::QUIC_STALE_CONNECTION_CANCELLED,
            quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      }
    }
  }

  bool DoesPeerAddressMatchWithFreshAddressList() {
    LogSessionAvailabilityWhenValidatingHost(session_ != nullptr);

    if (!session_)
      return false;

    std::vector<net::IPEndPoint> endpoints =
        fresh_resolve_host_request_->GetAddressResults().value().endpoints();

    if (!resolve_host_request_->GetAddressResults()) {
      LogEmptyStaleResult(EmptyStaleResultLocation::kMatchFreshResult);
      return false;
    }

    LogEmptyStaleResult(EmptyStaleResultLocation::kNotEmpty);
    IPEndPoint stale_address =
        resolve_host_request_->GetAddressResults().value().front();

    if (std::find(endpoints.begin(), endpoints.end(), stale_address) !=
        endpoints.end()) {
      return true;
    }
    return false;
  }

  void LogStaleHostRacing(bool used) {
    if (used) {
      net_log_.AddEvent(
          NetLogEventType::
              QUIC_STREAM_FACTORY_JOB_STALE_HOST_TRIED_ON_CONNECTION);
    } else {
      net_log_.AddEvent(
          NetLogEventType::
              QUIC_STREAM_FACTORY_JOB_STALE_HOST_NOT_USED_ON_CONNECTION);
    }
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.StaleHostRacing", used);
  }

  void LogStaleAndFreshHostMatched(bool matched) {
    if (matched) {
      net_log_.AddEvent(
          NetLogEventType::
              QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_MATCHED);
    } else {
      net_log_.AddEvent(
          NetLogEventType::
              QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_NO_MATCH);
    }
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.StaleAndFreshHostMatched", matched);
  }

  IoState io_state_;
  QuicStreamFactory* factory_;
  quic::ParsedQuicVersion quic_version_;
  HostResolver* host_resolver_;
  const QuicSessionAliasKey key_;
  RequestPriority priority_;
  const int cert_verify_flags_;
  const bool was_alternative_service_recently_broken_;
  const bool retry_on_alternate_network_before_handshake_;
  const bool race_stale_dns_on_connection_;
  const NetLogWithSource net_log_;
  bool host_resolution_finished_;
  bool connection_retried_;
  QuicChromiumClientSession* session_;
  // If connection migraiton is supported, |network_| denotes the network on
  // which |session_| is created.
  NetworkChangeNotifier::NetworkHandle network_;
  CompletionOnceCallback host_resolution_callback_;
  CompletionOnceCallback callback_;
  std::unique_ptr<HostResolver::ResolveHostRequest> resolve_host_request_;
  // Only set during DNS race. After completion, cleared or replaces
  // |resolve_host_request_|.
  std::unique_ptr<HostResolver::ResolveHostRequest> fresh_resolve_host_request_;
  base::TimeTicks dns_resolution_start_time_;
  base::TimeTicks dns_resolution_end_time_;
  std::set<QuicStreamRequest*> stream_requests_;
  base::WeakPtrFactory<Job> weak_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(Job);
};

QuicStreamFactory::Job::Job(QuicStreamFactory* factory,
                            quic::ParsedQuicVersion quic_version,
                            HostResolver* host_resolver,
                            const QuicSessionAliasKey& key,
                            bool was_alternative_service_recently_broken,
                            bool retry_on_alternate_network_before_handshake,
                            bool race_stale_dns_on_connection,
                            RequestPriority priority,
                            int cert_verify_flags,
                            const NetLogWithSource& net_log)
    : io_state_(STATE_RESOLVE_HOST),
      factory_(factory),
      quic_version_(quic_version),
      host_resolver_(host_resolver),
      key_(key),
      priority_(priority),
      cert_verify_flags_(cert_verify_flags),
      was_alternative_service_recently_broken_(
          was_alternative_service_recently_broken),
      retry_on_alternate_network_before_handshake_(
          retry_on_alternate_network_before_handshake),
      race_stale_dns_on_connection_(race_stale_dns_on_connection),
      net_log_(
          NetLogWithSource::Make(net_log.net_log(),
                                 NetLogSourceType::QUIC_STREAM_FACTORY_JOB)),
      host_resolution_finished_(false),
      connection_retried_(false),
      session_(nullptr),
      network_(NetworkChangeNotifier::kInvalidNetworkHandle) {
  net_log_.BeginEvent(NetLogEventType::QUIC_STREAM_FACTORY_JOB, [&] {
    return NetLogQuicStreamFactoryJobParams(&key_.server_id());
  });
  // Associate |net_log_| with |net_log|.
  net_log_.AddEventReferencingSource(
      NetLogEventType::QUIC_STREAM_FACTORY_JOB_BOUND_TO_HTTP_STREAM_JOB,
      net_log.source());
  net_log.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_BOUND_TO_QUIC_STREAM_FACTORY_JOB,
      net_log_.source());
}

QuicStreamFactory::Job::~Job() {
  net_log_.EndEvent(NetLogEventType::QUIC_STREAM_FACTORY_JOB);
  // If |this| is destroyed in QuicStreamFactory's destructor, |callback_| is
  // non-null.
}

int QuicStreamFactory::Job::Run(CompletionOnceCallback callback) {
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);

  return rv > 0 ? OK : rv;
}

int QuicStreamFactory::Job::DoLoop(int rv) {
  TRACE_EVENT0(NetTracingCategory(), "QuicStreamFactory::Job::DoLoop");

  do {
    IoState state = io_state_;
    io_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        CHECK_EQ(OK, rv);
        rv = DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case STATE_CONNECT:
        CHECK_EQ(OK, rv);
        rv = DoConnect();
        break;
      case STATE_CONNECT_COMPLETE:
        rv = DoConnectComplete(rv);
        break;
      case STATE_HOST_VALIDATION:
        rv = DoValidateHost();
        break;
      case STATE_CONFIRM_CONNECTION:
        rv = DoConfirmConnection(rv);
        break;
      default:
        NOTREACHED() << "io_state_: " << io_state_;
        break;
    }
  } while (io_state_ != STATE_NONE && rv != ERR_IO_PENDING);
  return rv;
}

void QuicStreamFactory::Job::OnSessionClosed(
    QuicChromiumClientSession* session) {
  // When dns racing experiment is on, the job needs to know that the stale
  // session is closed so that it will start the fresh session without matching
  // dns results.
  if (io_state_ == STATE_HOST_VALIDATION && session_ == session) {
    DCHECK(race_stale_dns_on_connection_);
    DCHECK(fresh_resolve_host_request_);
    resolve_host_request_ = std::move(fresh_resolve_host_request_);
    session_ = nullptr;
    io_state_ = STATE_RESOLVE_HOST_COMPLETE;
  }
}

void QuicStreamFactory::Job::OnResolveHostComplete(int rv) {
  DCHECK(!host_resolution_finished_);

  if (fresh_resolve_host_request_) {
    DCHECK(race_stale_dns_on_connection_);
    dns_resolution_end_time_ = base::TimeTicks::Now();
    if (rv != OK) {
      CloseStaleHostConnection();
      resolve_host_request_ = std::move(fresh_resolve_host_request_);
      io_state_ = STATE_RESOLVE_HOST_COMPLETE;
    } else if (factory_->HasMatchingIpSession(
                   key_,
                   fresh_resolve_host_request_->GetAddressResults().value())) {
      // Session with resolved IP has already existed, so close racing
      // connection, run callback, and return.
      LogConnectionIpPooling(true);
      CloseStaleHostConnection();
      if (!callback_.is_null())
        std::move(callback_).Run(OK);
      return;
    } else if (io_state_ != STATE_HOST_VALIDATION) {
      // Case where host resolution returns successfully, but stale connection
      // hasn't finished yet.
      if (DoesPeerAddressMatchWithFreshAddressList()) {
        LogStaleAndFreshHostMatched(true);
        fresh_resolve_host_request_ = nullptr;
        return;
      }
      LogStaleAndFreshHostMatched(false);
      CloseStaleHostConnection();
      resolve_host_request_ = std::move(fresh_resolve_host_request_);
      io_state_ = STATE_RESOLVE_HOST_COMPLETE;
    }  // Else stale connection has already finished successfully.
  } else {
    // If not in DNS race, we should have been waiting for this callback in
    // STATE_RESOLVE_HOST_COMPLETE.
    DCHECK_EQ(STATE_RESOLVE_HOST_COMPLETE, io_state_);
  }

  rv = DoLoop(rv);

  // Expect to be marked by either DoResolveHostComplete() or DoValidateHost().
  DCHECK(host_resolution_finished_);

  // DNS race should be completed either above or by DoValidateHost().
  DCHECK(!fresh_resolve_host_request_);

  for (auto* request : stream_requests_) {
    request->OnHostResolutionComplete(rv);
  }

  if (rv != ERR_IO_PENDING && !callback_.is_null())
    std::move(callback_).Run(rv);
}

void QuicStreamFactory::Job::OnConnectComplete(int rv) {
  // This early return will be triggered when CloseSessionOnError is called
  // before crypto handshake has completed.
  if (!session_)
    return;

  rv = DoLoop(rv);
  if (rv != ERR_IO_PENDING && !callback_.is_null())
    std::move(callback_).Run(rv);
}

void QuicStreamFactory::Job::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  if (!session_)
    return;
  details->connection_info = QuicHttpStream::ConnectionInfoFromQuicVersion(
      session_->connection()->transport_version());
  details->quic_connection_error = session_->error();
}

size_t QuicStreamFactory::Job::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(key_);
}

int QuicStreamFactory::Job::DoResolveHost() {
  dns_resolution_start_time_ = base::TimeTicks::Now();

  io_state_ = STATE_RESOLVE_HOST_COMPLETE;

  HostResolver::ResolveHostParameters parameters;
  parameters.initial_priority = priority_;
  if (race_stale_dns_on_connection_) {
    // Allow host resolver to return stale result immediately.
    parameters.cache_usage =
        HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;
  }
  resolve_host_request_ =
      host_resolver_->CreateRequest(key_.destination(), net_log_, parameters);
  // Unretained is safe because |this| owns the request, ensuring cancellation
  // on destruction.
  // When race_stale_dns_on_connection_ is on, this request will query for stale
  // cache if no fresh host result is available.
  int rv = resolve_host_request_->Start(base::BindOnce(
      &QuicStreamFactory::Job::OnResolveHostComplete, base::Unretained(this)));

  if (rv == ERR_IO_PENDING || !resolve_host_request_->GetStaleInfo() ||
      !resolve_host_request_->GetStaleInfo().value().is_stale()) {
    // Not a stale result.
    if (race_stale_dns_on_connection_)
      LogStaleHostRacing(false);
    return rv;
  }

  // If request resulted in a stale cache entry, start request for fresh results
  DCHECK(race_stale_dns_on_connection_);

  parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::DISALLOWED;
  fresh_resolve_host_request_ =
      host_resolver_->CreateRequest(key_.destination(), net_log_, parameters);
  // Unretained is safe because |this| owns the request, ensuring cancellation
  // on destruction.
  // This request will only query fresh host resolution.
  int fresh_rv = fresh_resolve_host_request_->Start(base::BindOnce(
      &QuicStreamFactory::Job::OnResolveHostComplete, base::Unretained(this)));
  if (fresh_rv != ERR_IO_PENDING) {
    // Fresh request returned immediate results.
    LogStaleHostRacing(false);
    resolve_host_request_ = std::move(fresh_resolve_host_request_);
    return fresh_rv;
  }

  // Check to make sure stale host request does produce valid results.
  if (!resolve_host_request_->GetAddressResults()) {
    LogStaleHostRacing(false);
    LogEmptyStaleResult(EmptyStaleResultLocation::kResolveHost);
    resolve_host_request_ = std::move(fresh_resolve_host_request_);
    return fresh_rv;
  }

  // No fresh host resolution is available at this time, but there is available
  // stale result. End time for stale host resolution is recorded and connection
  // from stale host will be tried.
  dns_resolution_end_time_ = base::TimeTicks().Now();
  io_state_ = STATE_CONNECT;
  LogStaleHostRacing(true);
  return OK;
}

int QuicStreamFactory::Job::DoResolveHostComplete(int rv) {
  host_resolution_finished_ = true;
  dns_resolution_end_time_ = base::TimeTicks::Now();
  if (rv != OK)
    return rv;

  DCHECK(!fresh_resolve_host_request_);
  DCHECK(!factory_->HasActiveSession(key_.session_key()));

  // Inform the factory of this resolution, which will set up
  // a session alias, if possible.
  if (factory_->HasMatchingIpSession(
          key_, resolve_host_request_->GetAddressResults().value())) {
    LogConnectionIpPooling(true);
    return OK;
  }

  io_state_ = STATE_CONNECT;
  return OK;
}

int QuicStreamFactory::Job::DoConnect() {
  DCHECK(dns_resolution_end_time_ != base::TimeTicks());
  io_state_ = STATE_CONNECT_COMPLETE;
  bool require_confirmation = was_alternative_service_recently_broken_;
  net_log_.AddEntryWithBoolParams(
      NetLogEventType::QUIC_STREAM_FACTORY_JOB_CONNECT, NetLogEventPhase::BEGIN,
      "require_confirmation", require_confirmation);

  DCHECK_NE(quic_version_.transport_version, quic::QUIC_VERSION_UNSUPPORTED);
  int rv = factory_->CreateSession(
      key_, quic_version_, cert_verify_flags_, require_confirmation,
      resolve_host_request_->GetAddressResults().value(),
      dns_resolution_start_time_, dns_resolution_end_time_, net_log_, &session_,
      &network_);
  DVLOG(1) << "Created session on network: " << network_;

  if (rv != OK) {
    DCHECK(rv != ERR_IO_PENDING);
    DCHECK(!session_);
    return rv;
  }

  if (!session_->connection()->connected())
    return ERR_CONNECTION_CLOSED;

  session_->StartReading();
  if (!session_->connection()->connected())
    return ERR_QUIC_PROTOCOL_ERROR;

  rv = session_->CryptoConnect(
      base::BindOnce(&QuicStreamFactory::Job::OnConnectComplete, GetWeakPtr()));

  if (!session_->connection()->connected() &&
      session_->error() == quic::QUIC_PROOF_INVALID) {
    return ERR_QUIC_HANDSHAKE_FAILED;
  }

  return rv;
}

int QuicStreamFactory::Job::DoConnectComplete(int rv) {
  if (!fresh_resolve_host_request_) {
    io_state_ = STATE_CONFIRM_CONNECTION;
    return rv;
  }

  if (rv == OK) {
    io_state_ = STATE_HOST_VALIDATION;
    return ERR_IO_PENDING;
  }

  // Connection from stale host resolution failed, has been closed and will
  // be deleted soon. Update Job status accordingly to wait for fresh host
  // resolution.
  resolve_host_request_ = std::move(fresh_resolve_host_request_);
  session_ = nullptr;
  io_state_ = STATE_RESOLVE_HOST_COMPLETE;
  return ERR_IO_PENDING;
}

// This state is reached iff both host resolution and connection from stale dns
// have finished successfully.
int QuicStreamFactory::Job::DoValidateHost() {
  if (DoesPeerAddressMatchWithFreshAddressList()) {
    LogStaleAndFreshHostMatched(true);
    fresh_resolve_host_request_ = nullptr;
    host_resolution_finished_ = true;
    io_state_ = STATE_CONFIRM_CONNECTION;
    return OK;
  }

  LogStaleAndFreshHostMatched(false);
  resolve_host_request_ = std::move(fresh_resolve_host_request_);
  CloseStaleHostConnection();
  io_state_ = STATE_RESOLVE_HOST_COMPLETE;
  return OK;
}

int QuicStreamFactory::Job::DoConfirmConnection(int rv) {
  UMA_HISTOGRAM_TIMES("Net.QuicSession.TimeFromResolveHostToConfirmConnection",
                      base::TimeTicks::Now() - dns_resolution_start_time_);
  net_log_.EndEvent(NetLogEventType::QUIC_STREAM_FACTORY_JOB_CONNECT);

  if (was_alternative_service_recently_broken_)
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ConnectAfterBroken", rv == OK);

  if (retry_on_alternate_network_before_handshake_ && session_ &&
      !session_->IsCryptoHandshakeConfirmed() &&
      network_ == factory_->default_network()) {
    if (session_->error() == quic::QUIC_NETWORK_IDLE_TIMEOUT ||
        session_->error() == quic::QUIC_HANDSHAKE_TIMEOUT ||
        session_->error() == quic::QUIC_PACKET_WRITE_ERROR) {
      // Retry the connection on an alternate network if crypto handshake failed
      // with network idle time out or handshake time out.
      DCHECK(network_ != NetworkChangeNotifier::kInvalidNetworkHandle);
      network_ = factory_->FindAlternateNetwork(network_);
      connection_retried_ =
          network_ != NetworkChangeNotifier::kInvalidNetworkHandle;
      UMA_HISTOGRAM_BOOLEAN(
          "Net.QuicStreamFactory.AttemptMigrationBeforeHandshake",
          connection_retried_);
      UMA_HISTOGRAM_ENUMERATION(
          "Net.QuicStreamFactory.AttemptMigrationBeforeHandshake."
          "FailedConnectionType",
          NetworkChangeNotifier::GetNetworkConnectionType(
              factory_->default_network()),
          NetworkChangeNotifier::ConnectionType::CONNECTION_LAST + 1);
      if (connection_retried_) {
        UMA_HISTOGRAM_ENUMERATION(
            "Net.QuicStreamFactory.MigrationBeforeHandshake.NewConnectionType",
            NetworkChangeNotifier::GetNetworkConnectionType(network_),
            NetworkChangeNotifier::ConnectionType::CONNECTION_LAST + 1);
        net_log_.AddEvent(
            NetLogEventType::
                QUIC_STREAM_FACTORY_JOB_RETRY_ON_ALTERNATE_NETWORK);
        // Notify requests that connection on the default network failed.
        for (auto* request : stream_requests_) {
          request->OnConnectionFailedOnDefaultNetwork();
        }
        DVLOG(1) << "Retry connection on alternate network: " << network_;
        session_ = nullptr;
        io_state_ = STATE_CONNECT;
        return OK;
      }
    }
  }

  if (connection_retried_) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.MigrationBeforeHandshake2",
                          rv == OK);
    if (rv == OK) {
      UMA_HISTOGRAM_BOOLEAN(
          "Net.QuicStreamFactory.NetworkChangeDuringMigrationBeforeHandshake",
          network_ == factory_->default_network());
    } else {
      base::UmaHistogramSparse(
          "Net.QuicStreamFactory.MigrationBeforeHandshakeFailedReason", -rv);
    }
  } else if (network_ != NetworkChangeNotifier::kInvalidNetworkHandle &&
             network_ != factory_->default_network()) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.ConnectionOnNonDefaultNetwork",
                          rv == OK);
  }

  if (rv != OK)
    return rv;

  DCHECK(!factory_->HasActiveSession(key_.session_key()));
  // There may well now be an active session for this IP.  If so, use the
  // existing session instead.
  AddressList address(ToIPEndPoint(session_->connection()->peer_address()));
  if (factory_->HasMatchingIpSession(key_, address)) {
    LogConnectionIpPooling(true);
    session_->connection()->CloseConnection(
        quic::QUIC_CONNECTION_IP_POOLED,
        "An active session exists for the given IP.",
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    session_ = nullptr;
    return OK;
  }
  LogConnectionIpPooling(false);

  factory_->ActivateSession(key_, session_);

  return OK;
}

QuicStreamRequest::QuicStreamRequest(QuicStreamFactory* factory)
    : factory_(factory), expect_on_host_resolution_(false) {}

QuicStreamRequest::~QuicStreamRequest() {
  if (factory_ && !callback_.is_null())
    factory_->CancelRequest(this);
}

int QuicStreamRequest::Request(
    const HostPortPair& destination,
    quic::ParsedQuicVersion quic_version,
    PrivacyMode privacy_mode,
    RequestPriority priority,
    const SocketTag& socket_tag,
    const NetworkIsolationKey& network_isolation_key,
    int cert_verify_flags,
    const GURL& url,
    const NetLogWithSource& net_log,
    NetErrorDetails* net_error_details,
    CompletionOnceCallback failed_on_default_network_callback,
    CompletionOnceCallback callback) {
  DCHECK_NE(quic_version.transport_version, quic::QUIC_VERSION_UNSUPPORTED);
  DCHECK(net_error_details);
  DCHECK(callback_.is_null());
  DCHECK(host_resolution_callback_.is_null());
  DCHECK(factory_);

  net_error_details_ = net_error_details;
  failed_on_default_network_callback_ =
      std::move(failed_on_default_network_callback);
  session_key_ = QuicSessionKey(HostPortPair::FromURL(url), privacy_mode,
                                socket_tag, network_isolation_key);

  int rv = factory_->Create(session_key_, destination, quic_version, priority,
                            cert_verify_flags, url, net_log, this);
  if (rv == ERR_IO_PENDING) {
    net_log_ = net_log;
    callback_ = std::move(callback);
  } else {
    DCHECK(!expect_on_host_resolution_);
    factory_ = nullptr;
  }

  if (rv == OK)
    DCHECK(session_);
  return rv;
}

bool QuicStreamRequest::WaitForHostResolution(CompletionOnceCallback callback) {
  DCHECK(host_resolution_callback_.is_null());
  if (expect_on_host_resolution_) {
    host_resolution_callback_ = std::move(callback);
  }
  return expect_on_host_resolution_;
}

void QuicStreamRequest::SetSession(
    std::unique_ptr<QuicChromiumClientSession::Handle> session) {
  session_ = move(session);
}

void QuicStreamRequest::OnConnectionFailedOnDefaultNetwork() {
  if (!failed_on_default_network_callback_.is_null())
    std::move(failed_on_default_network_callback_).Run(OK);
}

void QuicStreamRequest::OnRequestComplete(int rv) {
  factory_ = nullptr;
  std::move(callback_).Run(rv);
}

void QuicStreamRequest::ExpectOnHostResolution() {
  expect_on_host_resolution_ = true;
}

void QuicStreamRequest::OnHostResolutionComplete(int rv) {
  DCHECK(expect_on_host_resolution_);
  expect_on_host_resolution_ = false;
  if (!host_resolution_callback_.is_null()) {
    std::move(host_resolution_callback_).Run(rv);
  }
}

base::TimeDelta QuicStreamRequest::GetTimeDelayForWaitingJob() const {
  if (!factory_)
    return base::TimeDelta();
  return factory_->GetTimeDelayForWaitingJob(
      session_key_.server_id(), session_key_.network_isolation_key());
}

void QuicStreamRequest::SetPriority(RequestPriority priority) {
  if (factory_)
    factory_->SetRequestPriority(this, priority);
}

std::unique_ptr<QuicChromiumClientSession::Handle>
QuicStreamRequest::ReleaseSessionHandle() {
  if (!session_ || !session_->IsConnected())
    return nullptr;

  return std::move(session_);
}

namespace {

std::set<std::string> HostsFromOrigins(std::set<HostPortPair> origins) {
  std::set<std::string> hosts;
  for (const auto& origin : origins) {
    hosts.insert(origin.host());
  }
  return hosts;
}

}  // namespace

QuicStreamFactory::QuicStreamFactory(
    NetLog* net_log,
    HostResolver* host_resolver,
    SSLConfigService* ssl_config_service,
    ClientSocketFactory* client_socket_factory,
    HttpServerProperties* http_server_properties,
    CertVerifier* cert_verifier,
    CTPolicyEnforcer* ct_policy_enforcer,
    TransportSecurityState* transport_security_state,
    CTVerifier* cert_transparency_verifier,
    SocketPerformanceWatcherFactory* socket_performance_watcher_factory,
    QuicCryptoClientStreamFactory* quic_crypto_client_stream_factory,
    quic::QuicRandom* random_generator,
    quic::QuicClock* clock,
    const QuicParams& params)
    : require_confirmation_(true),
      net_log_(net_log),
      host_resolver_(host_resolver),
      client_socket_factory_(client_socket_factory),
      http_server_properties_(http_server_properties),
      push_delegate_(nullptr),
      transport_security_state_(transport_security_state),
      cert_transparency_verifier_(cert_transparency_verifier),
      quic_crypto_client_stream_factory_(quic_crypto_client_stream_factory),
      random_generator_(random_generator),
      clock_(clock),
      params_(params),
      clock_skew_detector_(base::TimeTicks::Now(), base::Time::Now()),
      socket_performance_watcher_factory_(socket_performance_watcher_factory),
      config_(
          InitializeQuicConfig(params.connection_options,
                               params.client_connection_options,
                               params.idle_connection_timeout,
                               params.max_time_before_crypto_handshake,
                               params.max_idle_time_before_crypto_handshake)),
      crypto_config_(std::make_unique<ProofVerifierChromium>(
          cert_verifier,
          ct_policy_enforcer,
          transport_security_state,
          cert_transparency_verifier,
          HostsFromOrigins(params.origins_to_force_quic_on))),
      ping_timeout_(quic::QuicTime::Delta::FromSeconds(quic::kPingTimeoutSecs)),
      reduced_ping_timeout_(quic::QuicTime::Delta::FromMicroseconds(
          params.reduced_ping_timeout.InMicroseconds())),
      retransmittable_on_wire_timeout_(quic::QuicTime::Delta::FromMicroseconds(
          params.retransmittable_on_wire_timeout.InMicroseconds())),
      yield_after_packets_(kQuicYieldAfterPacketsRead),
      yield_after_duration_(quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds)),
      default_network_(NetworkChangeNotifier::kInvalidNetworkHandle),
      need_to_check_persisted_supports_quic_(true),
      num_push_streams_created_(0),
      tick_clock_(nullptr),
      task_runner_(nullptr),
      ssl_config_service_(ssl_config_service) {
  DCHECK(transport_security_state_);
  DCHECK(http_server_properties_);
  crypto_config_.set_user_agent_id(params.user_agent_id);
  crypto_config_.AddCanonicalSuffix(".c.youtube.com");
  crypto_config_.AddCanonicalSuffix(".ggpht.com");
  crypto_config_.AddCanonicalSuffix(".googlevideo.com");
  crypto_config_.AddCanonicalSuffix(".googleusercontent.com");
  bool prefer_aes_gcm =
      !crypto_config_.aead.empty() && (crypto_config_.aead[0] == quic::kAESG);
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.PreferAesGcm", prefer_aes_gcm);
  InitializeMigrationOptions();
}

void QuicStreamFactory::InitializeMigrationOptions() {
  // The following list of options cannot be set immediately until
  // prerequisites are met. Cache the initial setting in local variables and
  // reset them in |params_|.
  bool migrate_sessions_on_network_change =
      params_.migrate_sessions_on_network_change_v2;
  bool migrate_sessions_early = params_.migrate_sessions_early_v2;
  bool retry_on_alternate_network_before_handshake =
      params_.retry_on_alternate_network_before_handshake;
  bool migrate_idle_sessions = params_.migrate_idle_sessions;
  bool allow_port_migration = params_.allow_port_migration;
  params_.migrate_sessions_on_network_change_v2 = false;
  params_.migrate_sessions_early_v2 = false;
  params_.allow_port_migration = false;
  params_.retry_on_alternate_network_before_handshake = false;
  params_.migrate_idle_sessions = false;

  DCHECK(!(migrate_sessions_early && params_.go_away_on_path_degrading));
  DCHECK(!(allow_port_migration && params_.go_away_on_path_degrading));

  // TODO(zhongyi): deprecate |goaway_sessions_on_ip_change| if the experiment
  // is no longer needed.
  // goaway_sessions_on_ip_change and close_sessions_on_ip_change should never
  // be simultaneously set to true.
  DCHECK(!(params_.close_sessions_on_ip_change &&
           params_.goaway_sessions_on_ip_change));

  bool handle_ip_change = params_.close_sessions_on_ip_change ||
                          params_.goaway_sessions_on_ip_change;
  // If IP address changes are handled explicitly, connection migration should
  // not be set.
  DCHECK(!(handle_ip_change && migrate_sessions_on_network_change));

  if (handle_ip_change)
    NetworkChangeNotifier::AddIPAddressObserver(this);

  // Port migration and early migration both act on path degrading and thus can
  // not be simultaneously set.
  DCHECK(!allow_port_migration || !migrate_sessions_early);

  if (allow_port_migration)
    params_.allow_port_migration = true;

  if (!NetworkChangeNotifier::AreNetworkHandlesSupported())
    return;

  NetworkChangeNotifier::AddNetworkObserver(this);
  // Perform checks on the connection migration options.
  if (!migrate_sessions_on_network_change) {
    DCHECK(!migrate_sessions_early);
    return;
  }

  // Enable migration on platform notifications.
  params_.migrate_sessions_on_network_change_v2 = true;

  if (!migrate_sessions_early) {
    DCHECK(!migrate_idle_sessions &&
           !retry_on_alternate_network_before_handshake);
    return;
  }

  // Enable migration on path degrading.
  params_.migrate_sessions_early_v2 = true;
  // Set retransmittable on wire timeout for migration on path degrading if no
  // value is specified.
  if (retransmittable_on_wire_timeout_.IsZero()) {
    retransmittable_on_wire_timeout_ = quic::QuicTime::Delta::FromMicroseconds(
        kDefaultRetransmittableOnWireTimeout.InMicroseconds());
  }

  // Enable retry on alternate network before handshake.
  if (retry_on_alternate_network_before_handshake)
    params_.retry_on_alternate_network_before_handshake = true;

  // Enable migration for idle sessions.
  if (migrate_idle_sessions)
    params_.migrate_idle_sessions = true;
}

QuicStreamFactory::~QuicStreamFactory() {
  UMA_HISTOGRAM_COUNTS_1000("Net.NumQuicSessionsAtShutdown",
                            all_sessions_.size());
  CloseAllSessions(ERR_ABORTED, quic::QUIC_CONNECTION_CANCELLED);
  while (!all_sessions_.empty()) {
    delete all_sessions_.begin()->first;
    all_sessions_.erase(all_sessions_.begin());
  }
  active_jobs_.clear();
  while (!active_cert_verifier_jobs_.empty())
    active_cert_verifier_jobs_.erase(active_cert_verifier_jobs_.begin());
  if (params_.close_sessions_on_ip_change ||
      params_.goaway_sessions_on_ip_change) {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
  }
  if (NetworkChangeNotifier::AreNetworkHandlesSupported()) {
    NetworkChangeNotifier::RemoveNetworkObserver(this);
  }
}

void QuicStreamFactory::set_require_confirmation(bool require_confirmation) {
  require_confirmation_ = require_confirmation;
  if (!(local_address_ == IPEndPoint())) {
    http_server_properties_->SetSupportsQuic(!require_confirmation,
                                             local_address_.address());
  }
}

base::TimeDelta QuicStreamFactory::GetTimeDelayForWaitingJob(
    const quic::QuicServerId& server_id,
    const NetworkIsolationKey& network_isolation_key) {
  if (require_confirmation_) {
    IPAddress last_address;
    if (!need_to_check_persisted_supports_quic_ ||
        !http_server_properties_->GetSupportsQuic(&last_address)) {
      return base::TimeDelta();
    }
  }

  int64_t srtt = 1.5 * GetServerNetworkStatsSmoothedRttInMicroseconds(
                           server_id, network_isolation_key);
  // Picked 300ms based on mean time from
  // Net.QuicSession.HostResolution.HandshakeConfirmedTime histogram.
  const int kDefaultRTT = 300 * quic::kNumMicrosPerMilli;
  if (!srtt)
    srtt = kDefaultRTT;
  return base::TimeDelta::FromMicroseconds(srtt);
}

void QuicStreamFactory::DumpMemoryStats(
    base::trace_event::ProcessMemoryDump* pmd,
    const std::string& parent_absolute_name) const {
  if (all_sessions_.empty() && active_jobs_.empty())
    return;
  base::trace_event::MemoryAllocatorDump* factory_dump =
      pmd->CreateAllocatorDump(parent_absolute_name + "/quic_stream_factory");
  size_t memory_estimate =
      base::trace_event::EstimateMemoryUsage(all_sessions_) +
      base::trace_event::EstimateMemoryUsage(active_sessions_) +
      base::trace_event::EstimateMemoryUsage(session_aliases_) +
      base::trace_event::EstimateMemoryUsage(ip_aliases_) +
      base::trace_event::EstimateMemoryUsage(session_peer_ip_) +
      base::trace_event::EstimateMemoryUsage(gone_away_aliases_) +
      base::trace_event::EstimateMemoryUsage(active_jobs_) +
      base::trace_event::EstimateMemoryUsage(active_cert_verifier_jobs_);
  factory_dump->AddScalar(base::trace_event::MemoryAllocatorDump::kNameSize,
                          base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                          memory_estimate);
  factory_dump->AddScalar("all_sessions",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          all_sessions_.size());
  factory_dump->AddScalar("active_jobs",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          active_jobs_.size());
  factory_dump->AddScalar("active_cert_jobs",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          active_cert_verifier_jobs_.size());
}

bool QuicStreamFactory::CanUseExistingSession(const QuicSessionKey& session_key,
                                              const HostPortPair& destination) {
  // TODO(zhongyi): delete active_sessions_.empty() checks once the
  // android crash issue(crbug.com/498823) is resolved.
  if (active_sessions_.empty())
    return false;

  if (base::Contains(active_sessions_, session_key))
    return true;

  for (const auto& key_value : active_sessions_) {
    QuicChromiumClientSession* session = key_value.second;
    if (destination.Equals(all_sessions_[session].destination()) &&
        session->CanPool(session_key.host(), session_key.privacy_mode(),
                         session_key.socket_tag(),
                         session_key.network_isolation_key())) {
      return true;
    }
  }

  return false;
}

void QuicStreamFactory::MarkAllActiveSessionsGoingAway() {
  while (!active_sessions_.empty()) {
    QuicChromiumClientSession* session = active_sessions_.begin()->second;
    OnSessionGoingAway(session);
  }
}

int QuicStreamFactory::Create(const QuicSessionKey& session_key,
                              const HostPortPair& destination,
                              quic::ParsedQuicVersion quic_version,
                              RequestPriority priority,
                              int cert_verify_flags,
                              const GURL& url,
                              const NetLogWithSource& net_log,
                              QuicStreamRequest* request) {
  if (clock_skew_detector_.ClockSkewDetected(base::TimeTicks::Now(),
                                             base::Time::Now())) {
    MarkAllActiveSessionsGoingAway();
  }
  DCHECK(HostPortPair(session_key.server_id().host(),
                      session_key.server_id().port())
             .Equals(HostPortPair::FromURL(url)));
  // Enforce session affinity for promised streams.
  quic::QuicClientPromisedInfo* promised =
      push_promise_index_.GetPromised(url.spec());
  if (promised) {
    QuicChromiumClientSession* session =
        static_cast<QuicChromiumClientSession*>(promised->session());
    DCHECK(session);
    if (session->server_id().privacy_mode_enabled() ==
        session_key.server_id().privacy_mode_enabled()) {
      request->SetSession(session->CreateHandle(destination));
      ++num_push_streams_created_;
      return OK;
    }
    // This should happen extremely rarely (if ever), but if somehow a
    // request comes in with a mismatched privacy mode, consider the
    // promise borked.
    promised->Cancel();
  }

  // Use active session for |session_key| if such exists.
  // TODO(rtenneti): crbug.com/498823 - delete active_sessions_.empty() checks.
  if (!active_sessions_.empty()) {
    auto it = active_sessions_.find(session_key);
    if (it != active_sessions_.end()) {
      QuicChromiumClientSession* session = it->second;
      request->SetSession(session->CreateHandle(destination));
      return OK;
    }
  }

  // Associate with active job to |session_key| if such exists.
  auto it = active_jobs_.find(session_key);
  if (it != active_jobs_.end()) {
    const NetLogWithSource& job_net_log = it->second->net_log();
    job_net_log.AddEventReferencingSource(
        NetLogEventType::QUIC_STREAM_FACTORY_JOB_BOUND_TO_HTTP_STREAM_JOB,
        net_log.source());
    net_log.AddEventReferencingSource(
        NetLogEventType::HTTP_STREAM_JOB_BOUND_TO_QUIC_STREAM_FACTORY_JOB,
        job_net_log.source());
    it->second->AddRequest(request);
    return ERR_IO_PENDING;
  }

  // Pool to active session to |destination| if possible.
  if (!active_sessions_.empty()) {
    for (const auto& key_value : active_sessions_) {
      QuicChromiumClientSession* session = key_value.second;
      if (destination.Equals(all_sessions_[session].destination()) &&
          session->CanPool(session_key.server_id().host(),
                           session_key.server_id().privacy_mode_enabled()
                               ? PRIVACY_MODE_ENABLED
                               : PRIVACY_MODE_DISABLED,
                           session_key.socket_tag(),
                           session_key.network_isolation_key())) {
        request->SetSession(session->CreateHandle(destination));
        return OK;
      }
    }
  }

  // TODO(rtenneti): |task_runner_| is used by the Job. Initialize task_runner_
  // in the constructor after WebRequestActionWithThreadsTest.* tests are fixed.
  if (!task_runner_)
    task_runner_ = base::ThreadTaskRunnerHandle::Get().get();

  if (!tick_clock_)
    tick_clock_ = base::DefaultTickClock::GetInstance();

  ignore_result(
      StartCertVerifyJob(session_key.server_id(), cert_verify_flags, net_log));

  QuicSessionAliasKey key(destination, session_key);
  std::unique_ptr<Job> job =
      std::make_unique<Job>(this, quic_version, host_resolver_, key,
                            WasQuicRecentlyBroken(session_key),
                            params_.retry_on_alternate_network_before_handshake,
                            params_.race_stale_dns_on_connection, priority,
                            cert_verify_flags, net_log);
  int rv = job->Run(base::BindOnce(&QuicStreamFactory::OnJobComplete,
                                   base::Unretained(this), job.get()));
  if (rv == ERR_IO_PENDING) {
    job->AddRequest(request);
    active_jobs_[session_key] = std::move(job);
    return rv;
  }
  if (rv == OK) {
    // TODO(rtenneti): crbug.com/498823 - revert active_sessions_.empty()
    // related changes.
    if (active_sessions_.empty())
      return ERR_QUIC_PROTOCOL_ERROR;
    auto it = active_sessions_.find(session_key);
    DCHECK(it != active_sessions_.end());
    if (it == active_sessions_.end())
      return ERR_QUIC_PROTOCOL_ERROR;
    QuicChromiumClientSession* session = it->second;
    request->SetSession(session->CreateHandle(destination));
  }
  return rv;
}

QuicStreamFactory::QuicSessionAliasKey::QuicSessionAliasKey(
    const HostPortPair& destination,
    const QuicSessionKey& session_key)
    : destination_(destination), session_key_(session_key) {}

bool QuicStreamFactory::QuicSessionAliasKey::operator<(
    const QuicSessionAliasKey& other) const {
  return std::tie(destination_, session_key_) <
         std::tie(other.destination_, other.session_key_);
}

bool QuicStreamFactory::QuicSessionAliasKey::operator==(
    const QuicSessionAliasKey& other) const {
  return destination_.Equals(other.destination_) &&
         session_key_ == other.session_key_;
}

size_t QuicStreamFactory::QuicSessionAliasKey::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(destination_) +
         base::trace_event::EstimateMemoryUsage(session_key_.server_id());
}

bool QuicStreamFactory::HasMatchingIpSession(const QuicSessionAliasKey& key,
                                             const AddressList& address_list) {
  const quic::QuicServerId& server_id(key.server_id());
  DCHECK(!HasActiveSession(key.session_key()));
  for (const IPEndPoint& address : address_list) {
    if (!base::Contains(ip_aliases_, address))
      continue;

    const SessionSet& sessions = ip_aliases_[address];
    for (QuicChromiumClientSession* session : sessions) {
      if (!session->CanPool(server_id.host(), key.session_key().privacy_mode(),
                            key.session_key().socket_tag(),
                            key.session_key().network_isolation_key())) {
        continue;
      }
      active_sessions_[key.session_key()] = session;
      session_aliases_[session].insert(key);
      return true;
    }
  }
  return false;
}

void QuicStreamFactory::OnJobComplete(Job* job, int rv) {
  auto iter = active_jobs_.find(job->key().session_key());
  DCHECK(iter != active_jobs_.end());
  if (rv == OK) {
    set_require_confirmation(false);

    auto session_it = active_sessions_.find(job->key().session_key());
    CHECK(session_it != active_sessions_.end());
    QuicChromiumClientSession* session = session_it->second;
    for (auto* request : iter->second->stream_requests()) {
      // Do not notify |request| yet.
      request->SetSession(session->CreateHandle(job->key().destination()));
    }
  }

  for (auto* request : iter->second->stream_requests()) {
    // Even though we're invoking callbacks here, we don't need to worry
    // about |this| being deleted, because the factory is owned by the
    // profile which can not be deleted via callbacks.
    if (rv < 0) {
      job->PopulateNetErrorDetails(request->net_error_details());
    }
    request->OnRequestComplete(rv);
  }
  active_jobs_.erase(iter);
}

void QuicStreamFactory::OnCertVerifyJobComplete(CertVerifierJob* job, int rv) {
  active_cert_verifier_jobs_.erase(job->server_id());
}

void QuicStreamFactory::OnSessionGoingAway(QuicChromiumClientSession* session) {
  const AliasSet& aliases = session_aliases_[session];
  for (auto it = aliases.begin(); it != aliases.end(); ++it) {
    const QuicSessionKey& session_key = it->session_key();
    DCHECK(active_sessions_.count(session_key));
    DCHECK_EQ(session, active_sessions_[session_key]);
    // Track sessions which have recently gone away so that we can disable
    // port suggestions.
    if (session->goaway_received())
      gone_away_aliases_.insert(*it);

    active_sessions_.erase(session_key);
    ProcessGoingAwaySession(session, session_key.server_id(), true);
  }
  ProcessGoingAwaySession(session, all_sessions_[session].server_id(), false);
  if (!aliases.empty()) {
    DCHECK(base::Contains(session_peer_ip_, session));
    const IPEndPoint peer_address = session_peer_ip_[session];
    ip_aliases_[peer_address].erase(session);
    if (ip_aliases_[peer_address].empty())
      ip_aliases_.erase(peer_address);
    session_peer_ip_.erase(session);
  }
  session_aliases_.erase(session);
}

void QuicStreamFactory::OnSessionClosed(QuicChromiumClientSession* session) {
  DCHECK_EQ(0u, session->GetNumActiveStreams());
  OnSessionGoingAway(session);

  for (const auto& iter : active_jobs_) {
    if (iter.first == session->quic_session_key()) {
      iter.second->OnSessionClosed(session);
    }
  }
  delete session;
  all_sessions_.erase(session);
}

void QuicStreamFactory::OnBlackholeAfterHandshakeConfirmed(
    QuicChromiumClientSession* session) {
  // Reduce PING timeout when connection blackholes after the handshake.
  if (ping_timeout_ > reduced_ping_timeout_)
    ping_timeout_ = reduced_ping_timeout_;
}

void QuicStreamFactory::CancelRequest(QuicStreamRequest* request) {
  auto job_iter = active_jobs_.find(request->session_key());
  CHECK(job_iter != active_jobs_.end());
  job_iter->second->RemoveRequest(request);
}

void QuicStreamFactory::SetRequestPriority(QuicStreamRequest* request,
                                           RequestPriority priority) {
  auto job_iter = active_jobs_.find(request->session_key());
  if (job_iter == active_jobs_.end())
    return;
  job_iter->second->SetPriority(priority);
}

void QuicStreamFactory::CloseAllSessions(int error,
                                         quic::QuicErrorCode quic_error) {
  base::UmaHistogramSparse("Net.QuicSession.CloseAllSessionsError", -error);
  while (!active_sessions_.empty()) {
    size_t initial_size = active_sessions_.size();
    active_sessions_.begin()->second->CloseSessionOnError(
        error, quic_error,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    DCHECK_NE(initial_size, active_sessions_.size());
  }
  while (!all_sessions_.empty()) {
    size_t initial_size = all_sessions_.size();
    all_sessions_.begin()->first->CloseSessionOnError(
        error, quic_error,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    DCHECK_NE(initial_size, all_sessions_.size());
  }
  DCHECK(all_sessions_.empty());
}

std::unique_ptr<base::Value> QuicStreamFactory::QuicStreamFactoryInfoToValue()
    const {
  std::unique_ptr<base::ListValue> list(new base::ListValue());

  for (auto it = active_sessions_.begin(); it != active_sessions_.end(); ++it) {
    const quic::QuicServerId& server_id = it->first.server_id();
    QuicChromiumClientSession* session = it->second;
    const AliasSet& aliases = session_aliases_.find(session)->second;
    // Only add a session to the list once.
    if (server_id == aliases.begin()->server_id()) {
      std::set<HostPortPair> hosts;
      for (auto alias_it = aliases.begin(); alias_it != aliases.end();
           ++alias_it) {
        hosts.insert(HostPortPair(alias_it->server_id().host(),
                                  alias_it->server_id().port()));
      }
      list->Append(session->GetInfoAsValue(hosts));
    }
  }
  return std::move(list);
}

void QuicStreamFactory::ClearCachedStatesInCryptoConfig(
    const base::Callback<bool(const GURL&)>& origin_filter) {
  ServerIdOriginFilter filter(origin_filter);
  crypto_config_.ClearCachedStates(filter);
}

void QuicStreamFactory::OnIPAddressChanged() {
  LogPlatformNotificationInHistogram(NETWORK_IP_ADDRESS_CHANGED);
  // Do nothing if connection migration is turned on.
  if (params_.migrate_sessions_on_network_change_v2)
    return;

  set_require_confirmation(true);
  if (params_.close_sessions_on_ip_change) {
    CloseAllSessions(ERR_NETWORK_CHANGED, quic::QUIC_IP_ADDRESS_CHANGED);
  } else {
    DCHECK(params_.goaway_sessions_on_ip_change);
    MarkAllActiveSessionsGoingAway();
  }
}

void QuicStreamFactory::OnNetworkConnected(NetworkHandle network) {
  LogPlatformNotificationInHistogram(NETWORK_CONNECTED);
  if (!params_.migrate_sessions_on_network_change_v2)
    return;

  ScopedConnectionMigrationEventLog scoped_event_log(net_log_,
                                                     "OnNetworkConnected");
  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the map.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->first;
    ++it;
    session->OnNetworkConnected(network, scoped_event_log.net_log());
  }
}

void QuicStreamFactory::OnNetworkMadeDefault(NetworkHandle network) {
  LogPlatformNotificationInHistogram(NETWORK_MADE_DEFAULT);
  if (!params_.migrate_sessions_on_network_change_v2)
    return;

  // Clear alternative services that were marked as broken until default network
  // changes.
  if (params_.retry_on_alternate_network_before_handshake &&
      default_network_ != NetworkChangeNotifier::kInvalidNetworkHandle &&
      network != default_network_) {
    http_server_properties_->OnDefaultNetworkChanged();
  }

  DCHECK_NE(NetworkChangeNotifier::kInvalidNetworkHandle, network);
  default_network_ = network;
  ScopedConnectionMigrationEventLog scoped_event_log(net_log_,
                                                     "OnNetworkMadeDefault");

  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the map.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->first;
    ++it;
    session->OnNetworkMadeDefault(network, scoped_event_log.net_log());
  }
  set_require_confirmation(true);
}

void QuicStreamFactory::OnNetworkDisconnected(NetworkHandle network) {
  LogPlatformNotificationInHistogram(NETWORK_DISCONNECTED);
  if (!params_.migrate_sessions_on_network_change_v2)
    return;

  ScopedConnectionMigrationEventLog scoped_event_log(net_log_,
                                                     "OnNetworkDisconnected");
  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the map.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->first;
    ++it;
    session->OnNetworkDisconnectedV2(/*disconnected_network*/ network,
                                     scoped_event_log.net_log());
  }
}

// This method is expected to only be called when migrating from Cellular to
// WiFi on Android, and should always be preceded by OnNetworkMadeDefault().
void QuicStreamFactory::OnNetworkSoonToDisconnect(NetworkHandle network) {
  LogPlatformNotificationInHistogram(NETWORK_SOON_TO_DISCONNECT);
}

NetworkHandle QuicStreamFactory::FindAlternateNetwork(
    NetworkHandle old_network) {
  // Find a new network that sessions bound to |old_network| can be migrated to.
  NetworkChangeNotifier::NetworkList network_list;
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  for (NetworkHandle new_network : network_list) {
    if (new_network != old_network)
      return new_network;
  }
  return NetworkChangeNotifier::kInvalidNetworkHandle;
}

std::unique_ptr<DatagramClientSocket> QuicStreamFactory::CreateSocket(
    NetLog* net_log,
    const NetLogSource& source) {
  auto socket = client_socket_factory_->CreateDatagramClientSocket(
      DatagramSocket::DEFAULT_BIND, net_log, source);
  if (params_.enable_socket_recv_optimization)
    socket->EnableRecvOptimization();
  return socket;
}

void QuicStreamFactory::OnCertDBChanged() {
  // We should flush the sessions if we removed trust from a
  // cert, because a previously trusted server may have become
  // untrusted.
  //
  // We should not flush the sessions if we added trust to a cert.
  //
  // Since the OnCertDBChanged method doesn't tell us what
  // kind of change it is, we have to flush the socket
  // pools to be safe.
  MarkAllActiveSessionsGoingAway();
}

bool QuicStreamFactory::HasActiveSession(
    const QuicSessionKey& session_key) const {
  // TODO(rtenneti): crbug.com/498823 - delete active_sessions_.empty() check.
  if (active_sessions_.empty())
    return false;
  return base::Contains(active_sessions_, session_key);
}

bool QuicStreamFactory::HasActiveJob(const QuicSessionKey& session_key) const {
  return base::Contains(active_jobs_, session_key);
}

bool QuicStreamFactory::HasActiveCertVerifierJob(
    const quic::QuicServerId& server_id) const {
  return base::Contains(active_cert_verifier_jobs_, server_id);
}

int QuicStreamFactory::ConfigureSocket(DatagramClientSocket* socket,
                                       IPEndPoint addr,
                                       NetworkHandle network,
                                       const SocketTag& socket_tag) {
  socket->UseNonBlockingIO();

  int rv;
  if (params_.migrate_sessions_on_network_change_v2) {
    // If caller leaves network unspecified, use current default network.
    if (network == NetworkChangeNotifier::kInvalidNetworkHandle) {
      rv = socket->ConnectUsingDefaultNetwork(addr);
    } else {
      rv = socket->ConnectUsingNetwork(network, addr);
    }
  } else {
    rv = socket->Connect(addr);
  }
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_CONNECTING_SOCKET);
    return rv;
  }

  socket->ApplySocketTag(socket_tag);

  rv = socket->SetReceiveBufferSize(kQuicSocketReceiveBufferSize);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_RECEIVE_BUFFER);
    return rv;
  }

  rv = socket->SetDoNotFragment();
  // SetDoNotFragment is not implemented on all platforms, so ignore errors.
  if (rv != OK && rv != ERR_NOT_IMPLEMENTED) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_DO_NOT_FRAGMENT);
    return rv;
  }

  // Set a buffer large enough to contain the initial CWND's worth of packet
  // to work around the problem with CHLO packets being sent out with the
  // wrong encryption level, when the send buffer is full.
  rv = socket->SetSendBufferSize(quic::kMaxOutgoingPacketSize * 20);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_SEND_BUFFER);
    return rv;
  }

  socket->GetLocalAddress(&local_address_);
  if (need_to_check_persisted_supports_quic_) {
    need_to_check_persisted_supports_quic_ = false;
    IPAddress last_address;
    if (http_server_properties_->GetSupportsQuic(&last_address) &&
        last_address == local_address_.address()) {
      require_confirmation_ = false;
      // Clear the persisted IP address, in case the network no longer supports
      // QUIC so the next restart will require confirmation. It will be
      // re-persisted when the first job completes successfully.
      http_server_properties_->SetSupportsQuic(false, last_address);
    }
  }

  return OK;
}

int QuicStreamFactory::CreateSession(
    const QuicSessionAliasKey& key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    const AddressList& address_list,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    const NetLogWithSource& net_log,
    QuicChromiumClientSession** session,
    NetworkChangeNotifier::NetworkHandle* network) {
  TRACE_EVENT0(NetTracingCategory(), "QuicStreamFactory::CreateSession");
  IPEndPoint addr = *address_list.begin();
  const quic::QuicServerId& server_id = key.server_id();
  std::unique_ptr<DatagramClientSocket> socket(
      CreateSocket(net_log.net_log(), net_log.source()));

  // Passing in kInvalidNetworkHandle binds socket to default network.
  int rv = ConfigureSocket(socket.get(), addr, *network,
                           key.session_key().socket_tag());
  if (rv != OK)
    return rv;

  if (params_.migrate_sessions_on_network_change_v2 &&
      *network == NetworkChangeNotifier::kInvalidNetworkHandle) {
    *network = socket->GetBoundNetwork();
    if (default_network_ == NetworkChangeNotifier::kInvalidNetworkHandle) {
      // QuicStreamFactory may miss the default network signal before its
      // creation, update |default_network_| when the first socket is bound
      // to the default network.
      default_network_ = *network;
    } else {
      UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.DefaultNetworkMatch",
                            default_network_ == *network);
    }
  }

  if (!helper_.get()) {
    helper_.reset(new QuicChromiumConnectionHelper(clock_, random_generator_));
  }

  if (!alarm_factory_.get()) {
    alarm_factory_.reset(new QuicChromiumAlarmFactory(
        base::ThreadTaskRunnerHandle::Get().get(), clock_));
  }

  quic::QuicConnectionId connection_id =
      quic::QuicUtils::CreateRandomConnectionId(random_generator_);
  std::unique_ptr<QuicServerInfo> server_info;
  if (params_.max_server_configs_stored_in_properties > 0) {
    server_info = std::make_unique<PropertiesBasedQuicServerInfo>(
        server_id, http_server_properties_);
  }
  InitializeCachedStateInCryptoConfig(server_id, server_info, &connection_id);

  QuicChromiumPacketWriter* writer =
      new QuicChromiumPacketWriter(socket.get(), task_runner_);
  quic::QuicConnection* connection = new quic::QuicConnection(
      connection_id, ToQuicSocketAddress(addr), helper_.get(),
      alarm_factory_.get(), writer, true /* owns_writer */,
      quic::Perspective::IS_CLIENT, {quic_version});
  connection->set_ping_timeout(ping_timeout_);
  connection->SetMaxPacketLength(params_.max_packet_length);

  quic::QuicConfig config = config_;
  config.set_max_undecryptable_packets(kMaxUndecryptablePackets);
  config.SetInitialSessionFlowControlWindowToSend(
      kQuicSessionMaxRecvWindowSize);
  config.SetInitialStreamFlowControlWindowToSend(kQuicStreamMaxRecvWindowSize);
  config.SetBytesForConnectionIdToSend(0);
  ConfigureInitialRttEstimate(
      server_id, key.session_key().network_isolation_key(), &config);
  if (quic_version.transport_version <= quic::QUIC_VERSION_43 &&
      !config.HasClientSentConnectionOption(quic::kNSTP,
                                            quic::Perspective::IS_CLIENT)) {
    // Enable the no stop waiting frames connection option by default.
    quic::QuicTagVector connection_options = config.SendConnectionOptions();
    connection_options.push_back(quic::kNSTP);
    config.SetConnectionOptionsToSend(connection_options);
  }

  // Use the factory to create a new socket performance watcher, and pass the
  // ownership to QuicChromiumClientSession.
  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher;
  if (socket_performance_watcher_factory_) {
    socket_performance_watcher =
        socket_performance_watcher_factory_->CreateSocketPerformanceWatcher(
            SocketPerformanceWatcherFactory::PROTOCOL_QUIC, address_list);
  }

  // Wait for handshake confirmation before allowing streams to be created if
  // either this session or the factory require confirmation.
  if (require_confirmation_)
    require_confirmation = true;

  *session = new QuicChromiumClientSession(
      connection, std::move(socket), this, quic_crypto_client_stream_factory_,
      clock_, transport_security_state_, ssl_config_service_,
      std::move(server_info), key.session_key(), require_confirmation,
      params_.max_allowed_push_id, params_.migrate_sessions_early_v2,
      params_.migrate_sessions_on_network_change_v2, default_network_,
      retransmittable_on_wire_timeout_, params_.migrate_idle_sessions,
      params_.allow_port_migration, params_.idle_session_migration_period,
      params_.max_time_on_non_default_network,
      params_.max_migrations_to_non_default_network_on_write_error,
      params_.max_migrations_to_non_default_network_on_path_degrading,
      yield_after_packets_, yield_after_duration_,
      params_.go_away_on_path_degrading,
      params_.headers_include_h2_stream_dependency, cert_verify_flags, config,
      &crypto_config_, network_connection_.connection_description(),
      dns_resolution_start_time, dns_resolution_end_time, &push_promise_index_,
      push_delegate_, tick_clock_, task_runner_,
      std::move(socket_performance_watcher), net_log.net_log());

  all_sessions_[*session] = key;  // owning pointer
  writer->set_delegate(*session);

  (*session)->Initialize();
  bool closed_during_initialize = !base::Contains(all_sessions_, *session) ||
                                  !(*session)->connection()->connected();
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedDuringInitializeSession",
                        closed_during_initialize);
  if (closed_during_initialize) {
    DLOG(DFATAL) << "Session closed during initialize";
    *session = nullptr;
    return ERR_CONNECTION_CLOSED;
  }
  if (connection->version().KnowsWhichDecrypterToUse()) {
    connection->InstallDecrypter(quic::ENCRYPTION_FORWARD_SECURE,
                                 quic::QuicMakeUnique<quic::NullDecrypter>(
                                     quic::Perspective::IS_CLIENT));
  }
  return OK;
}

void QuicStreamFactory::ActivateSession(const QuicSessionAliasKey& key,
                                        QuicChromiumClientSession* session) {
  DCHECK(!HasActiveSession(key.session_key()));
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicActiveSessions", active_sessions_.size());
  active_sessions_[key.session_key()] = session;
  session_aliases_[session].insert(key);
  const IPEndPoint peer_address =
      ToIPEndPoint(session->connection()->peer_address());
  DCHECK(!base::Contains(ip_aliases_[peer_address], session));
  ip_aliases_[peer_address].insert(session);
  DCHECK(!base::Contains(session_peer_ip_, session));
  session_peer_ip_[session] = peer_address;
}

void QuicStreamFactory::ConfigureInitialRttEstimate(
    const quic::QuicServerId& server_id,
    const NetworkIsolationKey& network_isolation_key,
    quic::QuicConfig* config) {
  const base::TimeDelta* srtt =
      GetServerNetworkStatsSmoothedRtt(server_id, network_isolation_key);
  if (srtt != nullptr) {
    SetInitialRttEstimate(*srtt, INITIAL_RTT_CACHED, config);
    return;
  }

  NetworkChangeNotifier::ConnectionType type =
      network_connection_.connection_type();
  if (type == NetworkChangeNotifier::CONNECTION_2G) {
    SetInitialRttEstimate(base::TimeDelta::FromMilliseconds(1200),
                          INITIAL_RTT_CACHED, config);
    return;
  }

  if (type == NetworkChangeNotifier::CONNECTION_3G) {
    SetInitialRttEstimate(base::TimeDelta::FromMilliseconds(400),
                          INITIAL_RTT_CACHED, config);
    return;
  }

  if (params_.initial_rtt_for_handshake > base::TimeDelta()) {
    SetInitialRttEstimate(
        base::TimeDelta::FromMicroseconds(
            params_.initial_rtt_for_handshake.InMicroseconds()),
        INITIAL_RTT_DEFAULT, config);
    return;
  }

  SetInitialRttEstimate(base::TimeDelta(), INITIAL_RTT_DEFAULT, config);
}

const base::TimeDelta* QuicStreamFactory::GetServerNetworkStatsSmoothedRtt(
    const quic::QuicServerId& server_id,
    const NetworkIsolationKey& network_isolation_key) const {
  url::SchemeHostPort server("https", server_id.host(), server_id.port());
  const ServerNetworkStats* stats =
      http_server_properties_->GetServerNetworkStats(server,
                                                     network_isolation_key);
  if (stats == nullptr)
    return nullptr;
  return &(stats->srtt);
}

int64_t QuicStreamFactory::GetServerNetworkStatsSmoothedRttInMicroseconds(
    const quic::QuicServerId& server_id,
    const NetworkIsolationKey& network_isolation_key) const {
  const base::TimeDelta* srtt =
      GetServerNetworkStatsSmoothedRtt(server_id, network_isolation_key);
  return srtt == nullptr ? 0 : srtt->InMicroseconds();
}

bool QuicStreamFactory::WasQuicRecentlyBroken(
    const QuicSessionKey& session_key) const {
  const AlternativeService alternative_service(
      kProtoQUIC, HostPortPair(session_key.server_id().host(),
                               session_key.server_id().port()));
  return http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, session_key.network_isolation_key());
}

bool QuicStreamFactory::CryptoConfigCacheIsEmpty(
    const quic::QuicServerId& server_id) {
  quic::QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id);
  return cached->IsEmpty();
}

quic::QuicAsyncStatus QuicStreamFactory::StartCertVerifyJob(
    const quic::QuicServerId& server_id,
    int cert_verify_flags,
    const NetLogWithSource& net_log) {
  if (!params_.race_cert_verification)
    return quic::QUIC_FAILURE;
  quic::QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id);
  if (!cached || cached->certs().empty() ||
      HasActiveCertVerifierJob(server_id)) {
    return quic::QUIC_FAILURE;
  }
  std::unique_ptr<CertVerifierJob> cert_verifier_job(
      new CertVerifierJob(server_id, cert_verify_flags, net_log));
  quic::QuicAsyncStatus status = cert_verifier_job->Run(
      &crypto_config_,
      base::BindOnce(&QuicStreamFactory::OnCertVerifyJobComplete,
                     base::Unretained(this), cert_verifier_job.get()));
  if (status == quic::QUIC_PENDING)
    active_cert_verifier_jobs_[server_id] = std::move(cert_verifier_job);
  return status;
}

void QuicStreamFactory::InitializeCachedStateInCryptoConfig(
    const quic::QuicServerId& server_id,
    const std::unique_ptr<QuicServerInfo>& server_info,
    quic::QuicConnectionId* connection_id) {
  quic::QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id);
  if (cached->has_server_designated_connection_id())
    *connection_id = cached->GetNextServerDesignatedConnectionId();

  if (!cached->IsEmpty()) {
    return;
  }

  if (!server_info || !server_info->Load()) {
    return;
  }

  cached->Initialize(server_info->state().server_config,
                     server_info->state().source_address_token,
                     server_info->state().certs, server_info->state().cert_sct,
                     server_info->state().chlo_hash,
                     server_info->state().server_config_sig, clock_->WallNow(),
                     quic::QuicWallTime::Zero());
}

void QuicStreamFactory::ProcessGoingAwaySession(
    QuicChromiumClientSession* session,
    const quic::QuicServerId& server_id,
    bool session_was_active) {
  if (!http_server_properties_)
    return;

  const quic::QuicConnectionStats& stats = session->connection()->GetStats();
  const AlternativeService alternative_service(
      kProtoQUIC, HostPortPair(server_id.host(), server_id.port()));

  url::SchemeHostPort server("https", server_id.host(), server_id.port());
  // Do nothing if QUIC is currently marked as broken.
  if (http_server_properties_->IsAlternativeServiceBroken(
          alternative_service,
          session->quic_session_key().network_isolation_key())) {
    return;
  }

  if (session->IsCryptoHandshakeConfirmed()) {
    http_server_properties_->ConfirmAlternativeService(
        alternative_service,
        session->quic_session_key().network_isolation_key());
    ServerNetworkStats network_stats;
    network_stats.srtt = base::TimeDelta::FromMicroseconds(stats.srtt_us);
    network_stats.bandwidth_estimate = stats.estimated_bandwidth;
    http_server_properties_->SetServerNetworkStats(
        server, session->quic_session_key().network_isolation_key(),
        network_stats);
    return;
  }

  http_server_properties_->ClearServerNetworkStats(
      server, session->quic_session_key().network_isolation_key());

  UMA_HISTOGRAM_COUNTS_1M("Net.QuicHandshakeNotConfirmedNumPacketsReceived",
                          stats.packets_received);

  if (!session_was_active)
    return;

  // TODO(rch):  In the special case where the session has received no packets
  // from the peer, we should consider blocking this differently so that we
  // still race TCP but we don't consider the session connected until the
  // handshake has been confirmed.
  HistogramBrokenAlternateProtocolLocation(
      BROKEN_ALTERNATE_PROTOCOL_LOCATION_QUIC_STREAM_FACTORY);

  // Since the session was active, there's no longer an HttpStreamFactory::Job
  // running which can mark it broken, unless the TCP job also fails. So to
  // avoid not using QUIC when we otherwise could, we mark it as recently
  // broken, which means that 0-RTT will be disabled but we'll still race.
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service, session->quic_session_key().network_isolation_key());
}

}  // namespace net
