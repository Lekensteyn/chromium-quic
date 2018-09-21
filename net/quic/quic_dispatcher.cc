// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_dispatcher.h"

#include <errno.h>

#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/quic_blocked_writer_interface.h"
#include "net/quic/quic_connection_helper.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_time_wait_list_manager.h"
#include "net/quic/quic_utils.h"

namespace net {

using base::StringPiece;
using std::make_pair;
using std::find;

class DeleteSessionsAlarm : public QuicAlarm::Delegate {
 public:
  explicit DeleteSessionsAlarm(QuicDispatcher* dispatcher)
      : dispatcher_(dispatcher) {
  }

  virtual QuicTime OnAlarm() OVERRIDE {
    dispatcher_->DeleteSessions();
    return QuicTime::Zero();
  }

 private:
  QuicDispatcher* dispatcher_;
};

class QuicDispatcher::QuicFramerVisitor : public QuicFramerVisitorInterface {
 public:
  explicit QuicFramerVisitor(QuicDispatcher* dispatcher)
      : dispatcher_(dispatcher),
        connection_id_(0) {}

  // QuicFramerVisitorInterface implementation
  virtual void OnPacket() OVERRIDE {}
  virtual bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header) OVERRIDE {
    connection_id_ = header.connection_id;
    return dispatcher_->OnUnauthenticatedPublicHeader(header);
  }
  virtual bool OnUnauthenticatedHeader(
      const QuicPacketHeader& header) OVERRIDE {
    dispatcher_->OnUnauthenticatedHeader(header);
    return false;
  }
  virtual void OnError(QuicFramer* framer) OVERRIDE {
    DVLOG(1) << QuicUtils::ErrorToString(framer->error());
  }

  virtual bool OnProtocolVersionMismatch(
      QuicVersion /*received_version*/) OVERRIDE {
    if (dispatcher_->time_wait_list_manager()->IsConnectionIdInTimeWait(
            connection_id_)) {
      // Keep processing after protocol mismatch - this will be dealt with by
      // the TimeWaitListManager.
      return true;
    } else {
      DLOG(DFATAL) << "Version mismatch, connection ID (" << connection_id_
                   << ") not in time wait list.";
      return false;
    }
  }

  // The following methods should never get called because we always return
  // false from OnUnauthenticatedHeader().  As a result, we never process the
  // payload of the packet.
  virtual void OnPublicResetPacket(
      const QuicPublicResetPacket& /*packet*/) OVERRIDE {
    DCHECK(false);
  }
  virtual void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& /*packet*/) OVERRIDE {
    DCHECK(false);
  }
  virtual void OnDecryptedPacket(EncryptionLevel level) OVERRIDE {
    DCHECK(false);
  }
  virtual bool OnPacketHeader(const QuicPacketHeader& /*header*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual void OnRevivedPacket() OVERRIDE {
    DCHECK(false);
  }
  virtual void OnFecProtectedPayload(StringPiece /*payload*/) OVERRIDE {
    DCHECK(false);
  }
  virtual bool OnStreamFrame(const QuicStreamFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnAckFrame(const QuicAckFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnCongestionFeedbackFrame(
      const QuicCongestionFeedbackFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnStopWaitingFrame(
      const QuicStopWaitingFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnPingFrame(const QuicPingFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnConnectionCloseFrame(
      const QuicConnectionCloseFrame & /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& /*frame*/)
      OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual bool OnBlockedFrame(const QuicBlockedFrame& frame) OVERRIDE {
    DCHECK(false);
    return false;
  }
  virtual void OnFecData(const QuicFecData& /*fec*/) OVERRIDE {
    DCHECK(false);
  }
  virtual void OnPacketComplete() OVERRIDE {
    DCHECK(false);
  }

 private:
  QuicDispatcher* dispatcher_;

  // Latched in OnUnauthenticatedPublicHeader for use later.
  QuicConnectionId connection_id_;
};

QuicDispatcher::QuicDispatcher(const QuicConfig& config,
                               const QuicCryptoServerConfig& crypto_config,
                               const QuicVersionVector& supported_versions,
                               QuicConnectionHelperInterface* helper)
    : config_(config),
      crypto_config_(crypto_config),
      helper_(helper),
      delete_sessions_alarm_(
          helper_->CreateAlarm(new DeleteSessionsAlarm(this))),
      supported_versions_(supported_versions),
      current_packet_(NULL),
      framer_(supported_versions, /*unused*/ QuicTime::Zero(), true),
      framer_visitor_(new QuicFramerVisitor(this)) {
  framer_.set_visitor(framer_visitor_.get());
}

QuicDispatcher::~QuicDispatcher() {
  STLDeleteValues(&session_map_);
  STLDeleteElements(&closed_session_list_);
}

void QuicDispatcher::Initialize(QuicServerPacketWriter* writer) {
  DCHECK(writer_ == NULL);
  writer_.reset(writer);
  time_wait_list_manager_.reset(CreateQuicTimeWaitListManager());
}

void QuicDispatcher::ProcessPacket(const IPEndPoint& server_address,
                                   const IPEndPoint& client_address,
                                   const QuicEncryptedPacket& packet) {
  current_server_address_ = server_address;
  current_client_address_ = client_address;
  current_packet_ = &packet;
  // ProcessPacket will cause the packet to be dispatched in
  // OnUnauthenticatedPublicHeader, or sent to the time wait list manager
  // in OnAuthenticatedHeader.
  framer_.ProcessPacket(packet);
  // TODO(rjshade): Return a status describing if/why a packet was dropped,
  //                and log somehow.  Maybe expose as a varz.
}

bool QuicDispatcher::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) {
  QuicSession* session = NULL;

  QuicConnectionId connection_id = header.connection_id;
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    if (header.reset_flag) {
      return false;
    }
    if (time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id)) {
      return HandlePacketForTimeWait(header);
    }

    // Ensure the packet has a version negotiation bit set before creating a new
    // session for it.  All initial packets for a new connection are required to
    // have the flag set.  Otherwise it may be a stray packet.
    if (header.version_flag) {
      session = CreateQuicSession(connection_id, current_server_address_,
                                  current_client_address_);
    }

    if (session == NULL) {
      DVLOG(1) << "Failed to create session for " << connection_id;
      // Add this connection_id fo the time-wait state, to safely reject future
      // packets.

      if (header.version_flag &&
          !framer_.IsSupportedVersion(header.versions.front())) {
        // TODO(ianswett): Produce a no-version version negotiation packet.
        return false;
      }

      // Use the version in the packet if possible, otherwise assume the latest.
      QuicVersion version = header.version_flag ? header.versions.front() :
          supported_versions_.front();
      time_wait_list_manager_->AddConnectionIdToTimeWait(
          connection_id, version, NULL);
      DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
      return HandlePacketForTimeWait(header);
    }
    DVLOG(1) << "Created new session for " << connection_id;
    session_map_.insert(make_pair(connection_id, session));
  } else {
    session = it->second;
  }

  session->connection()->ProcessUdpPacket(
      current_server_address_, current_client_address_, *current_packet_);

  // Do not parse the packet further.  The session will process it completely.
  return false;
}

void QuicDispatcher::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(
      header.public_header.connection_id));
  time_wait_list_manager_->ProcessPacket(current_server_address_,
                                         current_client_address_,
                                         header.public_header.connection_id,
                                         header.packet_sequence_number,
                                         *current_packet_);
}

void QuicDispatcher::CleanUpSession(SessionMap::iterator it) {
  QuicConnection* connection = it->second->connection();
  QuicEncryptedPacket* connection_close_packet =
      connection->ReleaseConnectionClosePacket();
  write_blocked_list_.erase(connection);
  time_wait_list_manager_->AddConnectionIdToTimeWait(it->first,
                                                     connection->version(),
                                                     connection_close_packet);
  session_map_.erase(it);
}

void QuicDispatcher::DeleteSessions() {
  STLDeleteElements(&closed_session_list_);
}

void QuicDispatcher::OnCanWrite() {
  // We finished a write: the socket should not be blocked.
  writer_->SetWritable();

  // Give all the blocked writers one chance to write, until we're blocked again
  // or there's no work left.
  while (!write_blocked_list_.empty() && !writer_->IsWriteBlocked()) {
    QuicBlockedWriterInterface* blocked_writer =
        write_blocked_list_.begin()->first;
    write_blocked_list_.erase(write_blocked_list_.begin());
    blocked_writer->OnCanWrite();
  }
}

bool QuicDispatcher::HasPendingWrites() const {
  return !write_blocked_list_.empty();
}

void QuicDispatcher::Shutdown() {
  while (!session_map_.empty()) {
    QuicSession* session = session_map_.begin()->second;
    session->connection()->SendConnectionClose(QUIC_PEER_GOING_AWAY);
    // Validate that the session removes itself from the session map on close.
    DCHECK(session_map_.empty() || session_map_.begin()->second != session);
  }
  DeleteSessions();
}

void QuicDispatcher::OnConnectionClosed(QuicConnectionId connection_id,
                                        QuicErrorCode error) {
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    LOG(DFATAL) << "ConnectionId " << connection_id
                << " does not exist in the session map.  "
                << "Error: " << QuicUtils::ErrorToString(error);
    LOG(DFATAL) << base::debug::StackTrace().ToString();
    return;
  }
  DVLOG_IF(1, error != QUIC_NO_ERROR) << "Closing connection ("
                                      << connection_id
                                      << ") due to error: "
                                      << QuicUtils::ErrorToString(error);
  if (closed_session_list_.empty()) {
    delete_sessions_alarm_->Set(helper_->GetClock()->ApproximateNow());
  }
  closed_session_list_.push_back(it->second);
  CleanUpSession(it);
}

void QuicDispatcher::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  if (!writer_->IsWriteBlocked()) {
    LOG(DFATAL) <<
        "QuicDispatcher::OnWriteBlocked called when the writer is not blocked.";
    // Return without adding the connection to the blocked list, to avoid
    // infinite loops in OnCanWrite.
    return;
  }
  write_blocked_list_.insert(make_pair(blocked_writer, true));
}

QuicSession* QuicDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const IPEndPoint& server_address,
    const IPEndPoint& client_address) {
  QuicPerConnectionPacketWriter* per_connection_packet_writer =
      new QuicPerConnectionPacketWriter(writer_.get());
  QuicConnection* connection =
      CreateQuicConnection(connection_id,
                           server_address,
                           client_address,
                           per_connection_packet_writer);
  QuicServerSession* session = new QuicServerSession(
      config_,
      connection,
      per_connection_packet_writer,
      this);
  session->InitializeSession(crypto_config_);
  return session;
}

QuicConnection* QuicDispatcher::CreateQuicConnection(
    QuicConnectionId connection_id,
    const IPEndPoint& server_address,
    const IPEndPoint& client_address,
    QuicPerConnectionPacketWriter* writer) {
  QuicConnection* connection;
  connection = new QuicConnection(
      connection_id,
      client_address,
      helper_,
      writer,
      false  /* owns_writer */,
      true   /* is_server */,
      supported_versions_);
  writer->set_connection(connection);
  return connection;
}

QuicTimeWaitListManager* QuicDispatcher::CreateQuicTimeWaitListManager() {
  return new QuicTimeWaitListManager(
      writer_.get(), this, helper_, supported_versions());
}

bool QuicDispatcher::HandlePacketForTimeWait(
    const QuicPacketPublicHeader& header) {
  if (header.reset_flag) {
    // Public reset packets do not have sequence numbers, so ignore the packet.
    return false;
  }

  // Switch the framer to the correct version, so that the sequence number can
  // be parsed correctly.
  framer_.set_version(time_wait_list_manager_->GetQuicVersionFromConnectionId(
      header.connection_id));

  // Continue parsing the packet to extract the sequence number.  Then
  // send it to the time wait manager in OnUnathenticatedHeader.
  return true;
}

}  // namespace net
