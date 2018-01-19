// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A QuicSession, which demuxes a single connection to individual streams.

#ifndef NET_QUIC_CORE_QUIC_SESSION_H_
#define NET_QUIC_CORE_QUIC_SESSION_H_

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/int128.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_crypto_stream.h"
#include "net/quic/core/quic_packet_creator.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/core/quic_stream_frame_data_producer.h"
#include "net/quic/core/quic_write_blocked_list.h"
#include "net/quic/core/session_notifier_interface.h"
#include "net/quic/platform/api/quic_containers.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_socket_address.h"

namespace net {

class QuicCryptoStream;
class QuicFlowController;
class QuicStream;

namespace test {
class QuicSessionPeer;
}  // namespace test

class QUIC_EXPORT_PRIVATE QuicSession : public QuicConnectionVisitorInterface,
                                        public SessionNotifierInterface,
                                        public QuicStreamFrameDataProducer {
 public:
  // An interface from the session to the entity owning the session.
  // This lets the session notify its owner (the Dispatcher) when the connection
  // is closed, blocked, or added/removed from the time-wait list.
  class Visitor {
   public:
    virtual ~Visitor() {}

    // Called when the connection is closed after the streams have been closed.
    virtual void OnConnectionClosed(QuicConnectionId connection_id,
                                    QuicErrorCode error,
                                    const std::string& error_details) = 0;

    // Called when the session has become write blocked.
    virtual void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) = 0;

    // Called when the session receives reset on a stream from the peer.
    virtual void OnRstStreamReceived(const QuicRstStreamFrame& frame) = 0;
  };

  // CryptoHandshakeEvent enumerates the events generated by a QuicCryptoStream.
  enum CryptoHandshakeEvent {
    // ENCRYPTION_FIRST_ESTABLISHED indicates that a full client hello has been
    // sent by a client and that subsequent packets will be encrypted. (Client
    // only.)
    ENCRYPTION_FIRST_ESTABLISHED,
    // ENCRYPTION_REESTABLISHED indicates that a client hello was rejected by
    // the server and thus the encryption key has been updated. Therefore the
    // connection should resend any packets that were sent under
    // ENCRYPTION_INITIAL. (Client only.)
    ENCRYPTION_REESTABLISHED,
    // HANDSHAKE_CONFIRMED, in a client, indicates the the server has accepted
    // our handshake. In a server it indicates that a full, valid client hello
    // has been received. (Client and server.)
    HANDSHAKE_CONFIRMED,
  };

  // Does not take ownership of |connection| or |visitor|.
  QuicSession(QuicConnection* connection,
              Visitor* owner,
              const QuicConfig& config);

  ~QuicSession() override;

  virtual void Initialize();

  // QuicConnectionVisitorInterface methods:
  void OnStreamFrame(const QuicStreamFrame& frame) override;
  void OnRstStream(const QuicRstStreamFrame& frame) override;
  void OnGoAway(const QuicGoAwayFrame& frame) override;
  void OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
  void OnBlockedFrame(const QuicBlockedFrame& frame) override;
  void OnConnectionClosed(QuicErrorCode error,
                          const std::string& error_details,
                          ConnectionCloseSource source) override;
  void OnWriteBlocked() override;
  void OnSuccessfulVersionNegotiation(
      const QuicTransportVersion& version) override;
  void OnConnectivityProbeReceived(
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address) override;
  void OnCanWrite() override;
  void OnCongestionWindowChange(QuicTime /*now*/) override {}
  void OnConnectionMigration(PeerAddressChangeType type) override {}
  // Deletes streams that are safe to be deleted now that it's safe to do so (no
  // other operations are being done on the streams at this time).
  void PostProcessAfterData() override;
  // Adds a connection level WINDOW_UPDATE frame.
  void OnAckNeedsRetransmittableFrame() override;
  bool WillingAndAbleToWrite() const override;
  bool HasPendingHandshake() const override;
  bool HasOpenDynamicStreams() const override;
  void OnPathDegrading() override;
  bool AllowSelfAddressChange() const override;

  // QuicStreamFrameDataProducer
  bool WriteStreamData(QuicStreamId id,
                       QuicStreamOffset offset,
                       QuicByteCount data_length,
                       QuicDataWriter* writer) override;

  // SessionNotifierInterface methods:
  void OnFrameAcked(const QuicFrame& frame,
                    QuicTime::Delta ack_delay_time) override;
  void OnStreamFrameRetransmitted(const QuicStreamFrame& frame) override;
  void OnFrameLost(const QuicFrame& frame) override;

  // Called on every incoming packet. Passes |packet| through to |connection_|.
  virtual void ProcessUdpPacket(const QuicSocketAddress& self_address,
                                const QuicSocketAddress& peer_address,
                                const QuicReceivedPacket& packet);

  // Called by streams when they want to write data to the peer.
  // Returns a pair with the number of bytes consumed from data, and a boolean
  // indicating if the fin bit was consumed.  This does not indicate the data
  // has been sent on the wire: it may have been turned into a packet and queued
  // if the socket was unexpectedly blocked.
  virtual QuicConsumedData WritevData(QuicStream* stream,
                                      QuicStreamId id,
                                      size_t write_length,
                                      QuicStreamOffset offset,
                                      StreamSendingState state);

  // Called by streams when they want to close the stream in both directions.
  virtual void SendRstStream(QuicStreamId id,
                             QuicRstStreamErrorCode error,
                             QuicStreamOffset bytes_written);

  // Called when the session wants to go away and not accept any new streams.
  void SendGoAway(QuicErrorCode error_code, const std::string& reason);

  // Removes the stream associated with 'stream_id' from the active stream map.
  virtual void CloseStream(QuicStreamId stream_id);

  // Returns true if outgoing packets will be encrypted, even if the server
  // hasn't confirmed the handshake yet.
  virtual bool IsEncryptionEstablished() const;

  // For a client, returns true if the server has confirmed our handshake. For
  // a server, returns true if a full, valid client hello has been received.
  virtual bool IsCryptoHandshakeConfirmed() const;

  // Called by the QuicCryptoStream when a new QuicConfig has been negotiated.
  virtual void OnConfigNegotiated();

  // Called by the QuicCryptoStream when the handshake enters a new state.
  //
  // Clients will call this function in the order:
  //   ENCRYPTION_FIRST_ESTABLISHED
  //   zero or more ENCRYPTION_REESTABLISHED
  //   HANDSHAKE_CONFIRMED
  //
  // Servers will simply call it once with HANDSHAKE_CONFIRMED.
  virtual void OnCryptoHandshakeEvent(CryptoHandshakeEvent event);

  // Called by the QuicCryptoStream when a handshake message is sent.
  virtual void OnCryptoHandshakeMessageSent(
      const CryptoHandshakeMessage& message);

  // Called by the QuicCryptoStream when a handshake message is received.
  virtual void OnCryptoHandshakeMessageReceived(
      const CryptoHandshakeMessage& message);

  // Returns mutable config for this session. Returned config is owned
  // by QuicSession.
  QuicConfig* config();

  // Returns true if the stream existed previously and has been closed.
  // Returns false if the stream is still active or if the stream has
  // not yet been created.
  bool IsClosedStream(QuicStreamId id);

  QuicConnection* connection() { return connection_; }
  const QuicConnection* connection() const { return connection_; }
  size_t num_active_requests() const { return dynamic_stream_map_.size(); }
  const QuicSocketAddress& peer_address() const {
    return connection_->peer_address();
  }
  const QuicSocketAddress& self_address() const {
    return connection_->self_address();
  }
  QuicConnectionId connection_id() const {
    return connection_->connection_id();
  }

  // Returns the number of currently open streams, excluding the reserved
  // headers and crypto streams, and never counting unfinished streams.
  size_t GetNumActiveStreams() const;

  // Returns the number of currently open peer initiated streams, excluding the
  // reserved headers and crypto streams.
  size_t GetNumOpenIncomingStreams() const;

  // Returns the number of currently open self initiated streams, excluding the
  // reserved headers and crypto streams.
  size_t GetNumOpenOutgoingStreams() const;

  // Returns the number of "available" streams, the stream ids less than
  // largest_peer_created_stream_id_ that have not yet been opened.
  size_t GetNumAvailableStreams() const;

  // Add the stream to the session's write-blocked list because it is blocked by
  // connection-level flow control but not by its own stream-level flow control.
  // The stream will be given a chance to write when a connection-level
  // WINDOW_UPDATE arrives.
  void MarkConnectionLevelWriteBlocked(QuicStreamId id);

  // Called when stream |id| is done waiting for acks either because all data
  // gets acked or is not interested in data being acked (which happens when
  // a stream is reset because of an error).
  void OnStreamDoneWaitingForAcks(QuicStreamId id);

  // Called to cancel retransmission of unencypted crypto stream data.
  void NeuterUnencryptedData();

  // Returns true if the session has data to be sent, either queued in the
  // connection, or in a write-blocked stream.
  bool HasDataToWrite() const;

  bool goaway_sent() const { return goaway_sent_; }

  bool goaway_received() const { return goaway_received_; }

  QuicErrorCode error() const { return error_; }

  Perspective perspective() const { return connection_->perspective(); }

  QuicFlowController* flow_controller() { return &flow_controller_; }

  // Returns true if connection is flow controller blocked.
  bool IsConnectionFlowControlBlocked() const;

  // Returns true if any stream is flow controller blocked.
  bool IsStreamFlowControlBlocked();

  size_t max_open_incoming_streams() const {
    return max_open_incoming_streams_;
  }

  size_t max_open_outgoing_streams() const {
    return max_open_outgoing_streams_;
  }

  size_t MaxAvailableStreams() const;

  // Returns existing static or dynamic stream with id = |stream_id|. If no
  // such stream exists, and |stream_id| is a peer-created dynamic stream id,
  // then a new stream is created and returned. In all other cases, nullptr is
  // returned.
  QuicStream* GetOrCreateStream(const QuicStreamId stream_id);

  // Mark a stream as draining.
  virtual void StreamDraining(QuicStreamId id);

  // Returns true if this stream should yield writes to another blocked stream.
  bool ShouldYield(QuicStreamId stream_id);

  // Called to cancel retransmission of unencrypted stream data.
  void NeuterUnencryptedStreamData();

  bool can_use_slices() const { return can_use_slices_; }

  bool allow_multiple_acks_for_data() const {
    return allow_multiple_acks_for_data_;
  }

  bool session_unblocks_stream() const { return session_unblocks_stream_; }

 protected:
  using StaticStreamMap = QuicSmallMap<QuicStreamId, QuicStream*, 2>;

  using DynamicStreamMap =
      QuicSmallMap<QuicStreamId, std::unique_ptr<QuicStream>, 10>;

  using ClosedStreams = std::vector<std::unique_ptr<QuicStream>>;

  using ZombieStreamMap =
      QuicSmallMap<QuicStreamId, std::unique_ptr<QuicStream>, 10>;

  // Creates a new stream to handle a peer-initiated stream.
  // Caller does not own the returned stream.
  // Returns nullptr and does error handling if the stream can not be created.
  virtual QuicStream* CreateIncomingDynamicStream(QuicStreamId id) = 0;

  // Create a new stream to handle a locally-initiated stream.
  // Caller does not own the returned stream.
  // Returns nullptr if max streams have already been opened.
  virtual QuicStream* CreateOutgoingDynamicStream() = 0;

  // Return the reserved crypto stream.
  virtual QuicCryptoStream* GetMutableCryptoStream() = 0;

  // Return the reserved crypto stream as a constant pointer.
  virtual const QuicCryptoStream* GetCryptoStream() const = 0;

  // Adds |stream| to the dynamic stream map.
  virtual void ActivateStream(std::unique_ptr<QuicStream> stream);

  // Returns the stream ID for a new outgoing stream, and increments the
  // underlying counter.
  QuicStreamId GetNextOutgoingStreamId();

  // Returns existing stream with id = |stream_id|. If no such stream exists,
  // and |stream_id| is a peer-created id, then a new stream is created and
  // returned. However if |stream_id| is a locally-created id and no such stream
  // exists, the connection is closed.
  // Caller does not own the returned stream.
  QuicStream* GetOrCreateDynamicStream(QuicStreamId stream_id);

  // Performs the work required to close |stream_id|.  If |locally_reset|
  // then the stream has been reset by this endpoint, not by the peer.
  virtual void CloseStreamInner(QuicStreamId stream_id, bool locally_reset);

  // When a stream is closed locally, it may not yet know how many bytes the
  // peer sent on that stream.
  // When this data arrives (via stream frame w. FIN, trailing headers, or RST)
  // this method is called, and correctly updates the connection level flow
  // controller.
  virtual void OnFinalByteOffsetReceived(QuicStreamId id,
                                         QuicStreamOffset final_byte_offset);

  // Return true if given stream is peer initiated.
  bool IsIncomingStream(QuicStreamId id) const;

  StaticStreamMap& static_streams() { return static_stream_map_; }
  const StaticStreamMap& static_streams() const { return static_stream_map_; }

  DynamicStreamMap& dynamic_streams() { return dynamic_stream_map_; }
  const DynamicStreamMap& dynamic_streams() const {
    return dynamic_stream_map_;
  }

  ClosedStreams* closed_streams() { return &closed_streams_; }

  const ZombieStreamMap& zombie_streams() const { return zombie_streams_; }

  void set_max_open_incoming_streams(size_t max_open_incoming_streams);
  void set_max_open_outgoing_streams(size_t max_open_outgoing_streams);

  void set_largest_peer_created_stream_id(
      QuicStreamId largest_peer_created_stream_id) {
    largest_peer_created_stream_id_ = largest_peer_created_stream_id;
  }
  void set_error(QuicErrorCode error) { error_ = error; }
  QuicWriteBlockedList* write_blocked_streams() {
    return &write_blocked_streams_;
  }

  size_t GetNumDynamicOutgoingStreams() const;

  size_t GetNumDrainingOutgoingStreams() const;

  size_t num_locally_closed_incoming_streams_highest_offset() const {
    return num_locally_closed_incoming_streams_highest_offset_;
  }

  size_t GetNumLocallyClosedOutgoingStreamsHighestOffset() const;

  // Returns true if the stream is still active.
  bool IsOpenStream(QuicStreamId id);

  QuicStreamId next_outgoing_stream_id() const {
    return next_outgoing_stream_id_;
  }

  // Close connection when receive a frame for a locally-created nonexistant
  // stream.
  // Prerequisite: IsClosedStream(stream_id) == false
  // Server session might need to override this method to allow server push
  // stream to be promised before creating an active stream.
  virtual void HandleFrameOnNonexistentOutgoingStream(QuicStreamId stream_id);

  bool MaybeIncreaseLargestPeerStreamId(const QuicStreamId stream_id);

  void InsertLocallyClosedStreamsHighestOffset(const QuicStreamId id,
                                               QuicStreamOffset offset);
  // If stream is a locally closed stream, this RST will update FIN offset.
  // Otherwise stream is a preserved stream and the behavior of it depends on
  // derived class's own implementation.
  virtual void HandleRstOnValidNonexistentStream(
      const QuicRstStreamFrame& frame);

  // Returns a stateless reset token which will be included in the public reset
  // packet.
  virtual uint128 GetStatelessResetToken() const;

 private:
  friend class test::QuicSessionPeer;

  // Called in OnConfigNegotiated when we receive a new stream level flow
  // control window in a negotiated config. Closes the connection if invalid.
  void OnNewStreamFlowControlWindow(QuicStreamOffset new_window);

  // Called in OnConfigNegotiated when we receive a new connection level flow
  // control window in a negotiated config. Closes the connection if invalid.
  void OnNewSessionFlowControlWindow(QuicStreamOffset new_window);

  // Debug helper for |OnCanWrite()|, check that OnStreamWrite() makes
  // forward progress.  Returns false if busy loop detected.
  bool CheckStreamNotBusyLooping(QuicStream* stream,
                                 uint64_t previous_bytes_written,
                                 bool previous_fin_sent);

  // Called in OnConfigNegotiated for Finch trials to measure performance of
  // starting with larger flow control receive windows.
  void AdjustInitialFlowControlWindows(size_t stream_window);

  // Find stream with |id|, returns nullptr if the stream does not exist or
  // closed.
  QuicStream* GetStream(QuicStreamId id) const;

  // Let streams retransmit lost data, returns true if all lost data is
  // retransmitted. Returns false otherwise.
  bool RetransmitLostStreamData();

  // Keep track of highest received byte offset of locally closed streams, while
  // waiting for a definitive final highest offset from the peer.
  std::map<QuicStreamId, QuicStreamOffset>
      locally_closed_streams_highest_offset_;

  QuicConnection* connection_;

  // May be null.
  Visitor* visitor_;

  ClosedStreams closed_streams_;

  // Streams which are closed, but need to be kept alive. Currently, the only
  // reason is the stream's sent data (including FIN) does not get fully acked.
  ZombieStreamMap zombie_streams_;

  QuicConfig config_;

  // The maximum number of outgoing streams this connection can open.
  size_t max_open_outgoing_streams_;

  // The maximum number of incoming streams this connection will allow.
  size_t max_open_incoming_streams_;

  // Static streams, such as crypto and header streams. Owned by child classes
  // that create these streams.
  StaticStreamMap static_stream_map_;

  // Map from StreamId to pointers to streams. Owns the streams.
  DynamicStreamMap dynamic_stream_map_;

  // The ID to use for the next outgoing stream.
  QuicStreamId next_outgoing_stream_id_;

  // Set of stream ids that are less than the largest stream id that has been
  // received, but are nonetheless available to be created.
  QuicUnorderedSet<QuicStreamId> available_streams_;

  // Set of stream ids that are "draining" -- a FIN has been sent and received,
  // but the stream object still exists because not all the received data has
  // been consumed.
  QuicUnorderedSet<QuicStreamId> draining_streams_;

  // A list of streams which need to write more data.
  QuicWriteBlockedList write_blocked_streams_;

  QuicStreamId largest_peer_created_stream_id_;

  // A counter for peer initiated streams which are in the dynamic_stream_map_.
  size_t num_dynamic_incoming_streams_;

  // A counter for peer initiated streams which are in the draining_streams_.
  size_t num_draining_incoming_streams_;

  // A counter for peer initiated streams which are in the
  // locally_closed_streams_highest_offset_.
  size_t num_locally_closed_incoming_streams_highest_offset_;

  // The latched error with which the connection was closed.
  QuicErrorCode error_;

  // Used for connection-level flow control.
  QuicFlowController flow_controller_;

  // The stream id which was last popped in OnCanWrite, or 0, if not under the
  // call stack of OnCanWrite.
  QuicStreamId currently_writing_stream_id_;

  // Whether a GoAway has been sent.
  bool goaway_sent_;

  // Whether a GoAway has been received.
  bool goaway_received_;

  // QUIC stream can take ownership of application data provided in reference
  // counted memory to avoid data copy.
  const bool can_use_slices_;

  // Latched value of quic_reloadable_flag_quic_allow_multiple_acks_for_data2.
  const bool allow_multiple_acks_for_data_;

  // TODO(fayang): switch to linked_hash_set when chromium supports it. The bool
  // is not used here.
  // List of streams with pending retransmissions.
  QuicLinkedHashMap<QuicStreamId, bool> streams_with_pending_retransmission_;

  // Latched value of quic_reloadable_flag_quic_streams_unblocked_by_session.
  const bool session_unblocks_stream_;

  DISALLOW_COPY_AND_ASSIGN(QuicSession);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_SESSION_H_
