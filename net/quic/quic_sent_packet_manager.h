// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_
#define NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_

#include <deque>
#include <list>
#include <map>
#include <queue>
#include <set>
#include <utility>
#include <vector>

#include "base/containers/hash_tables.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_ack_notifier_manager.h"
#include "net/quic/quic_protocol.h"

NET_EXPORT_PRIVATE extern bool FLAGS_track_retransmission_history;
NET_EXPORT_PRIVATE extern bool FLAGS_limit_rto_increase_for_tests;
NET_EXPORT_PRIVATE extern bool FLAGS_enable_quic_pacing;

namespace net {

namespace test {
class QuicConnectionPeer;
class QuicSentPacketManagerPeer;
}  // namespace test

class QuicClock;
class QuicConfig;

// Class which tracks the set of packets sent on a QUIC connection and contains
// a send algorithm to decide when to send new packets.  It keeps track of any
// retransmittable data associated with each packet. If a packet is
// retransmitted, it will keep track of each version of a packet so that if a
// previous transmission is acked, the data will not be retransmitted.
class NET_EXPORT_PRIVATE QuicSentPacketManager {
 public:
  // Struct to store the pending retransmission information.
  struct PendingRetransmission {
    PendingRetransmission(QuicPacketSequenceNumber sequence_number,
                          TransmissionType transmission_type,
                          const RetransmittableFrames& retransmittable_frames,
                          QuicSequenceNumberLength sequence_number_length)
            : sequence_number(sequence_number),
              transmission_type(transmission_type),
              retransmittable_frames(retransmittable_frames),
              sequence_number_length(sequence_number_length) {
        }

        QuicPacketSequenceNumber sequence_number;
        TransmissionType transmission_type;
        const RetransmittableFrames& retransmittable_frames;
        QuicSequenceNumberLength sequence_number_length;
  };

  // Interface which provides callbacks that the manager needs.
  class NET_EXPORT_PRIVATE HelperInterface {
   public:
    virtual ~HelperInterface();

    // Called to return the sequence number of the next packet to be sent.
    virtual QuicPacketSequenceNumber GetNextPacketSequenceNumber() = 0;
  };

  QuicSentPacketManager(bool is_server,
                        HelperInterface* helper,
                        const QuicClock* clock,
                        CongestionFeedbackType congestion_type);
  virtual ~QuicSentPacketManager();

  virtual void SetFromConfig(const QuicConfig& config);

  virtual void SetMaxPacketSize(QuicByteCount max_packet_size);

  // Called when a new packet is serialized.  If the packet contains
  // retransmittable data, it will be added to the unacked packet map.
  void OnSerializedPacket(const SerializedPacket& serialized_packet,
                          QuicTime serialized_time);

  // Called when a packet is retransmitted with a new sequence number.
  // Replaces the old entry in the unacked packet map with the new
  // sequence number.
  void OnRetransmittedPacket(QuicPacketSequenceNumber old_sequence_number,
                             QuicPacketSequenceNumber new_sequence_number);

  // Processes the ReceivedPacketInfo data from the incoming ack.
  void OnPacketAcked(const ReceivedPacketInfo& received_info);

  // Discards any information for the packet corresponding to |sequence_number|.
  // If this packet has been retransmitted, information on those packets
  // will be discarded as well.
  void DiscardUnackedPacket(QuicPacketSequenceNumber sequence_number);

  // Discards all information about fec packet |sequence_number|.
  void DiscardFecPacket(QuicPacketSequenceNumber sequence_number);

  // Returns true if |sequence_number| is a retransmission of a packet.
  bool IsRetransmission(QuicPacketSequenceNumber sequence_number) const;

  // Returns true if the non-FEC packet |sequence_number| is unacked.
  bool IsUnacked(QuicPacketSequenceNumber sequence_number) const;

  // Returns true if the FEC packet |sequence_number| is unacked.
  bool IsFecUnacked(QuicPacketSequenceNumber sequence_number) const;

  // Returns true if the unacked packet |sequence_number| has retransmittable
  // frames.  This will only return false if the packet has been acked, if a
  // previous transmission of this packet was ACK'd, or if this packet has been
  // retransmitted as with different sequence number.
  bool HasRetransmittableFrames(QuicPacketSequenceNumber sequence_number) const;

  // Returns the RetransmittableFrames for |sequence_number|.
  const RetransmittableFrames& GetRetransmittableFrames(
      QuicPacketSequenceNumber sequence_number) const;

  // Request that |sequence_number| be retransmitted after the other pending
  // retransmissions.  Returns false if there are no retransmittable frames for
  // |sequence_number| and true if it will be retransmitted.
  bool MarkForRetransmission(QuicPacketSequenceNumber sequence_number,
                             TransmissionType transmission_type);

  // Returns true if there are pending retransmissions.
  bool HasPendingRetransmissions() const;

  // Retrieves the next pending retransmission.
  PendingRetransmission NextPendingRetransmission();

  // Returns the time the fec packet was sent.
  QuicTime GetFecSentTime(QuicPacketSequenceNumber sequence_number) const;

  // Returns true if there are any unacked packets.
  bool HasUnackedPackets() const;

  // Returns the number of unacked packets which have retransmittable frames.
  size_t GetNumRetransmittablePackets() const;

  // Returns true if there are any unacked FEC packets.
  bool HasUnackedFecPackets() const;

  // Returns the smallest sequence number of a sent packet which has not been
  // acked by the peer.  Excludes any packets which have been retransmitted
  // with a new sequence number. If all packets have been acked, returns the
  // sequence number of the next packet that will be sent.
  QuicPacketSequenceNumber GetLeastUnackedSentPacket() const;

  // Returns the smallest sequence number of a sent fec packet which has not
  // been acked by the peer.  If all packets have been acked, returns the
  // sequence number of the next packet that will be sent.
  QuicPacketSequenceNumber GetLeastUnackedFecPacket() const;

  // Returns the set of sequence numbers of all unacked packets.
  SequenceNumberSet GetUnackedPackets() const;

  // Returns true if |sequence_number| is a previous transmission of packet.
  bool IsPreviousTransmission(QuicPacketSequenceNumber sequence_number) const;

  // TODO(ianswett): Combine the congestion control related methods below with
  // some of the methods above and cleanup the resulting code.
  // Called when we have received an ack frame from peer.
  // Returns a set containing all the sequence numbers to be nack retransmitted
  // as a result of the ack.
  virtual SequenceNumberSet OnIncomingAckFrame(const QuicAckFrame& frame,
                                               QuicTime ack_receive_time);

  // Called when a congestion feedback frame is received from peer.
  virtual void OnIncomingQuicCongestionFeedbackFrame(
      const QuicCongestionFeedbackFrame& frame,
      QuicTime feedback_receive_time);

  // Called when we have sent bytes to the peer.  This informs the manager both
  // the number of bytes sent and if they were retransmitted.
  virtual void OnPacketSent(QuicPacketSequenceNumber sequence_number,
                            QuicTime sent_time,
                            QuicByteCount bytes,
                            TransmissionType transmission_type,
                            HasRetransmittableData has_retransmittable_data);

  // Called when the retransmission timer expires.
  virtual void OnRetransmissionTimeout();

  // Called when the least unacked sequence number increases, indicating the
  // consecutive rto count should be reset to 0.
  virtual void OnLeastUnackedIncreased();

  // Called when a packet is timed out, such as an RTO.  Removes the bytes from
  // the congestion manager, but does not change the congestion window size.
  virtual void OnPacketAbandoned(QuicPacketSequenceNumber sequence_number);

  // Calculate the time until we can send the next packet to the wire.
  // Note 1: When kUnknownWaitTime is returned, there is no need to poll
  // TimeUntilSend again until we receive an OnIncomingAckFrame event.
  // Note 2: Send algorithms may or may not use |retransmit| in their
  // calculations.
  virtual QuicTime::Delta TimeUntilSend(QuicTime now,
                                        TransmissionType transmission_type,
                                        HasRetransmittableData retransmittable,
                                        IsHandshake handshake);

  const QuicTime::Delta DefaultRetransmissionTime();

  // Returns amount of time for delayed ack timer.
  const QuicTime::Delta DelayedAckTime();

  // Returns the current RTO delay.
  const QuicTime::Delta GetRetransmissionDelay() const;

  // Returns the estimated smoothed RTT calculated by the congestion algorithm.
  const QuicTime::Delta SmoothedRtt() const;

  // Returns the estimated bandwidth calculated by the congestion algorithm.
  QuicBandwidth BandwidthEstimate() const;

  // Returns the size of the current congestion window in bytes.  Note, this is
  // not the *available* window.  Some send algorithms may not use a congestion
  // window and will return 0.
  QuicByteCount GetCongestionWindow() const;

  // Sets the value of the current congestion window to |window|.
  void SetCongestionWindow(QuicByteCount window);

  // Enables pacing if it has not already been enabled, and if
  // FLAGS_enable_quic_pacing is set.
  void MaybeEnablePacing();

  bool using_pacing() const { return using_pacing_; }


 private:
  friend class test::QuicConnectionPeer;
  friend class test::QuicSentPacketManagerPeer;

  struct TransmissionInfo {
    TransmissionInfo() {}
    TransmissionInfo(RetransmittableFrames* retransmittable_frames,
                     QuicSequenceNumberLength sequence_number_length)
        : retransmittable_frames(retransmittable_frames),
          sequence_number_length(sequence_number_length) {
    }

    RetransmittableFrames* retransmittable_frames;
    QuicSequenceNumberLength sequence_number_length;
  };

  typedef linked_hash_map<QuicPacketSequenceNumber,
                          TransmissionInfo> UnackedPacketMap;
  typedef linked_hash_map<QuicPacketSequenceNumber,
                          QuicTime> UnackedFecPacketMap;
  typedef linked_hash_map<QuicPacketSequenceNumber,
                          TransmissionType> PendingRetransmissionMap;
  typedef base::hash_map<QuicPacketSequenceNumber, SequenceNumberSet*>
                         PreviousTransmissionMap;

  // Process the incoming ack looking for newly ack'd data packets.
  void HandleAckForSentPackets(const ReceivedPacketInfo& received_info);

  // Process the incoming ack looking for newly ack'd FEC packets.
  void HandleAckForSentFecPackets(const ReceivedPacketInfo& received_info);

  // Marks |sequence_number| as having been seen by the peer.  Returns an
  // iterator to the next remaining unacked packet.
  UnackedPacketMap::iterator MarkPacketReceivedByPeer(
      QuicPacketSequenceNumber sequence_number);

  // Simply removes the entries, if any, from the unacked packet map
  // and the retransmission map.
  void DiscardPacket(QuicPacketSequenceNumber sequence_number);

  // Returns the length of the serialized sequence number for
  // the packet |sequence_number|.
  QuicSequenceNumberLength GetSequenceNumberLength(
      QuicPacketSequenceNumber sequence_number) const;

  // Returns the sequence number of the packet that |sequence_number| was
  // most recently transmitted as.
  QuicPacketSequenceNumber GetMostRecentTransmission(
      QuicPacketSequenceNumber sequence_number) const;

  void CleanupPacketHistory();

  // When new packets are created which may be retransmitted, they are added
  // to this map, which contains owning pointers to the contained frames.  If
  // a packet is retransmitted, this map will contain entries for both the old
  // and the new packet.  The old packet's retransmittable frames entry will be
  // NULL, while the new packet's entry will contain the frames to retransmit.
  // If the old packet is acked before the new packet, then the old entry will
  // be removed from the map and the new entry's retransmittable frames will be
  // set to NULL.
  UnackedPacketMap unacked_packets_;

  // Pending fec packets that have not been acked yet. These packets need to be
  // cleared out of the cgst_window after a timeout since FEC packets are never
  // retransmitted.
  UnackedFecPacketMap unacked_fec_packets_;

  // Pending retransmissions which have not been packetized and sent yet.
  PendingRetransmissionMap pending_retransmissions_;

  // Map from sequence number to set of all sequence number that this packet has
  // been transmitted as.  If a packet has not been retransmitted, it will not
  // have an entry in this map.  If any transmission of a packet has been acked
  // it will not have an entry in this map.
  PreviousTransmissionMap previous_transmissions_map_;

  // Tracks if the connection was created by the server.
  bool is_server_;

  HelperInterface* helper_;

  // An AckNotifier can register to be informed when ACKs have been received for
  // all packets that a given block of data was sent in. The AckNotifierManager
  // maintains the currently active notifiers.
  AckNotifierManager ack_notifier_manager_;

  const QuicClock* clock_;
  scoped_ptr<SendAlgorithmInterface> send_algorithm_;
  // Tracks the send time, size, and nack count of sent packets.  Packets are
  // removed after 5 seconds and they've been removed from pending_packets_.
  SendAlgorithmInterface::SentPacketsMap packet_history_map_;
  // Packets that are outstanding and have not been abandoned or lost.
  SequenceNumberSet pending_packets_;
  QuicTime::Delta rtt_sample_;  // RTT estimate from the most recent ACK.
  // Number of times the RTO timer has fired in a row without receiving an ack.
  size_t consecutive_rto_count_;
  bool using_pacing_;

  DISALLOW_COPY_AND_ASSIGN(QuicSentPacketManager);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SENT_PACKET_MANAGER_H_
