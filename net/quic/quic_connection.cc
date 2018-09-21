// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection.h"

#include "base/logging.h"
#include "base/stl_util.h"
#include "net/base/net_errors.h"
#include "net/quic/congestion_control/quic_receipt_metrics_collector.h"
#include "net/quic/congestion_control/quic_send_scheduler.h"
#include "net/quic/quic_utils.h"

using base::hash_map;
using base::hash_set;
using base::StringPiece;
using std::list;
using std::vector;
using std::set;

/*
DEFINE_int32(fake_packet_loss_percentage, 0,
            "The percentage of packets to drop.");
DEFINE_int32(negotiated_timeout_us, net::kDefaultTimeout,
             "The default timeout for connections being closed");
*/

namespace net {

// An arbitrary number we'll probably want to tune.
const size_t kMaxUnackedPackets = 5000u;

// The amount of time we wait before resending a packet.
const int64 kDefaultResendTimeMs = 500;

bool Near(QuicPacketSequenceNumber a, QuicPacketSequenceNumber b) {
  QuicPacketSequenceNumber delta = (a > b) ? a - b : b - a;
  return delta <= kMaxUnackedPackets;
}

QuicConnection::QuicConnection(QuicGuid guid,
                               IPEndPoint address,
                               QuicConnectionHelperInterface* helper)
    : helper_(helper),
      framer_(QuicDecrypter::Create(kNULL), QuicEncrypter::Create(kNULL)),
      clock_(helper->GetClock()),
      guid_(guid),
      peer_address_(address),
      largest_seen_packet_with_ack_(0),
      largest_seen_least_packet_awaiting_ack_(0),
      write_blocked_(false),
      packet_creator_(guid_, &framer_),
      timeout_us_(kDefaultTimeout),
      time_of_last_packet_us_(clock_->NowInUsec()),
      collector_(new QuicReceiptMetricsCollector(clock_, kFixRate)),
      scheduler_(new QuicSendScheduler(clock_, kFixRate)),
      connected_(true) {
  helper_->SetConnection(this);
  helper_->SetTimeoutAlarm(timeout_us_);
  framer_.set_visitor(this);
  memset(&last_header_, 0, sizeof(last_header_));
  outgoing_ack_.sent_info.least_unacked = 0;
  outgoing_ack_.received_info.largest_received = 0;
  outgoing_ack_.received_info.time_received = 0;
  outgoing_ack_.congestion_info.type = kNone;
  /*
  if (FLAGS_fake_packet_loss_percentage > 0) {
    int32 seed = RandomBase::WeakSeed32();
    LOG(INFO) << "Seeding packet loss with " << seed;
    random_.reset(new MTRandom(seed));
  }
  */
}

QuicConnection::~QuicConnection() {
  STLDeleteValues(&unacked_packets_);
  STLDeleteValues(&group_map_);
  // Queued packets that are not to be resent are owned
  // by the packet queue.
  for (QueuedPacketList::iterator q = queued_packets_.begin();
       q != queued_packets_.end(); ++q) {
    if (!q->resend) delete q->packet;
  }
}

void QuicConnection::OnError(QuicFramer* framer) {
  SendConnectionClose(framer->error());
}

void QuicConnection::OnPacket(const IPEndPoint& self_address,
                              const IPEndPoint& peer_address) {
  time_of_last_packet_us_ = clock_->NowInUsec();
  DVLOG(1) << "last packet: " << time_of_last_packet_us_;

  // TODO(alyssar, rch) handle migration!
  self_address_ = self_address;
  peer_address_ = peer_address;
}

void QuicConnection::OnRevivedPacket() {
}

bool QuicConnection::OnPacketHeader(const QuicPacketHeader& header) {
  if (!Near(header.packet_sequence_number,
            last_header_.packet_sequence_number)) {
    DLOG(INFO) << "Packet out of bounds.  Discarding";
    return false;
  }

  last_header_ = header;
  ReceivedPacketInfo info = outgoing_ack_.received_info;
  // If this packet has already been seen, or that the sender
  // has told us will not be resent, then stop processing the packet.
  if (header.packet_sequence_number <= info.largest_received &&
      info.missing_packets.count(header.packet_sequence_number) != 1) {
    return false;
  }
  return true;
}

void QuicConnection::OnFecProtectedPayload(StringPiece payload) {
  DCHECK_NE(0, last_header_.fec_group);
  QuicFecGroup* group = GetFecGroup();
  group->Update(last_header_, payload);
}

void QuicConnection::OnStreamFrame(const QuicStreamFrame& frame) {
  frames_.push_back(frame);
}

void QuicConnection::OnAckFrame(const QuicAckFrame& incoming_ack) {
  DVLOG(1) << "Ack packet: " << incoming_ack;

  if (last_header_.packet_sequence_number <= largest_seen_packet_with_ack_) {
    DLOG(INFO) << "Received an old ack frame: ignoring";
    return;
  }
  largest_seen_packet_with_ack_ = last_header_.packet_sequence_number;

  if (!ValidateAckFrame(incoming_ack)) {
    SendConnectionClose(QUIC_INVALID_ACK_DATA);
    return;
  }

  UpdatePacketInformationReceivedByPeer(incoming_ack);
  UpdatePacketInformationSentByPeer(incoming_ack);
  scheduler_->OnIncomingAckFrame(incoming_ack);
  // Now the we have received an ack, we might be able to send queued packets.
  if (!queued_packets_.empty()) {
    int delay = scheduler_->TimeUntilSend(false);
    if (delay == 0) {
      helper_->UnregisterSendAlarmIfRegistered();
      if (!write_blocked_) {
        OnCanWrite();
      }
    } else {
      helper_->SetSendAlarm(delay);
    }
  }
}

bool QuicConnection::ValidateAckFrame(const QuicAckFrame& incoming_ack) {
  if (incoming_ack.received_info.largest_received >
      packet_creator_.sequence_number()) {
    DLOG(ERROR) << "Client acked unsent packet";
    // We got an error for data we have not sent.  Error out.
    return false;
  }

  // We can't have too many missing or retransmitting packets, or our ack
  // frames go over kMaxPacketSize.
  DCHECK_LT(incoming_ack.received_info.missing_packets.size(),
            kMaxUnackedPackets);
  DCHECK_LT(incoming_ack.sent_info.non_retransmiting.size(),
            kMaxUnackedPackets);

  if (incoming_ack.sent_info.least_unacked != 0 &&
      incoming_ack.sent_info.least_unacked <
      largest_seen_least_packet_awaiting_ack_) {
    DLOG(INFO) << "Client sent low least_unacked";
    // We never process old ack frames, so this number should only increase.
    return false;
  }

  return true;
}

void QuicConnection::UpdatePacketInformationReceivedByPeer(
    const QuicAckFrame& incoming_ack) {
  QuicConnectionVisitorInterface::AckedPackets acked_packets;

  // For tracking the lowest unacked packet, pick one we have not sent yet.
  QuicPacketSequenceNumber lowest_unacked =
      packet_creator_.sequence_number() + 1;

  // If there's a packet between the next one we're sending and the
  // highest one the peer has seen, that's our new lowest unacked.
  if (incoming_ack.received_info.largest_received + 1 < lowest_unacked) {
    lowest_unacked = incoming_ack.received_info.largest_received + 1;
  }

  // Go through the packets we have not received an ack for and see if this
  // incoming_ack shows they've been seen by the peer.
  UnackedPacketMap::iterator it = unacked_packets_.begin();
  while (it != unacked_packets_.end()) {
    if ((it->first < incoming_ack.received_info.largest_received &&
         incoming_ack.received_info.missing_packets.find(it->first) ==
         incoming_ack.received_info.missing_packets.end()) ||
        it->first == incoming_ack.received_info.largest_received) {
      // This was either explicitly or implicitly acked.  Remove it from our
      // unacked packet list.
      DVLOG(1) << "Got an ack for " << it->first;
      // TODO(rch): This is inefficient and should be sped up.
      // The acked packet might be queued (if a resend had been attempted).
      for (QueuedPacketList::iterator q = queued_packets_.begin();
           q != queued_packets_.end(); ++q) {
        if (q->sequence_number == it->first) {
          queued_packets_.erase(q);
          break;
        }
      }
      delete it->second;
      UnackedPacketMap::iterator tmp_it = it;
      acked_packets.insert(it->first);
      ++tmp_it;
      unacked_packets_.erase(it);
      it = tmp_it;
    } else {
      // This is a packet which we planned on resending and has not been
      // seen at the time of this ack being sent out.  See if it's our new
      // lowest unacked packet.
      DVLOG(1) << "still missing " << it->first;
      if (it->first < lowest_unacked) {
        lowest_unacked = it->first;
      }
      ++it;
    }
  }
  if (acked_packets.size() > 0) {
    visitor_->OnAck(acked_packets);
  }

  // If we've gotten an ack for the lowest packet we were waiting on,
  // update that and the list of packets we advertise we will not resend.
  if (lowest_unacked > outgoing_ack_.sent_info.least_unacked) {
    SequenceSet* non_retrans = &outgoing_ack_.sent_info.non_retransmiting;
    // We don't need to advertise not-resending packets between the old
    // and new values.
    for (QuicPacketSequenceNumber i = outgoing_ack_.sent_info.least_unacked;
         i < lowest_unacked; ++i) {
      non_retrans->erase(i);
    }
    // If all packets we sent have been acked, use the special value of 0
    if (lowest_unacked > packet_creator_.sequence_number()) {
      lowest_unacked = 0;
      DCHECK_EQ(0u, non_retrans->size());
    }
    outgoing_ack_.sent_info.least_unacked = lowest_unacked;
  }
}

void QuicConnection::UpdatePacketInformationSentByPeer(
    const QuicAckFrame& incoming_ack) {
  // Iteratate through the packets which will the peer will not resend and
  // remove them from our missing list.
  hash_set<QuicPacketSequenceNumber>::const_iterator it =
      incoming_ack.sent_info.non_retransmiting.begin();
  while (it != incoming_ack.sent_info.non_retransmiting.end()) {
    outgoing_ack_.received_info.missing_packets.erase(*it);
    DVLOG(1) << "no longer expecting " << *it;
    ++it;
  }

  // Make sure we also don't expect any packets lower than the peer's
  // last-packet-awaiting-ack
  if (incoming_ack.sent_info.least_unacked >
      largest_seen_least_packet_awaiting_ack_) {
    for (QuicPacketSequenceNumber i = largest_seen_least_packet_awaiting_ack_;
         i < incoming_ack.sent_info.least_unacked;
         ++i) {
      outgoing_ack_.received_info.missing_packets.erase(i);
    }
    largest_seen_least_packet_awaiting_ack_ =
        incoming_ack.sent_info.least_unacked;
  }

  // Possibly close any FecGroups which are now irrelevant
  CloseFecGroupsBefore(incoming_ack.sent_info.least_unacked + 1);
}

void QuicConnection::OnFecData(const QuicFecData& fec) {
  DCHECK_NE(0, last_header_.fec_group);
  QuicFecGroup* group = GetFecGroup();
  group->UpdateFec(last_header_.packet_sequence_number, fec);
}

void QuicConnection::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  DLOG(INFO) << "Stream reset with error " << frame.error_code;
  visitor_->OnRstStream(frame);
}

void QuicConnection::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  DLOG(INFO) << "Connection closed with error " << frame.error_code;
  visitor_->ConnectionClose(frame.error_code, true);
  connected_ = false;
}

void QuicConnection::OnPacketComplete() {
  DLOG(INFO) << "Got packet " << last_header_.packet_sequence_number
             << " with " << frames_.size()
             << " frames for " << last_header_.guid;
  if (!last_packet_revived_) {
    collector_->RecordIncomingPacket(last_size_,
                                     last_header_.packet_sequence_number,
                                     clock_->NowInUsec(),
                                     last_packet_revived_);
  }

  if (frames_.size()) {
    // If there's data, pass it to the visitor and send out an ack.
    bool accepted = visitor_->OnPacket(self_address_, peer_address_,
                                       last_header_, frames_);
    if (accepted) {
      AckPacket(last_header_);
    } else {
      // Send an ack without changing our state.
      SendAck();
    }
    frames_.clear();
  } else {
    // If there was no data, still make sure we update our internal state.
    // AckPacket will not send an ack on the wire in this case.
    AckPacket(last_header_);
  }
}

size_t QuicConnection::SendStreamData(
    QuicStreamId id,
    StringPiece data,
    QuicStreamOffset offset,
    bool fin,
    QuicPacketSequenceNumber* last_packet) {
  vector<PacketPair> packets;
  packet_creator_.DataToStream(id, data, offset, fin, &packets);
  DCHECK_LT(0u, packets.size());

  for (size_t i = 0; i < packets.size(); ++i) {
    SendPacket(packets[i].first, packets[i].second, true, false);
    // TODO(alyssar) either only buffer this up if we send successfully,
    // and make the upper levels deal with backup, or handle backup here.
    unacked_packets_.insert(packets[i]);
  }

  if (last_packet != NULL) {
    *last_packet = packets[packets.size() - 1].first;
  }
  return data.size();
}

void QuicConnection::SendRstStream(QuicStreamId id,
                                   QuicErrorCode error,
                                   QuicStreamOffset offset) {
  PacketPair packetpair = packet_creator_.ResetStream(id, offset, error);

  SendPacket(packetpair.first, packetpair.second, true, false);
  unacked_packets_.insert(packetpair);
}

void QuicConnection::ProcessUdpPacket(const IPEndPoint& self_address,
                                      const IPEndPoint& peer_address,
                                      const QuicEncryptedPacket& packet) {
  last_packet_revived_ = false;
  last_size_ = packet.length();
  framer_.ProcessPacket(self_address, peer_address, packet);

  MaybeProcessRevivedPacket();
}

bool QuicConnection::OnCanWrite() {
  write_blocked_ = false;
  size_t num_queued_packets = queued_packets_.size() + 1;
  while (!write_blocked_ && !helper_->IsSendAlarmSet() &&
         !queued_packets_.empty()) {
    // Ensure that from one iteration of this loop to the next we
    // succeeded in sending a packet so we don't infinitely loop.
    // TODO(rch): clean up and close the connection if we really hit this.
    DCHECK_LT(queued_packets_.size(), num_queued_packets);
    num_queued_packets = queued_packets_.size();
    QueuedPacket p = queued_packets_.front();
    queued_packets_.pop_front();
    SendPacket(p.sequence_number, p.packet, p.resend, false);
  }
  return !write_blocked_;
}

void QuicConnection::AckPacket(const QuicPacketHeader& header) {
  QuicPacketSequenceNumber sequence_number = header.packet_sequence_number;
  if (sequence_number > outgoing_ack_.received_info.largest_received) {
    // We've got a new high sequence number.  Note any new intermediate missing
    // packets, and update the last_ack data.
    for (QuicPacketSequenceNumber i =
             outgoing_ack_.received_info.largest_received + 1;
         i < sequence_number; ++i) {
      DVLOG(1) << "missing " << i;
      outgoing_ack_.received_info.missing_packets.insert(i);
    }
    outgoing_ack_.received_info.largest_received = sequence_number;
    outgoing_ack_.received_info.time_received = clock_->NowInUsec();
  } else {
    // We've gotten one of the out of order packets - remove it from our
    // "missing packets" list.
    DVLOG(1) << "Removing "  << sequence_number << " from missing list";
    outgoing_ack_.received_info.missing_packets.erase(sequence_number);
  }
  // TODO(alyssar) delay sending until we have data, or enough time has elapsed.
  if (frames_.size() > 0) {
    SendAck();
  }
}

void QuicConnection::MaybeResendPacket(
    QuicPacketSequenceNumber sequence_number) {
  UnackedPacketMap::iterator it = unacked_packets_.find(sequence_number);

  if (it != unacked_packets_.end()) {
    DVLOG(1) << "Resending unacked packet " << sequence_number;
    framer_.IncrementRetransmitCount(it->second);
    SendPacket(sequence_number, it->second, true, false);
  } else {
    DVLOG(2) << "alarm fired for " << sequence_number
             << " but it has been acked";
  }
}

bool QuicConnection::SendPacket(QuicPacketSequenceNumber sequence_number,
                                QuicPacket* packet,
                                bool resend,
                                bool force) {
  // If this packet is being forced, don't bother checking to see if we should
  // write, just write.
  if (!force) {
    // If we can't write, then simply queue the packet.
    if (write_blocked_ || helper_->IsSendAlarmSet()) {
      queued_packets_.push_back(QueuedPacket(sequence_number, packet, resend));
      return false;
    }

    int delay = scheduler_->TimeUntilSend(resend);
    // If the scheduler requires a delay, then we can not send this packet now.
    if (delay > 0) {
      helper_->SetSendAlarm(delay);
      queued_packets_.push_back(QueuedPacket(sequence_number, packet, resend));
      return false;
    }
  }
  if (resend) {
    helper_->SetResendAlarm(sequence_number, kDefaultResendTimeMs * 1000);
    // The second case should never happen in the real world, but does here
    // because we sometimes send out of order to validate corner cases.
    if (outgoing_ack_.sent_info.least_unacked == 0 ||
        sequence_number < outgoing_ack_.sent_info.least_unacked) {
      outgoing_ack_.sent_info.least_unacked = sequence_number;
    }
  } else {
    if (outgoing_ack_.sent_info.least_unacked!= 0 &&
        sequence_number > outgoing_ack_.sent_info.least_unacked) {
      outgoing_ack_.sent_info.non_retransmiting.insert(sequence_number);
    }
  }

  // Just before we send the packet to the wire, update the transmission time.
  framer_.WriteTransmissionTime(clock_->NowInUsec(), packet);

  scoped_ptr<QuicEncryptedPacket> encrypted(framer_.EncryptPacket(*packet));
  int error;
  int rv = helper_->WritePacketToWire(sequence_number, *encrypted, resend,
                                      &error);
  if (rv == -1) {
    if (error == ERR_IO_PENDING) {
      write_blocked_ = true;
      queued_packets_.push_front(QueuedPacket(sequence_number, packet, resend));
      return false;
    }
  }

  time_of_last_packet_us_ = clock_->NowInUsec();
  DVLOG(1) << "last packet: " << time_of_last_packet_us_;

  scheduler_->SentPacket(sequence_number, packet->length(),
                         framer_.GetRetransmitCount(packet) != 0);
  if (!resend) delete packet;
  return true;
}

bool QuicConnection::ShouldSimulateLostPacket() {
  // TODO(rch): enable this
  return false;
  /*
  return FLAGS_fake_packet_loss_percentage > 0 &&
      random_->Rand32() % 100 < FLAGS_fake_packet_loss_percentage;
  */
}

void QuicConnection::SendAck() {
  if (!collector_->GenerateCongestionInfo(&outgoing_ack_.congestion_info)) {
    outgoing_ack_.congestion_info.type = kNone;
  }
  DVLOG(1) << "Sending ack " << outgoing_ack_;

  PacketPair packetpair = packet_creator_.AckPacket(&outgoing_ack_);
  SendPacket(packetpair.first, packetpair.second, false, false);
}

void QuicConnection::MaybeProcessRevivedPacket() {
  QuicFecGroup* group = GetFecGroup();
  if (group == NULL || !group->CanRevive()) {
    return;
  }
  DCHECK(!revived_payload_.get());
  revived_payload_.reset(new char[kMaxPacketSize]);
  size_t len = group->Revive(&revived_header_, revived_payload_.get(),
                             kMaxPacketSize);
  group_map_.erase(last_header_.fec_group);
  delete group;

  last_packet_revived_ = true;
  framer_.ProcessRevivedPacket(revived_header_,
                               StringPiece(revived_payload_.get(), len));
  revived_payload_.reset(NULL);
}

QuicFecGroup* QuicConnection::GetFecGroup() {
  QuicFecGroupNumber fec_group_num = last_header_.fec_group;
  if (fec_group_num == 0) {
    return NULL;
  }
  if (group_map_.count(fec_group_num) == 0) {
    // TODO(rch): limit the number of active FEC groups.
    group_map_[fec_group_num] = new QuicFecGroup();
  }
  return group_map_[fec_group_num];
}

void QuicConnection::SendConnectionClose(QuicErrorCode error) {
  DLOG(INFO) << "Force closing with error " << QuicUtils::ErrorToString(error)
             << " (" << error << ")";
  QuicConnectionCloseFrame frame;
  frame.error_code = error;
  frame.ack_frame = outgoing_ack_;

  PacketPair packetpair = packet_creator_.CloseConnection(&frame);
  // There's no point in resending this: we're closing the connection.
  SendPacket(packetpair.first, packetpair.second, false, true);
  visitor_->ConnectionClose(error, false);
  connected_ = false;
}

void QuicConnection::CloseFecGroupsBefore(
    QuicPacketSequenceNumber sequence_number) {
  FecGroupMap::iterator it = group_map_.begin();
  while (it != group_map_.end()) {
    // If this is the current group or the group doesn't protect this packet
    // we can ignore it.
    if (last_header_.fec_group == it->first ||
        !it->second->ProtectsPacketsBefore(sequence_number)) {
      ++it;
      continue;
    }
    QuicFecGroup* fec_group = it->second;
    DCHECK(!fec_group->CanRevive());
    FecGroupMap::iterator next = it;
    ++next;
    group_map_.erase(it);
    delete fec_group;
    it = next;
  }
}

bool QuicConnection::CheckForTimeout() {
  uint64 now_in_us = clock_->NowInUsec();
  uint64 delta_in_us = now_in_us - time_of_last_packet_us_;
  DVLOG(1) << "last_packet " << time_of_last_packet_us_
           << " now:" << now_in_us
           << " delta:" << delta_in_us;
  if (delta_in_us >= timeout_us_) {
    SendConnectionClose(QUIC_CONNECTION_TIMED_OUT);
    return true;
  }
  helper_->SetTimeoutAlarm(timeout_us_ - delta_in_us);
  return false;
}

}  // namespace net
