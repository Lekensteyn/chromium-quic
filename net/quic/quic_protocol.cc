// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_protocol.h"
#include "base/stl_util.h"

using base::StringPiece;
using std::map;
using std::numeric_limits;
using std::ostream;

namespace net {

QuicStreamFrame::QuicStreamFrame() {}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 uint64 offset,
                                 StringPiece data)
    : stream_id(stream_id),
      fin(fin),
      offset(offset),
      data(data) {
}

// TODO(ianswett): Initializing largest_received to 0 should not be necessary.
ReceivedPacketInfo::ReceivedPacketInfo() : largest_received(0) {}

ReceivedPacketInfo::~ReceivedPacketInfo() {}

void ReceivedPacketInfo::RecordReceived(
    QuicPacketSequenceNumber sequence_number) {
  DCHECK(IsAwaitingPacket(sequence_number));
  if (largest_received < sequence_number) {
    DCHECK_LT(sequence_number - largest_received,
              numeric_limits<uint16>::max());
    // We've got a new high sequence number.  Note any new intermediate missing
    // packets, and update the last_ack data.
    for (QuicPacketSequenceNumber i = largest_received + 1;
         i < sequence_number; ++i) {
      DVLOG(1) << "missing " << i;
      missing_packets.insert(i);
    }
    largest_received = sequence_number;
  } else {
    // We've gotten one of the out of order packets - remove it from our
    // "missing packets" list.
    DVLOG(1) << "Removing "  << sequence_number << " from missing list";
    missing_packets.erase(sequence_number);
  }
}

bool ReceivedPacketInfo::IsAwaitingPacket(
    QuicPacketSequenceNumber sequence_number) const {
  return sequence_number > largest_received ||
      ContainsKey(missing_packets, sequence_number);
}

void ReceivedPacketInfo::ClearMissingBefore(
    QuicPacketSequenceNumber least_unacked) {
  missing_packets.erase(missing_packets.begin(),
                        missing_packets.lower_bound(least_unacked));
}

SentPacketInfo::SentPacketInfo() {}

SentPacketInfo::~SentPacketInfo() {}

// Testing convenience method.
QuicAckFrame::QuicAckFrame(QuicPacketSequenceNumber largest_received,
                           QuicPacketSequenceNumber least_unacked) {
  for (QuicPacketSequenceNumber seq_num = 1;
       seq_num <= largest_received; ++seq_num) {
    received_info.RecordReceived(seq_num);
  }
  received_info.largest_received = largest_received;
  sent_info.least_unacked = least_unacked;
}

ostream& operator<<(ostream& os, const SentPacketInfo& s) {
  os << "least_waiting: " << s.least_unacked;
  return os;
}

ostream& operator<<(ostream& os, const ReceivedPacketInfo& r) {
  os << "largest_received: "
     << r.largest_received
     << " missing_packets: [ ";
  for (SequenceSet::const_iterator it = r.missing_packets.begin();
       it != r.missing_packets.end(); ++it) {
    os << *it << " ";
  }
  os << " ] ";
  return os;
}

QuicCongestionFeedbackFrame::QuicCongestionFeedbackFrame() {
}

QuicCongestionFeedbackFrame::~QuicCongestionFeedbackFrame() {
}

ostream& operator<<(ostream& os, const QuicCongestionFeedbackFrame& c) {
  os << "type: " << c.type;
  switch (c.type) {
    case kInterArrival: {
      const CongestionFeedbackMessageInterArrival& inter_arrival =
          c.inter_arrival;
      os << " accumulated_number_of_lost_packets: "
         << inter_arrival.accumulated_number_of_lost_packets;
      os << " offset_time: " << inter_arrival.offset_time;
      os << " delta_time: " << inter_arrival.delta_time;
      os << " received packets: [ ";
      for (TimeMap::const_iterator it =
               inter_arrival.received_packet_times.begin();
           it != inter_arrival.received_packet_times.end(); ++it) {
        os << it->first << "@" << it->second.ToMilliseconds() << " ";
      }
      os << "]";
      break;
    }
    case kFixRate: {
      os << " bitrate_in_bytes_per_second: "
         << c.fix_rate.bitrate_in_bytes_per_second;
      break;
    }
    case kTCP: {
      const CongestionFeedbackMessageTCP& tcp = c.tcp;
      os << " accumulated_number_of_lost_packets: "
         << c.tcp.accumulated_number_of_lost_packets;
      os << " receive_window: " << tcp.receive_window;
      break;
    }
    default: {
      DLOG(FATAL) << "Unsupported congestion info type: "
                  << c.type;
    }
  }
 return os;
}

ostream& operator<<(ostream& os, const QuicAckFrame& a) {
  os << "sent info { " << a.sent_info << " } "
     << "received info { " << a.received_info << " }\n";
 return os;
}

CongestionFeedbackMessageInterArrival::
CongestionFeedbackMessageInterArrival() {}

CongestionFeedbackMessageInterArrival::
~CongestionFeedbackMessageInterArrival() {}

QuicFecData::QuicFecData() {}

bool QuicFecData::operator==(const QuicFecData& other) const {
  if (fec_group != other.fec_group) {
    return false;
  }
  if (min_protected_packet_sequence_number !=
      other.min_protected_packet_sequence_number) {
    return false;
  }
  if (redundancy != other.redundancy) {
    return false;
  }
  return true;
}

QuicData::~QuicData() {
  if (owns_buffer_) {
    delete [] const_cast<char*>(buffer_);
  }
}

}  // namespace net
