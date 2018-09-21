// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_protocol.h"

#include "base/stl_util.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using std::map;
using std::numeric_limits;
using std::ostream;
using std::string;

namespace net {

size_t GetPacketHeaderSize(const QuicPacketHeader& header) {
  return GetPacketHeaderSize(header.public_header.connection_id_length,
                             header.public_header.version_flag,
                             header.public_header.packet_number_length,
                             header.is_in_fec_group);
}

size_t GetPacketHeaderSize(QuicConnectionIdLength connection_id_length,
                           bool include_version,
                           QuicPacketNumberLength packet_number_length,
                           InFecGroup is_in_fec_group) {
  return kPublicFlagsSize + connection_id_length +
         (include_version ? kQuicVersionSize : 0) + packet_number_length +
         kPrivateFlagsSize +
         (is_in_fec_group == IN_FEC_GROUP ? kFecGroupSize : 0);
}

size_t GetStartOfFecProtectedData(QuicConnectionIdLength connection_id_length,
                                  bool include_version,
                                  QuicPacketNumberLength packet_number_length) {
  return GetPacketHeaderSize(connection_id_length, include_version,
                             packet_number_length, IN_FEC_GROUP);
}

size_t GetStartOfEncryptedData(QuicConnectionIdLength connection_id_length,
                               bool include_version,
                               QuicPacketNumberLength packet_number_length) {
  // Don't include the fec size, since encryption starts before private flags.
  return GetPacketHeaderSize(connection_id_length, include_version,
                             packet_number_length, NOT_IN_FEC_GROUP) -
         kPrivateFlagsSize;
}

QuicPacketPublicHeader::QuicPacketPublicHeader()
    : connection_id(0),
      connection_id_length(PACKET_8BYTE_CONNECTION_ID),
      reset_flag(false),
      version_flag(false),
      packet_number_length(PACKET_6BYTE_PACKET_NUMBER) {}

QuicPacketPublicHeader::QuicPacketPublicHeader(
    const QuicPacketPublicHeader& other)
    : connection_id(other.connection_id),
      connection_id_length(other.connection_id_length),
      reset_flag(other.reset_flag),
      version_flag(other.version_flag),
      packet_number_length(other.packet_number_length),
      versions(other.versions) {}

QuicPacketPublicHeader::~QuicPacketPublicHeader() {}

QuicPacketHeader::QuicPacketHeader()
    : packet_packet_number(0),
      fec_flag(false),
      entropy_flag(false),
      entropy_hash(0),
      is_in_fec_group(NOT_IN_FEC_GROUP),
      fec_group(0) {}

QuicPacketHeader::QuicPacketHeader(const QuicPacketPublicHeader& header)
    : public_header(header),
      packet_packet_number(0),
      fec_flag(false),
      entropy_flag(false),
      entropy_hash(0),
      is_in_fec_group(NOT_IN_FEC_GROUP),
      fec_group(0) {}

QuicPublicResetPacket::QuicPublicResetPacket()
    : nonce_proof(0), rejected_packet_number(0) {}

QuicPublicResetPacket::QuicPublicResetPacket(
    const QuicPacketPublicHeader& header)
    : public_header(header), nonce_proof(0), rejected_packet_number(0) {}

QuicStreamFrame::QuicStreamFrame() : stream_id(0), fin(false), offset(0) {
}

QuicStreamFrame::QuicStreamFrame(const QuicStreamFrame& frame)
    : stream_id(frame.stream_id),
      fin(frame.fin),
      offset(frame.offset),
      data(frame.data) {
}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 QuicStreamOffset offset,
                                 StringPiece data)
    : stream_id(stream_id), fin(fin), offset(offset), data(data) {
}

uint32 MakeQuicTag(char a, char b, char c, char d) {
  return static_cast<uint32>(a) |
         static_cast<uint32>(b) << 8 |
         static_cast<uint32>(c) << 16 |
         static_cast<uint32>(d) << 24;
}

bool ContainsQuicTag(const QuicTagVector& tag_vector, QuicTag tag) {
  return std::find(tag_vector.begin(), tag_vector.end(),  tag)
      != tag_vector.end();
}

QuicVersionVector QuicSupportedVersions() {
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  return supported_versions;
}

QuicTag QuicVersionToQuicTag(const QuicVersion version) {
  switch (version) {
    case QUIC_VERSION_24:
      return MakeQuicTag('Q', '0', '2', '4');
    case QUIC_VERSION_25:
      return MakeQuicTag('Q', '0', '2', '5');
    case QUIC_VERSION_26:
      return MakeQuicTag('Q', '0', '2', '6');
    default:
      // This shold be an ERROR because we should never attempt to convert an
      // invalid QuicVersion to be written to the wire.
      LOG(ERROR) << "Unsupported QuicVersion: " << version;
      return 0;
  }
}

QuicVersion QuicTagToQuicVersion(const QuicTag version_tag) {
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    if (version_tag == QuicVersionToQuicTag(kSupportedQuicVersions[i])) {
      return kSupportedQuicVersions[i];
    }
  }
  // Reading from the client so this should not be considered an ERROR.
  DVLOG(1) << "Unsupported QuicTag version: "
           << QuicUtils::TagToString(version_tag);
  return QUIC_VERSION_UNSUPPORTED;
}

#define RETURN_STRING_LITERAL(x) \
case x: \
return #x

string QuicVersionToString(const QuicVersion version) {
  switch (version) {
    RETURN_STRING_LITERAL(QUIC_VERSION_24);
    RETURN_STRING_LITERAL(QUIC_VERSION_25);
    RETURN_STRING_LITERAL(QUIC_VERSION_26);
    default:
      return "QUIC_VERSION_UNSUPPORTED";
  }
}

string QuicVersionVectorToString(const QuicVersionVector& versions) {
  string result = "";
  for (size_t i = 0; i < versions.size(); ++i) {
    if (i != 0) {
      result.append(",");
    }
    result.append(QuicVersionToString(versions[i]));
  }
  return result;
}

ostream& operator<<(ostream& os, const Perspective& s) {
  if (s == Perspective::IS_SERVER) {
    os << "IS_SERVER";
  } else {
    os << "IS_CLIENT";
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicPacketHeader& header) {
  os << "{ connection_id: " << header.public_header.connection_id
     << ", connection_id_length:" << header.public_header.connection_id_length
     << ", packet_number_length:" << header.public_header.packet_number_length
     << ", reset_flag: " << header.public_header.reset_flag
     << ", version_flag: " << header.public_header.version_flag;
  if (header.public_header.version_flag) {
    os << " version: ";
    for (size_t i = 0; i < header.public_header.versions.size(); ++i) {
      os << header.public_header.versions[i] << " ";
    }
  }
  os << ", fec_flag: " << header.fec_flag
     << ", entropy_flag: " << header.entropy_flag
     << ", entropy hash: " << static_cast<int>(header.entropy_hash)
     << ", packet_number: " << header.packet_packet_number
     << ", is_in_fec_group:" << header.is_in_fec_group
     << ", fec_group: " << header.fec_group << "}\n";
  return os;
}

bool IsAwaitingPacket(const QuicAckFrame& ack_frame,
                      QuicPacketNumber packet_number) {
  return packet_number > ack_frame.largest_observed ||
         ack_frame.missing_packets.Contains(packet_number);
}

QuicStopWaitingFrame::QuicStopWaitingFrame()
    : entropy_hash(0),
      least_unacked(0) {
}

QuicStopWaitingFrame::~QuicStopWaitingFrame() {}

QuicAckFrame::QuicAckFrame()
    : entropy_hash(0),
      largest_observed(0),
      delta_time_largest_observed(QuicTime::Delta::Infinite()),
      is_truncated(false) {}

QuicAckFrame::~QuicAckFrame() {}

QuicRstStreamErrorCode AdjustErrorForVersion(
    QuicRstStreamErrorCode error_code,
    QuicVersion version) {
  return error_code;
}

QuicRstStreamFrame::QuicRstStreamFrame()
    : stream_id(0), error_code(QUIC_STREAM_NO_ERROR), byte_offset(0) {}

QuicRstStreamFrame::QuicRstStreamFrame(QuicStreamId stream_id,
                                       QuicRstStreamErrorCode error_code,
                                       QuicStreamOffset bytes_written)
    : stream_id(stream_id),
      error_code(error_code),
      byte_offset(bytes_written) {
  DCHECK_LE(error_code, numeric_limits<uint8>::max());
}

QuicConnectionCloseFrame::QuicConnectionCloseFrame()
    : error_code(QUIC_NO_ERROR) {
}

QuicFrame::QuicFrame() {}

QuicFrame::QuicFrame(QuicPaddingFrame* padding_frame)
    : type(PADDING_FRAME),
      padding_frame(padding_frame) {
}

QuicFrame::QuicFrame(QuicStreamFrame* stream_frame)
    : type(STREAM_FRAME),
      stream_frame(stream_frame) {
}

QuicFrame::QuicFrame(QuicAckFrame* frame)
    : type(ACK_FRAME),
      ack_frame(frame) {
}

QuicFrame::QuicFrame(QuicMtuDiscoveryFrame* frame)
    : type(MTU_DISCOVERY_FRAME), mtu_discovery_frame(frame) {
}

QuicFrame::QuicFrame(QuicStopWaitingFrame* frame)
    : type(STOP_WAITING_FRAME),
      stop_waiting_frame(frame) {
}

QuicFrame::QuicFrame(QuicPingFrame* frame)
    : type(PING_FRAME),
      ping_frame(frame) {
}

QuicFrame::QuicFrame(QuicRstStreamFrame* frame)
    : type(RST_STREAM_FRAME),
      rst_stream_frame(frame) {
}

QuicFrame::QuicFrame(QuicConnectionCloseFrame* frame)
    : type(CONNECTION_CLOSE_FRAME),
      connection_close_frame(frame) {
}

QuicFrame::QuicFrame(QuicGoAwayFrame* frame)
    : type(GOAWAY_FRAME),
      goaway_frame(frame) {
}

QuicFrame::QuicFrame(QuicWindowUpdateFrame* frame)
    : type(WINDOW_UPDATE_FRAME),
      window_update_frame(frame) {
}

QuicFrame::QuicFrame(QuicBlockedFrame* frame)
    : type(BLOCKED_FRAME),
      blocked_frame(frame) {
}

QuicFecData::QuicFecData() : fec_group(0) {}

ostream& operator<<(ostream& os, const QuicStopWaitingFrame& sent_info) {
  os << "entropy_hash: " << static_cast<int>(sent_info.entropy_hash)
     << " least_unacked: " << sent_info.least_unacked;
  return os;
}

PacketNumberQueue::const_iterator::const_iterator(
    PacketNumberSet::const_iterator set_iter)
    : use_interval_set_(false), set_iter_(set_iter) {}

PacketNumberQueue::const_iterator::const_iterator(
    IntervalSet<QuicPacketNumber>::const_iterator interval_set_iter,
    QuicPacketNumber first,
    QuicPacketNumber last)
    : use_interval_set_(true),
      interval_set_iter_(interval_set_iter),
      current_(first),
      last_(last) {}

PacketNumberQueue::const_iterator::const_iterator(const const_iterator& other) =
    default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::const_iterator::const_iterator(const_iterator&& other) =
//    default;
PacketNumberQueue::const_iterator::~const_iterator() {}

PacketNumberQueue::const_iterator& PacketNumberQueue::const_iterator::operator=(
    const const_iterator& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::const_iterator&
// PacketNumberQueue::const_iterator::operator=(
//    const_iterator&& other) = default;

bool PacketNumberQueue::const_iterator::operator!=(
    const const_iterator& other) const {
  if (use_interval_set_) {
    return current_ != other.current_;
  } else {
    return set_iter_ != other.set_iter_;
  }
}

bool PacketNumberQueue::const_iterator::operator==(
    const const_iterator& other) const {
  if (use_interval_set_) {
    return current_ == other.current_;
  } else {
    return set_iter_ == other.set_iter_;
  }
}

PacketNumberQueue::const_iterator::value_type
    PacketNumberQueue::const_iterator::
    operator*() const {
  if (use_interval_set_) {
    return current_;
  } else {
    return *set_iter_;
  }
}

PacketNumberQueue::const_iterator& PacketNumberQueue::const_iterator::
operator++() {
  if (use_interval_set_) {
    ++current_;
    if (current_ < last_) {
      if (current_ >= interval_set_iter_->max()) {
        ++interval_set_iter_;
        current_ = interval_set_iter_->min();
      }
    } else {
      current_ = last_;
    }
  } else {
    ++set_iter_;
  }
  return *this;
}

PacketNumberQueue::const_iterator PacketNumberQueue::const_iterator::operator++(
    int /* postincrement */) {
  PacketNumberQueue::const_iterator preincrement(*this);
  operator++();
  return preincrement;
}

PacketNumberQueue::PacketNumberQueue()
    : use_interval_set_(FLAGS_quic_packet_queue_use_interval_set) {}

PacketNumberQueue::PacketNumberQueue(const PacketNumberQueue& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::PacketNumberQueue(PacketNumberQueue&& other) = default;
PacketNumberQueue::~PacketNumberQueue() {}

PacketNumberQueue& PacketNumberQueue::operator=(
    const PacketNumberQueue& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue& PacketNumberQueue::operator=(PacketNumberQueue&& other) =
//    default;

void PacketNumberQueue::Add(QuicPacketNumber packet_number) {
  if (use_interval_set_) {
    packet_number_intervals_.Add(packet_number, packet_number + 1);
  } else {
    packet_number_set_.insert(packet_number);
  }
}

void PacketNumberQueue::Add(QuicPacketNumber lower, QuicPacketNumber higher) {
  if (use_interval_set_) {
    packet_number_intervals_.Add(lower, higher);
  } else {
    for (QuicPacketNumber packet_number = lower; packet_number < higher;
         ++packet_number) {
      Add(packet_number);
    }
  }
}

void PacketNumberQueue::Remove(QuicPacketNumber packet_number) {
  if (use_interval_set_) {
    packet_number_intervals_.Difference(packet_number, packet_number + 1);
  } else {
    packet_number_set_.erase(packet_number);
  }
}

bool PacketNumberQueue::RemoveUpTo(QuicPacketNumber higher) {
  if (use_interval_set_) {
    if (Empty()) {
      return false;
    }
    const QuicPacketNumber old_min = Min();
    packet_number_intervals_.Difference(0, higher);
    return Empty() || old_min != Min();
  } else {
    const size_t orig_size = packet_number_set_.size();
    packet_number_set_.erase(packet_number_set_.begin(),
                             packet_number_set_.lower_bound(higher));
    return orig_size != packet_number_set_.size();
  }
}

bool PacketNumberQueue::Contains(QuicPacketNumber packet_number) const {
  if (use_interval_set_) {
    return packet_number_intervals_.Contains(packet_number);
  } else {
    return ContainsKey(packet_number_set_, packet_number);
  }
}

bool PacketNumberQueue::Empty() const {
  if (use_interval_set_) {
    return packet_number_intervals_.Empty();
  } else {
    return packet_number_set_.empty();
  }
}

QuicPacketNumber PacketNumberQueue::Min() const {
  DCHECK(!Empty());
  if (use_interval_set_) {
    return packet_number_intervals_.begin()->min();
  } else {
    return *packet_number_set_.begin();
  }
}

QuicPacketNumber PacketNumberQueue::Max() const {
  DCHECK(!Empty());
  if (use_interval_set_) {
    return packet_number_intervals_.rbegin()->max() - 1;
  } else {
    return *packet_number_set_.rbegin();
  }
}

size_t PacketNumberQueue::NumPacketsSlow() const {
  if (use_interval_set_) {
    size_t num_packets = 0;
    for (const auto& interval : packet_number_intervals_) {
      num_packets += interval.Length();
    }
    return num_packets;
  } else {
    return packet_number_set_.size();
  }
}

PacketNumberQueue::const_iterator PacketNumberQueue::begin() const {
  if (use_interval_set_) {
    QuicPacketNumber first;
    QuicPacketNumber last;
    if (packet_number_intervals_.Empty()) {
      first = 0;
      last = 0;
    } else {
      first = packet_number_intervals_.begin()->min();
      last = packet_number_intervals_.rbegin()->max();
    }
    return const_iterator(packet_number_intervals_.begin(), first, last);
  } else {
    return const_iterator(packet_number_set_.begin());
  }
}

PacketNumberQueue::const_iterator PacketNumberQueue::end() const {
  if (use_interval_set_) {
    QuicPacketNumber last = packet_number_intervals_.Empty()
                                ? 0
                                : packet_number_intervals_.rbegin()->max();
    return const_iterator(packet_number_intervals_.end(), last, last);
  } else {
    return const_iterator(packet_number_set_.end());
  }
}

PacketNumberQueue::const_iterator PacketNumberQueue::lower_bound(
    QuicPacketNumber packet_number) const {
  if (use_interval_set_) {
    QuicPacketNumber first;
    QuicPacketNumber last;
    if (packet_number_intervals_.Empty()) {
      first = 0;
      last = 0;
      return const_iterator(packet_number_intervals_.begin(), first, last);
    }
    if (!packet_number_intervals_.Contains(packet_number)) {
      return end();
    }
    IntervalSet<QuicPacketNumber>::const_iterator it =
        packet_number_intervals_.Find(packet_number);
    first = packet_number;
    last = packet_number_intervals_.rbegin()->max();
    return const_iterator(it, first, last);
  } else {
    return const_iterator(packet_number_set_.lower_bound(packet_number));
  }
}

ostream& operator<<(ostream& os, const PacketNumberQueue& q) {
  for (QuicPacketNumber packet_number : q) {
    os << packet_number << " ";
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicAckFrame& ack_frame) {
  os << "entropy_hash: " << static_cast<int>(ack_frame.entropy_hash)
     << " largest_observed: " << ack_frame.largest_observed
     << " delta_time_largest_observed: "
     << ack_frame.delta_time_largest_observed.ToMicroseconds()
     << " missing_packets: [ " << ack_frame.missing_packets
     << " ] is_truncated: " << ack_frame.is_truncated;
  os << " revived_packets: [ ";
  for (PacketNumberSet::const_iterator it = ack_frame.revived_packets.begin();
       it != ack_frame.revived_packets.end(); ++it) {
    os << *it << " ";
  }
  os << " ] received_packets: [ ";
  for (PacketTimeList::const_iterator it =
           ack_frame.received_packet_times.begin();
           it != ack_frame.received_packet_times.end(); ++it) {
    os << it->first << " at " << it->second.ToDebuggingValue() << " ";
  }
  os << " ]";
  return os;
}

ostream& operator<<(ostream& os, const QuicFrame& frame) {
  switch (frame.type) {
  case PADDING_FRAME: {
      os << "type { PADDING_FRAME } ";
      break;
    }
    case RST_STREAM_FRAME: {
      os << "type { RST_STREAM_FRAME } " << *(frame.rst_stream_frame);
      break;
    }
    case CONNECTION_CLOSE_FRAME: {
      os << "type { CONNECTION_CLOSE_FRAME } "
         << *(frame.connection_close_frame);
      break;
    }
    case GOAWAY_FRAME: {
      os << "type { GOAWAY_FRAME } " << *(frame.goaway_frame);
      break;
    }
    case WINDOW_UPDATE_FRAME: {
      os << "type { WINDOW_UPDATE_FRAME } " << *(frame.window_update_frame);
      break;
    }
    case BLOCKED_FRAME: {
      os << "type { BLOCKED_FRAME } " << *(frame.blocked_frame);
      break;
    }
    case STREAM_FRAME: {
      os << "type { STREAM_FRAME } " << *(frame.stream_frame);
      break;
    }
    case ACK_FRAME: {
      os << "type { ACK_FRAME } " << *(frame.ack_frame);
      break;
    }
    case STOP_WAITING_FRAME: {
      os << "type { STOP_WAITING_FRAME } " << *(frame.stop_waiting_frame);
      break;
    }
    case PING_FRAME: {
      os << "type { PING_FRAME } ";
      break;
    }
    case MTU_DISCOVERY_FRAME: {
      os << "type { MTU_DISCOVERY_FRAME } ";
      break;
    }
    default: {
      LOG(ERROR) << "Unknown frame type: " << frame.type;
      break;
    }
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicRstStreamFrame& rst_frame) {
  os << "stream_id { " << rst_frame.stream_id << " } "
     << "error_code { " << rst_frame.error_code << " } "
     << "error_details { " << rst_frame.error_details << " }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicConnectionCloseFrame& connection_close_frame) {
  os << "error_code { " << connection_close_frame.error_code << " } "
     << "error_details { " << connection_close_frame.error_details << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicGoAwayFrame& goaway_frame) {
  os << "error_code { " << goaway_frame.error_code << " } "
     << "last_good_stream_id { " << goaway_frame.last_good_stream_id << " } "
     << "reason_phrase { " << goaway_frame.reason_phrase << " }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicWindowUpdateFrame& window_update_frame) {
  os << "stream_id { " << window_update_frame.stream_id << " } "
     << "byte_offset { " << window_update_frame.byte_offset << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicBlockedFrame& blocked_frame) {
  os << "stream_id { " << blocked_frame.stream_id << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicStreamFrame& stream_frame) {
  os << "stream_id { " << stream_frame.stream_id << " } "
     << "fin { " << stream_frame.fin << " } "
     << "offset { " << stream_frame.offset << " } "
     << "data { " << QuicUtils::StringToHexASCIIDump(stream_frame.data)
     << " }\n";
  return os;
}

QuicGoAwayFrame::QuicGoAwayFrame()
    : error_code(QUIC_NO_ERROR),
      last_good_stream_id(0) {
}

QuicGoAwayFrame::QuicGoAwayFrame(QuicErrorCode error_code,
                                 QuicStreamId last_good_stream_id,
                                 const string& reason)
    : error_code(error_code),
      last_good_stream_id(last_good_stream_id),
      reason_phrase(reason) {
  DCHECK_LE(error_code, numeric_limits<uint8>::max());
}

QuicData::QuicData(const char* buffer,
                   size_t length)
    : buffer_(buffer),
      length_(length),
      owns_buffer_(false) {
}

QuicData::QuicData(char* buffer,
                   size_t length,
                   bool owns_buffer)
    : buffer_(buffer),
      length_(length),
      owns_buffer_(owns_buffer) {
}

QuicData::~QuicData() {
  if (owns_buffer_) {
    delete [] const_cast<char*>(buffer_);
  }
}

QuicWindowUpdateFrame::QuicWindowUpdateFrame(QuicStreamId stream_id,
                                             QuicStreamOffset byte_offset)
    : stream_id(stream_id),
      byte_offset(byte_offset) {}

QuicBlockedFrame::QuicBlockedFrame(QuicStreamId stream_id)
    : stream_id(stream_id) {}

QuicPacket::QuicPacket(char* buffer,
                       size_t length,
                       bool owns_buffer,
                       QuicConnectionIdLength connection_id_length,
                       bool includes_version,
                       QuicPacketNumberLength packet_number_length)
    : QuicData(buffer, length, owns_buffer),
      buffer_(buffer),
      connection_id_length_(connection_id_length),
      includes_version_(includes_version),
      packet_number_length_(packet_number_length) {}

QuicEncryptedPacket::QuicEncryptedPacket(const char* buffer,
                                         size_t length)
    : QuicData(buffer, length) {
}

QuicEncryptedPacket::QuicEncryptedPacket(char* buffer,
                                         size_t length,
                                         bool owns_buffer)
      : QuicData(buffer, length, owns_buffer) {
}

StringPiece QuicPacket::FecProtectedData() const {
  const size_t start_of_fec = GetStartOfFecProtectedData(
      connection_id_length_, includes_version_, packet_number_length_);
  return StringPiece(data() + start_of_fec, length() - start_of_fec);
}

StringPiece QuicPacket::AssociatedData() const {
  return StringPiece(
      data() + kStartOfHashData,
      GetStartOfEncryptedData(connection_id_length_, includes_version_,
                              packet_number_length_) -
          kStartOfHashData);
}

StringPiece QuicPacket::BeforePlaintext() const {
  return StringPiece(
      data(), GetStartOfEncryptedData(connection_id_length_, includes_version_,
                                      packet_number_length_));
}

StringPiece QuicPacket::Plaintext() const {
  const size_t start_of_encrypted_data = GetStartOfEncryptedData(
      connection_id_length_, includes_version_, packet_number_length_);
  return StringPiece(data() + start_of_encrypted_data,
                     length() - start_of_encrypted_data);
}

RetransmittableFrames::RetransmittableFrames(EncryptionLevel level)
    : encryption_level_(level),
      has_crypto_handshake_(NOT_HANDSHAKE),
      needs_padding_(false) {
}

RetransmittableFrames::~RetransmittableFrames() {
  for (QuicFrames::iterator it = frames_.begin(); it != frames_.end(); ++it) {
    switch (it->type) {
      case PADDING_FRAME:
        delete it->padding_frame;
        break;
      case STREAM_FRAME:
        delete it->stream_frame;
        break;
      case ACK_FRAME:
        delete it->ack_frame;
        break;
      case MTU_DISCOVERY_FRAME:
        delete it->mtu_discovery_frame;
        break;
      case STOP_WAITING_FRAME:
        delete it->stop_waiting_frame;
        break;
      case PING_FRAME:
        delete it->ping_frame;
        break;
      case RST_STREAM_FRAME:
        delete it->rst_stream_frame;
        break;
      case CONNECTION_CLOSE_FRAME:
        delete it->connection_close_frame;
        break;
      case GOAWAY_FRAME:
        delete it->goaway_frame;
        break;
      case WINDOW_UPDATE_FRAME:
        delete it->window_update_frame;
        break;
      case BLOCKED_FRAME:
        delete it->blocked_frame;
        break;
      case NUM_FRAME_TYPES:
        DCHECK(false) << "Cannot delete type: " << it->type;
    }
  }
  for (const char* buffer : stream_data_) {
    delete[] buffer;
  }
}

const QuicFrame& RetransmittableFrames::AddFrame(const QuicFrame& frame) {
  return AddFrame(frame, nullptr);
}

const QuicFrame& RetransmittableFrames::AddFrame(const QuicFrame& frame,
                                                 char* buffer) {
  if (frame.type == STREAM_FRAME &&
      frame.stream_frame->stream_id == kCryptoStreamId) {
    has_crypto_handshake_ = IS_HANDSHAKE;
  }
  if (buffer != nullptr) {
    stream_data_.push_back(buffer);
  }
  frames_.push_back(frame);
  return frames_.back();
}

void RetransmittableFrames::RemoveFramesForStream(QuicStreamId stream_id) {
  QuicFrames::iterator it = frames_.begin();
  while (it != frames_.end()) {
    if (it->type != STREAM_FRAME || it->stream_frame->stream_id != stream_id) {
      ++it;
      continue;
    }
    delete it->stream_frame;
    it = frames_.erase(it);
  }
}

SerializedPacket::SerializedPacket(
    QuicPacketNumber packet_number,
    QuicPacketNumberLength packet_number_length,
    QuicEncryptedPacket* packet,
    QuicPacketEntropyHash entropy_hash,
    RetransmittableFrames* retransmittable_frames,
    bool has_ack,
    bool has_stop_waiting)
    : packet(packet),
      retransmittable_frames(retransmittable_frames),
      packet_number(packet_number),
      packet_number_length(packet_number_length),
      entropy_hash(entropy_hash),
      is_fec_packet(false),
      has_ack(has_ack),
      has_stop_waiting(has_stop_waiting) {}

SerializedPacket::~SerializedPacket() {}

QuicEncryptedPacket* QuicEncryptedPacket::Clone() const {
  char* buffer = new char[this->length()];
  memcpy(buffer, this->data(), this->length());
  return new QuicEncryptedPacket(buffer, this->length(), true);
}

ostream& operator<<(ostream& os, const QuicEncryptedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

TransmissionInfo::TransmissionInfo()
    : retransmittable_frames(nullptr),
      packet_number_length(PACKET_1BYTE_PACKET_NUMBER),
      sent_time(QuicTime::Zero()),
      bytes_sent(0),
      nack_count(0),
      transmission_type(NOT_RETRANSMISSION),
      all_transmissions(nullptr),
      in_flight(false),
      is_unackable(false),
      is_fec_packet(false) {}

TransmissionInfo::TransmissionInfo(
    RetransmittableFrames* retransmittable_frames,
    QuicPacketNumberLength packet_number_length,
    TransmissionType transmission_type,
    QuicTime sent_time,
    QuicByteCount bytes_sent,
    bool is_fec_packet)
    : retransmittable_frames(retransmittable_frames),
      packet_number_length(packet_number_length),
      sent_time(sent_time),
      bytes_sent(bytes_sent),
      nack_count(0),
      transmission_type(transmission_type),
      all_transmissions(nullptr),
      in_flight(false),
      is_unackable(false),
      is_fec_packet(is_fec_packet) {}

}  // namespace net
