// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/reliable_quic_stream.h"

#include "net/quic/quic_session.h"

using base::StringPiece;

namespace net {

ReliableQuicStream::ReliableQuicStream(QuicStreamId id,
                                       QuicSession* session)
    : sequencer_(this),
      id_(id),
      offset_(0),
      session_(session),
      error_(QUIC_NO_ERROR),
      read_side_closed_(false),
      write_side_closed_(false) {
}

ReliableQuicStream::~ReliableQuicStream() {
}

bool ReliableQuicStream::WillAcceptStreamFrame(
    const QuicStreamFrame& frame) const {
  if (read_side_closed_) {
    return true;
  }
  if (frame.stream_id != id_) {
    LOG(ERROR) << "Error!";
    return false;
  }
  return sequencer_.WillAcceptStreamFrame(frame);
}

bool ReliableQuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  DCHECK_EQ(frame.stream_id, id_);
  if (read_side_closed_) {
    DLOG(INFO) << "Ignoring frame " << frame.stream_id;
    // We don't want to be reading: blackhole the data.
    return true;
  }

  bool accepted = sequencer_.OnStreamFrame(frame);

  if (frame.fin) {
    sequencer_.CloseStreamAtOffset(frame.offset + frame.data.size(),
                                   true);
  }

  return accepted;
}

void ReliableQuicStream::OnStreamReset(QuicErrorCode error,
                                       QuicStreamOffset offset) {
  error_ = error;
  sequencer_.CloseStreamAtOffset(offset, false);  // Full close.
}

void ReliableQuicStream::ConnectionClose(QuicErrorCode error, bool from_peer) {
  error_ = error;
  if (from_peer) {
    TerminateFromPeer(false);
  } else {
    CloseWriteSide();
    CloseReadSide();
  }
}

void ReliableQuicStream::TerminateFromPeer(bool half_close) {
  if (!half_close) {
    CloseWriteSide();
  }
  CloseReadSide();
}

void ReliableQuicStream::Close(QuicErrorCode error) {
  error_ = error;
  session()->SendRstStream(id(), error, offset_);
}

bool ReliableQuicStream::IsHalfClosed() const {
  return sequencer_.IsHalfClosed();
}

bool ReliableQuicStream::HasBytesToRead() const {
  return sequencer_.HasBytesToRead();
}

const IPEndPoint& ReliableQuicStream::GetPeerAddress() const {
  return session_->peer_address();
}

int ReliableQuicStream::WriteData(StringPiece data, bool fin) {
  if (write_side_closed_) {
    DLOG(ERROR) << "Attempt to write when the write side is closed";
    return 0;
  }

  int rv = session()->WriteData(id(), data, offset_, fin);
  offset_ += data.length();
  if (fin) {
    CloseWriteSide();
  }
  return rv;
}

void ReliableQuicStream::CloseReadSide() {
  if (read_side_closed_) {
    return;
  }
  DLOG(INFO) << "Done reading from stream " << id();

  read_side_closed_ = true;
  if (write_side_closed_) {
    DLOG(INFO) << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

void ReliableQuicStream::CloseWriteSide() {
  if (write_side_closed_) {
    return;
  }
  DLOG(INFO) << "Done writing to stream " << id();

  write_side_closed_ = true;
  if (read_side_closed_) {
    DLOG(INFO) << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

}  // namespace net
