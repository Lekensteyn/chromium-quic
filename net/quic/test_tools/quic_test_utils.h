// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Common utilities for Quic tests

#ifndef NET_QUIC_TEST_TOOLS_QUIC_TEST_UTILS_H_
#define NET_QUIC_TEST_TOOLS_QUIC_TEST_UTILS_H_

#include "net/quic/congestion_control/quic_send_scheduler.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_session.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace net {

namespace test {

void CompareCharArraysWithHexError(const std::string& description,
                                   const char* actual,
                                   const int actual_len,
                                   const char* expected,
                                   const int expected_len);

void CompareQuicDataWithHexError(const std::string& description,
                                 QuicData* actual,
                                 QuicData* expected);

// Constructs a basic crypto handshake message
QuicPacket* ConstructHandshakePacket(QuicGuid guid, CryptoTag tag);

class MockFramerVisitor : public QuicFramerVisitorInterface {
 public:
  MockFramerVisitor();
  ~MockFramerVisitor();

  MOCK_METHOD1(OnError, void(QuicFramer* framer));
  MOCK_METHOD2(OnPacket, void(const IPEndPoint& self_address,
                              const IPEndPoint& peer_address));
  MOCK_METHOD0(OnRevivedPacket, void());
  MOCK_METHOD1(OnPacketHeader, bool(const QuicPacketHeader& header));
  MOCK_METHOD1(OnFecProtectedPayload, void(base::StringPiece payload));
  MOCK_METHOD1(OnStreamFrame, void(const QuicStreamFrame& frame));
  MOCK_METHOD1(OnAckFrame, void(const QuicAckFrame& frame));
  MOCK_METHOD1(OnFecData, void(const QuicFecData& fec));
  MOCK_METHOD1(OnRstStreamFrame, void(const QuicRstStreamFrame& frame));
  MOCK_METHOD1(OnConnectionCloseFrame,
               void(const QuicConnectionCloseFrame& frame));
  MOCK_METHOD0(OnPacketComplete, void());
};

class NoOpFramerVisitor : public QuicFramerVisitorInterface {
 public:
  virtual void OnError(QuicFramer* framer) OVERRIDE {}
  virtual void OnPacket(const IPEndPoint& self_address,
                        const IPEndPoint& peer_address) OVERRIDE {}
  virtual void OnRevivedPacket() OVERRIDE {}
  virtual bool OnPacketHeader(const QuicPacketHeader& header) OVERRIDE;
  virtual void OnFecProtectedPayload(base::StringPiece payload) OVERRIDE {}
  virtual void OnStreamFrame(const QuicStreamFrame& frame) OVERRIDE {}
  virtual void OnAckFrame(const QuicAckFrame& frame) OVERRIDE {}
  virtual void OnFecData(const QuicFecData& fec) OVERRIDE {}
  virtual void OnRstStreamFrame(const QuicRstStreamFrame& frame) OVERRIDE {}
  virtual void OnConnectionCloseFrame(
      const QuicConnectionCloseFrame& frame) OVERRIDE {}
  virtual void OnPacketComplete() OVERRIDE {}
};

class FramerVisitorCapturingAcks : public NoOpFramerVisitor {
 public:
  // NoOpFramerVisitor
  virtual bool OnPacketHeader(const QuicPacketHeader& header) OVERRIDE;
  virtual void OnAckFrame(const QuicAckFrame& frame) OVERRIDE;

  QuicPacketHeader* header() { return &header_; }
  QuicAckFrame* frame() { return &frame_; }
 private:
  QuicPacketHeader header_;
  QuicAckFrame frame_;
};

class MockConnectionVisitor : public QuicConnectionVisitorInterface {
 public:
  MockConnectionVisitor();
  virtual ~MockConnectionVisitor();
  MOCK_METHOD4(OnPacket, bool(const IPEndPoint& self_address,
                              const IPEndPoint& peer_address,
                              const QuicPacketHeader& header,
                              const std::vector<QuicStreamFrame>& frame));
  MOCK_METHOD1(OnRstStream, void(const QuicRstStreamFrame& frame));
  MOCK_METHOD2(ConnectionClose, void(QuicErrorCode error, bool from_peer));
  MOCK_METHOD1(OnAck, void(AckedPackets acked_packets));
};

class MockScheduler : public QuicSendScheduler {
 public:
  MockScheduler();
  virtual ~MockScheduler();

  MOCK_METHOD1(TimeUntilSend, int(bool));
  MOCK_METHOD1(OnIncomingAckFrame, void(const QuicAckFrame&));
  MOCK_METHOD3(SentPacket, void(QuicPacketSequenceNumber, size_t, bool));
};

class MockHelper : public QuicConnectionHelperInterface {
 public:
  MockHelper();
  virtual ~MockHelper();

  MOCK_METHOD1(SetConnection, void(QuicConnection* connection));
  QuicClock* GetClock();
  MOCK_METHOD4(WritePacketToWire, int(QuicPacketSequenceNumber number,
                                      const QuicEncryptedPacket& packet,
                                      bool resend,
                                      int* error));
  MOCK_METHOD2(SetResendAlarm, void(QuicPacketSequenceNumber sequence_number,
                                    uint64 delay_in_us));
  MOCK_METHOD1(SetSendAlarm, void(uint64 delay_in_us));
  MOCK_METHOD1(SetTimeoutAlarm, void(uint64 delay_in_us));
  MOCK_METHOD0(IsSendAlarmSet, bool());
  MOCK_METHOD0(UnregisterSendAlarmIfRegistered, void());
 private:
  MockClock clock_;
};

class MockConnection : public QuicConnection {
 public:
  MockConnection(QuicGuid guid, IPEndPoint address);
  virtual ~MockConnection();

  MOCK_METHOD3(ProcessUdpPacket, void(const IPEndPoint& self_address,
                                      const IPEndPoint& peer_address,
                                      const QuicEncryptedPacket& packet));
  MOCK_METHOD1(SendConnectionClose, void(QuicErrorCode error));

  MOCK_METHOD3(SendRstStream, void(QuicStreamId id,
                                   QuicErrorCode error,
                                   QuicStreamOffset offset));

  MOCK_METHOD0(OnCanWrite, bool());
};

class PacketSavingConnection : public MockConnection {
 public:
  PacketSavingConnection(QuicGuid guid, IPEndPoint address);
  virtual ~PacketSavingConnection();

  virtual bool SendPacket(QuicPacketSequenceNumber number,
                          QuicPacket* packet,
                          bool should_resend,
                          bool force,
                          bool is_retransmit) OVERRIDE;

  std::vector<QuicPacket*> packets_;
};

class MockSession : public QuicSession {
 public:
  MockSession(QuicConnection* connection, bool is_server);
  ~MockSession();

  MOCK_METHOD4(OnPacket, bool(const IPEndPoint& seld_address,
                              const IPEndPoint& peer_address,
                              const QuicPacketHeader& header,
                              const std::vector<QuicStreamFrame>& frame));
  MOCK_METHOD2(ConnectionClose, void(QuicErrorCode error, bool from_peer));
  MOCK_METHOD1(CreateIncomingReliableStream,
               ReliableQuicStream*(QuicStreamId id));
  MOCK_METHOD0(GetCryptoStream, QuicCryptoStream*());
  MOCK_METHOD0(CreateOutgoingReliableStream, ReliableQuicStream*());
  MOCK_METHOD3(WriteData,
               void(QuicStreamId id, base::StringPiece data, bool fin));
  MOCK_METHOD4(WriteData, int(QuicStreamId id, base::StringPiece data,
                              QuicStreamOffset offset, bool fin));
  MOCK_METHOD0(IsHandshakeComplete, bool());
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_TEST_UTILS_H_
