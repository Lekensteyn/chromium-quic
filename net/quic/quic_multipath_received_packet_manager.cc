// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_multipath_received_packet_manager.h"

#include "base/stl_util.h"

namespace net {

QuicMultipathReceivedPacketManager::QuicMultipathReceivedPacketManager(
    QuicConnectionStats* stats) {
  path_managers_[kDefaultPathId] = new QuicReceivedPacketManager(stats);
}

QuicMultipathReceivedPacketManager::~QuicMultipathReceivedPacketManager() {
  STLDeleteValues(&path_managers_);
}

void QuicMultipathReceivedPacketManager::OnPathCreated(
    QuicPathId path_id,
    QuicConnectionStats* stats) {
  if (path_managers_[path_id] != nullptr) {
    LOG(DFATAL) << "Received packet manager of path already exists: "
                << static_cast<uint32_t>(path_id);
    return;
  }

  path_managers_[path_id] = new QuicReceivedPacketManager(stats);
}

void QuicMultipathReceivedPacketManager::OnPathClosed(QuicPathId path_id) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL) << "Received packet manager of path does not exist: "
                << static_cast<uint32_t>(path_id);
    return;
  }

  delete manager;
  path_managers_.erase(path_id);
}

void QuicMultipathReceivedPacketManager::RecordPacketReceived(
    QuicPathId path_id,
    QuicByteCount bytes,
    const QuicPacketHeader& header,
    QuicTime receipt_time) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL) << "Received a packet on a non-existent path.";
    return;
  }

  manager->RecordPacketReceived(bytes, header, receipt_time);
}

void QuicMultipathReceivedPacketManager::RecordPacketRevived(
    QuicPathId path_id,
    QuicPacketNumber packet_number) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL) << "Revived a packet on a non-existent path.";
    return;
  }

  manager->RecordPacketRevived(packet_number);
}

bool QuicMultipathReceivedPacketManager::IsMissing(
    QuicPathId path_id,
    QuicPacketNumber packet_number) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL) << "Check whether a packet is missing on a non-existent path.";
    return true;
  }

  return manager->IsMissing(packet_number);
}

bool QuicMultipathReceivedPacketManager::IsAwaitingPacket(
    QuicPathId path_id,
    QuicPacketNumber packet_number) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL) << "Check whether a packet is awaited on a non-existent path.";
    return false;
  }

  return manager->IsAwaitingPacket(packet_number);
}

void QuicMultipathReceivedPacketManager::UpdateReceivedPacketInfo(
    std::vector<QuicAckFrame>* ack_frames,
    QuicTime approximate_now,
    bool force_all_paths) {
  QuicAckFrame ack_frame;
  for (std::pair<QuicPathId, QuicReceivedPacketManager*>
           per_path_received_packet_manager : path_managers_) {
    if (!force_all_paths &&
        !per_path_received_packet_manager.second->ack_frame_updated()) {
      continue;
    }
    per_path_received_packet_manager.second->UpdateReceivedPacketInfo(
        &ack_frame, approximate_now);
    ack_frames->push_back(ack_frame);
  }
}

void QuicMultipathReceivedPacketManager::UpdatePacketInformationSentByPeer(
    const std::vector<QuicStopWaitingFrame>& stop_waitings) {
  for (QuicStopWaitingFrame stop_waiting : stop_waitings) {
    QuicReceivedPacketManager* manager = path_managers_[stop_waiting.path_id];
    if (manager != nullptr) {
      manager->UpdatePacketInformationSentByPeer(stop_waiting);
    }
  }
}

bool QuicMultipathReceivedPacketManager::HasNewMissingPackets(
    QuicPathId path_id) const {
  MultipathReceivedPacketManagerMap::const_iterator it =
      path_managers_.find(path_id);
  if (it == path_managers_.end()) {
    LOG(DFATAL)
        << "Check whether has new missing packets on a non-existent path.";
    return false;
  }

  return it->second->HasNewMissingPackets();
}

QuicPacketNumber
QuicMultipathReceivedPacketManager::GetPeerLeastPacketAwaitingAck(
    QuicPathId path_id) {
  QuicReceivedPacketManager* manager = path_managers_[path_id];
  if (manager == nullptr) {
    LOG(DFATAL)
        << "Try to get peer_least_packet_awaiting_ack of a non-existent path.";
    return false;
  }

  return manager->peer_least_packet_awaiting_ack();
}

}  // namespace net
