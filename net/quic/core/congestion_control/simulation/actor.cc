// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/simulation/actor.h"
#include "net/quic/core/congestion_control/simulation/simulator.h"

namespace net {
namespace simulation {

Actor::Actor(Simulator* simulator, std::string name)
    : simulator_(simulator),
      clock_(simulator->GetClock()),
      name_(std::move(name)) {
  simulator->AddActor(this);
}

Actor::~Actor() {}

void Actor::Schedule(QuicTime next_tick) {
  simulator_->Schedule(this, next_tick);
}

void Actor::Unschedule() {
  simulator_->Unschedule(this);
}

}  // namespace simulation
}  // namespace net
