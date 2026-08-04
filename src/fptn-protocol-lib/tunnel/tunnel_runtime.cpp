/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/tunnel_runtime.h"

namespace fptn::tunnel {

TunnelRuntime::TunnelRuntime()
    : work_(boost::asio::make_work_guard(ioc_)) {}

TunnelRuntime::~TunnelRuntime() { Stop(); }

void TunnelRuntime::Start() {
  if (running_) {
    return;
  }
  running_ = true;
  thread_ = std::thread([this] { ioc_.run(); });
}

void TunnelRuntime::Stop() noexcept {
  if (!running_) {
    return;
  }
  running_ = false;
  work_.reset();
  ioc_.stop();
  if (thread_.joinable()) {
    thread_.join();
  }
}

}  // namespace fptn::tunnel
