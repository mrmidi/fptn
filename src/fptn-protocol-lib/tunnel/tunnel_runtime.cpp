/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/tunnel_runtime.h"

namespace fptn::tunnel {

TunnelRuntime::TunnelRuntime()
    : work_(boost::asio::make_work_guard(ioc_)) {}

TunnelRuntime::~TunnelRuntime() { Stop(); }

bool TunnelRuntime::Start() {
  if (running_ || stopped_ever_) {
    return false;
  }
  std::promise<std::thread::id> id_ready;
  auto id_future = id_ready.get_future();
  thread_ = std::thread([this, &id_ready] {
    id_ready.set_value(std::this_thread::get_id());
    ioc_.run();
  });
  thread_id_ = id_future.get();
  running_ = true;
  return true;
}

void TunnelRuntime::Stop() noexcept {
  if (!running_) {
    return;
  }
  running_ = false;
  stopped_ever_ = true;
  work_.reset();
  ioc_.stop();
  if (thread_.joinable()) {
    thread_.join();
  }
  thread_id_ = std::thread::id{};
}

}  // namespace fptn::tunnel
