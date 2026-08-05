/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/flow_proxy_data_plane.h"

#include <future>
#include <new>
#include <utility>

#include <boost/asio/post.hpp>

namespace fptn::tunnel {

FlowProxyDataPlane::FlowProxyDataPlane(
    TunnelConfiguration config, TunnelCallbacks callbacks)
    : config_(std::move(config)), callbacks_(std::move(callbacks)) {}

FlowProxyDataPlane::~FlowProxyDataPlane() { Stop(); }

std::expected<void, TunnelError> FlowProxyDataPlane::Start() {
  if (started_.load(std::memory_order_acquire)) {
    return std::unexpected(TunnelError::already_running);
  }
  if (stopped_ever_) {
    // The runtime is one-shot; a stopped plane cannot be restarted.
    return std::unexpected(TunnelError::already_running);
  }
  if (config_.l3.tun_ipv4.empty()) {
    return std::unexpected(TunnelError::invalid_configuration);
  }
  if (!runtime_.Start()) {
    return std::unexpected(TunnelError::start_failed);
  }
  const auto executor = runtime_.Executor();

  router_ = std::make_unique<DirectRouter>();
  event_sink_ = std::make_unique<NullEventSink>();
  tcp_outbound_ = std::make_unique<flow::DirectTcpOutbound>(executor);
  udp_outbound_ = std::make_unique<flow::DirectUdpOutbound>(executor);

  flow::StackConfiguration stack_config;
  stack_config.tun_ipv4 = config_.l3.tun_ipv4;
  stack_config.tun_ipv6 = config_.l3.tun_ipv6;

  auto output = callbacks_.on_owned_packet_batch;
  auto stack = std::make_shared<flow::LwipStack>(executor,
      std::move(stack_config), *event_sink_, *router_, *tcp_outbound_,
      *udp_outbound_,
      [output](OwnedPacketBatch batch) {
        if (output) {
          output(std::move(batch));
        }
      });
  stack->SetExecutorThreadId(runtime_.ThreadId());

  auto result = stack->Start();
  if (!result.has_value()) {
    tcp_outbound_.reset();
    udp_outbound_.reset();
    router_.reset();
    event_sink_.reset();
    runtime_.Stop();
    return result;
  }
  {
    std::scoped_lock lock(stack_mutex_);
    stack_ = std::move(stack);
  }
  started_.store(true, std::memory_order_release);
  return {};
}

// NOLINTNEXTLINE(bugprone-exception-escape): rare allocation failures are caught.
void FlowProxyDataPlane::Stop() noexcept {
  if (!started_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  stopped_ever_ = true;

  if (runtime_.IsCurrentThread()) {
    // Stopping from within the runtime thread cannot join the runtime and
    // cannot safely drain stack state synchronously. Reject: the engine is
    // one-shot, and a reentrant stop is a caller contract violation.
    reentrant_stop_attempts_.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  std::shared_ptr<flow::LwipStack> stack;
  {
    std::scoped_lock lock(stack_mutex_);
    stack = std::move(stack_);
  }
  if (stack) {
    stack->Stop();
  }

  try {
    std::promise<void> done;
    auto future = done.get_future();
    boost::asio::post(runtime_.Executor(), [this, &done] {
      if (tcp_outbound_) {
        tcp_outbound_->Stop();
      }
      if (udp_outbound_) {
        udp_outbound_->Stop();
      }
      done.set_value();
    });
    future.get();
    // NOLINTNEXTLINE(bugprone-empty-catch): runtime stop below cancels work.
  } catch (const std::bad_alloc&) {
    // Post can only fail on allocation failure; the runtime is stopped
    // below, which cancels any outbound work that was not stopped here.
  }

  // Stop the runtime (join its thread) before destroying any member: after
  // Stop() returns no handler can run, so teardown of the stack/outbounds
  // cannot race a pending executor callback.
  runtime_.Stop();

  stack.reset();
  tcp_outbound_.reset();
  udp_outbound_.reset();
  router_.reset();
  event_sink_.reset();
}

PacketInputResult FlowProxyDataPlane::InputPackets(
    PacketBatchView packets) noexcept {
  if (!started_.load(std::memory_order_acquire)) {
    return PacketInputResult::transport_stopped;
  }
  std::shared_ptr<flow::LwipStack> stack;
  {
    std::scoped_lock lock(stack_mutex_);
    stack = stack_;
  }
  if (!stack) {
    return PacketInputResult::transport_stopped;
  }
  return stack->InputPackets(packets);
}

}  // namespace fptn::tunnel
