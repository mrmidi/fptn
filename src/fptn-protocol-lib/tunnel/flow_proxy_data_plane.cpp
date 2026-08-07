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
  if (config_.flow.tun_ipv4.empty()) {
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
  stack_config.tun_ipv4 = config_.flow.tun_ipv4;
  stack_config.tun_ipv6 = config_.flow.tun_ipv6;
  stack_config.mtu = config_.flow.mtu;

  auto output = callbacks_.on_owned_packet_batch;
  auto stack = std::make_shared<flow::LwipStack>(executor,
      std::move(stack_config), *event_sink_, *router_, *tcp_outbound_,
      *udp_outbound_,
      [output](OwnedPacketBatchView batch) {
        if (output) {
          output(batch);
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
  if (runtime_.IsCurrentThread()) {
    // Stopping from within the runtime thread cannot join the runtime and
    // cannot safely drain stack state synchronously. Reject WITHOUT changing
    // state: clearing started_ here would leave the plane logically stopped
    // but physically running, and every later external Stop() would become a
    // no-op, making teardown unrecoverable. The counter records the contract
    // violation; a later external Stop() still performs full teardown.
    reentrant_stop_attempts_.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  if (!started_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  stopped_ever_ = true;

  std::shared_ptr<flow::LwipStack> stack;
  {
    std::scoped_lock lock(stack_mutex_);
    if (stack_) {
      // Capture before the stack goes away; the outbounds are still alive
      // here and are only destroyed further down.
      last_counters_ = SnapshotLocked();
    }
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

// The whole snapshot is taken under stack_mutex_: Stop() clears stack_ while
// holding it and only destroys the outbounds afterwards, so holding it for
// the entire read keeps every pointer here alive.
FlowCounters FlowProxyDataPlane::Counters() const noexcept {
  std::scoped_lock lock(stack_mutex_);
  return stack_ == nullptr ? last_counters_ : SnapshotLocked();
}

FlowCounters FlowProxyDataPlane::SnapshotLocked() const noexcept {
  FlowCounters out;
  const auto& c = stack_->counters();
  const auto load = [](const std::atomic<std::uint64_t>& v) {
    return v.load(std::memory_order_relaxed);
  };
  out.input_packets = load(c.input_packets);
  out.input_bytes = load(c.input_bytes);
  out.ingress_zero_copy_packets = load(c.ingress_zero_copy_packets);
  out.ingress_copy_packets = load(c.ingress_copy_packets);
  out.lease_pool_exhaustions = load(c.lease_pool_exhaustions);
  out.dropped_packets = load(c.dropped_packets);
  out.active_tcp_flows = load(c.active_tcp_flows);
  out.peak_tcp_flows = load(c.peak_tcp_flows);
  out.active_udp_flows = load(c.active_udp_flows);
  out.peak_udp_flows = load(c.peak_udp_flows);
  out.tcp_backpressure_events = load(c.tcp_backpressure_events);
  out.tcp_resets = load(c.tcp_resets);
  out.udp_drops = load(c.udp_drops);
  out.output_packets = load(c.output_packets);
  out.output_bytes = load(c.output_bytes);
  out.egress_batches = load(c.egress_batches);
  if (tcp_outbound_) {
    out.tcp_outbound_active = tcp_outbound_->ActiveFlows();
    out.tcp_outbound_opened_total = tcp_outbound_->OpenedTotal();
  }
  if (udp_outbound_) {
    out.udp_outbound_active = udp_outbound_->ActiveFlows();
  }
  return out;
}

std::uint64_t FlowProxyDataPlane::ActiveTcpFlowsForTesting() const noexcept {
  std::scoped_lock lock(stack_mutex_);
  return stack_ == nullptr ? 0 : stack_->ActiveTcpFlows();
}

std::uint64_t FlowProxyDataPlane::ActiveUdpFlowsForTesting() const noexcept {
  std::scoped_lock lock(stack_mutex_);
  return stack_ == nullptr
             ? 0
             : stack_->counters().active_udp_flows.load(
                   std::memory_order_relaxed);
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
