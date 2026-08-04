/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/flow_proxy_data_plane.h"

#include <future>
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
  if (config_.l3.tun_ipv4.empty()) {
    return std::unexpected(TunnelError::invalid_configuration);
  }

  runtime_.Start();
  const auto executor = runtime_.Executor();

  router_ = std::make_unique<DirectRouter>();
  event_sink_ = std::make_unique<NullEventSink>();
  tcp_outbound_ = std::make_unique<flow::DirectTcpOutbound>(executor);
  udp_outbound_ = std::make_unique<flow::DirectUdpOutbound>(executor);

  flow::StackConfiguration stack_config;
  stack_config.tun_ipv4 = config_.l3.tun_ipv4;
  stack_config.tun_ipv6 = config_.l3.tun_ipv6;

  auto output = callbacks_.on_owned_packet_batch;
  stack_ = std::make_unique<flow::LwipStack>(executor,
      std::move(stack_config), *event_sink_, *router_, *tcp_outbound_,
      *udp_outbound_,
      [output](OwnedPacketBatch batch) {
        if (output) {
          output(std::move(batch));
        }
      });

  auto result = stack_->Start();
  if (!result.has_value()) {
    tcp_outbound_.reset();
    udp_outbound_.reset();
    stack_.reset();
    router_.reset();
    event_sink_.reset();
    runtime_.Stop();
    return result;
  }
  started_.store(true, std::memory_order_release);
  return {};
}

void FlowProxyDataPlane::Stop() noexcept {
  if (!started_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }

  if (stack_) {
    stack_->Stop();
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
  } catch (...) {
  }

  stack_.reset();
  tcp_outbound_.reset();
  udp_outbound_.reset();
  router_.reset();
  event_sink_.reset();
  runtime_.Stop();
}

PacketInputResult FlowProxyDataPlane::InputPackets(
    PacketBatchView packets) noexcept {
  if (!started_.load(std::memory_order_acquire) || !stack_) {
    return PacketInputResult::transport_stopped;
  }
  return stack_->InputPackets(packets);
}

}  // namespace fptn::tunnel
