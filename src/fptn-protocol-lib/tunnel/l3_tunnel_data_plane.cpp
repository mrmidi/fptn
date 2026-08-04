/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/l3_tunnel_data_plane.h"

#include <exception>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>

#ifndef FPTN_CLIENT_DEFAULT_ADDRESS_IP6
#define FPTN_CLIENT_DEFAULT_ADDRESS_IP6 "fd00::1"
#endif

namespace fptn::tunnel {

namespace {

PacketInputResult MapSendResult(
    fptn::protocol::https::SendResult result) noexcept {
  switch (result) {
    case fptn::protocol::https::SendResult::accepted:
      return PacketInputResult::accepted;
    case fptn::protocol::https::SendResult::queue_full:
      return PacketInputResult::queue_full;
    case fptn::protocol::https::SendResult::transport_stopped:
      return PacketInputResult::transport_stopped;
    case fptn::protocol::https::SendResult::invalid_packet:
      return PacketInputResult::invalid_packet;
  }
  return PacketInputResult::invalid_packet;
}

}  // namespace

L3TunnelDataPlane::L3TunnelDataPlane(
    TunnelL3Configuration config, TunnelCallbacks callbacks)
    : config_(std::move(config)), callbacks_(std::move(callbacks)) {}

L3TunnelDataPlane::~L3TunnelDataPlane() { Stop(); }

std::expected<void, TunnelError> L3TunnelDataPlane::Start() {
  if (running_.load(std::memory_order_acquire) || run_thread_.joinable()) {
    return std::unexpected(TunnelError::already_running);
  }
  if (config_.server_ip.empty() || config_.server_port <= 0 ||
      config_.tun_ipv4.empty()) {
    return std::unexpected(TunnelError::invalid_configuration);
  }
  running_.store(true, std::memory_order_release);
  try {
    run_thread_ = std::thread(&L3TunnelDataPlane::RunThread, this);
  } catch (...) {
    running_.store(false, std::memory_order_release);
    return std::unexpected(TunnelError::start_failed);
  }
  return {};
}

void L3TunnelDataPlane::Stop() noexcept {
  running_.store(false, std::memory_order_release);

  fptn::protocol::https::WebsocketClientSPtr active_client;
  {
    std::lock_guard lock(mutex_);
    active_client = std::move(client_);
  }
  if (active_client) {
    active_client->Stop(fptn::protocol::https::StopOrigin::swift_tunnel_stop);
  }
  if (run_thread_.joinable()) {
    run_thread_.join();
  }
}

PacketInputResult L3TunnelDataPlane::InputPackets(
    PacketBatchView packets) noexcept {
  if (!running_.load(std::memory_order_acquire)) {
    return PacketInputResult::transport_stopped;
  }
  fptn::protocol::https::WebsocketClientSPtr client;
  {
    std::lock_guard lock(mutex_);
    client = client_;
  }
  if (!client) {
    return PacketInputResult::transport_stopped;
  }
  for (const auto& lease : packets) {
    if (lease.bytes == nullptr || lease.length == 0) {
      return PacketInputResult::invalid_packet;
    }
    if (lease.ip_version != 0 && lease.ip_version != 4 &&
        lease.ip_version != 6) {
      return PacketInputResult::invalid_packet;
    }
    PacketInputResult result = PacketInputResult::invalid_packet;
    try {
      result = MapSendResult(
          client->TrySendPacketBytes(lease.bytes, lease.length));
    } catch (...) {
      result = PacketInputResult::invalid_packet;
    }
    if (result != PacketInputResult::accepted) {
      return result;
    }
  }
  return PacketInputResult::accepted;
}

void L3TunnelDataPlane::RunThread() noexcept {
  fptn::protocol::https::WebsocketClientSPtr client;
  try {
    {
      std::lock_guard lock(mutex_);
      if (!running_.load(std::memory_order_acquire)) {
        return;
      }

      fptn::protocol::https::WebsocketClient::Config client_config;
      client_config.server_ip =
          fptn::common::network::IPv4Address::Create(config_.server_ip);
      client_config.server_port = config_.server_port;
      client_config.tun_interface_address_ipv4 =
          fptn::common::network::IPv4Address::Create(config_.tun_ipv4);
      client_config.tun_interface_address_ipv6 =
          fptn::common::network::IPv6Address::Create(
              config_.tun_ipv6.empty() ? FPTN_CLIENT_DEFAULT_ADDRESS_IP6
                                       : config_.tun_ipv6);
      client_config.sni = config_.sni;
      client_config.access_token = config_.access_token;
      client_config.expected_md5_fingerprint = config_.md5_fingerprint;
      client_config.censorship_strategy = config_.censorship_strategy;
      client_config.on_connected_callback = [this]() {
        if (callbacks_.on_connected) {
          callbacks_.on_connected();
        }
      };
      client_config.new_ip_pkt_batch_callback =
          [this](fptn::common::network::BatchIPPacketPtr packets) {
            if (callbacks_.on_packet_batch) {
              callbacks_.on_packet_batch(std::move(packets));
            }
          };

      client = std::make_shared<fptn::protocol::https::WebsocketClient>(
          std::move(client_config), config_.concurrency_hint);
      client_ = client;
    }

    client->Run();

    if (callbacks_.on_disconnected) {
      callbacks_.on_disconnected(true, "Transport stopped");
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("L3 tunnel data plane exception: {}", ex.what());
    if (callbacks_.on_disconnected) {
      callbacks_.on_disconnected(
          false, std::string("Transport exception: ") + ex.what());
    }
  } catch (...) {
    SPDLOG_ERROR("L3 tunnel data plane unknown exception");
    if (callbacks_.on_disconnected) {
      callbacks_.on_disconnected(false, "Transport unknown exception");
    }
  }

  {
    std::lock_guard lock(mutex_);
    client_.reset();
  }
  running_.store(false, std::memory_order_release);
}

}  // namespace fptn::tunnel
