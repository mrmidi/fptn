/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/l3_tunnel_data_plane.h"

#include <exception>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

#include "common/network/ip_packet.h"

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

  // Ownership contract: on `accepted` the engine owns every lease and
  // releases each exactly once; on any other result the caller keeps every
  // lease. The L3 transport always copies packet bytes into its own queue,
  // so this is enforced by consuming leases only on the all-success path.

  // 1. Validate every lease up front; reject before touching any lease.
  std::uint64_t total_bytes = 0;
  for (const auto& lease : packets) {
    if (lease.bytes == nullptr || lease.length == 0) {
      client->NoteRejectedBeforeCopy(packets.size(), total_bytes);
      return PacketInputResult::invalid_packet;
    }
    if (lease.ip_version != 0 && lease.ip_version != 4 &&
        lease.ip_version != 6) {
      client->NoteRejectedBeforeCopy(packets.size(), total_bytes);
      return PacketInputResult::invalid_packet;
    }
    // Header-only admission check (mirrors TrySendPacketBytes): avoid an
    // allocation for malformed/non-IP input.
    const std::uint8_t version = lease.bytes[0] >> 4;
    if (lease.length < 20 ||
        (version != 4 && (version != 6 || lease.length < 40))) {
      client->NoteRejectedBeforeCopy(packets.size(), total_bytes);
      return PacketInputResult::invalid_packet;
    }
    total_bytes += lease.length;
  }

  // 2. Reserve the whole batch atomically.
  auto reservation = client->TryReserveBatch(packets.size(), total_bytes);
  if (!reservation) {
    return PacketInputResult::queue_full;
  }

  // 3. Copy + parse every packet before enqueueing anything, so a parse
  // failure rejects the batch without consuming any lease. The RAII
  // reservation rolls back the queue accounting on this path.
  std::vector<fptn::common::network::IPPacketPtr> parsed;
  try {
    parsed.reserve(packets.size());
    for (const auto& lease : packets) {
      fptn::common::network::IPPacketData storage(
          lease.bytes, lease.bytes + lease.length);
      auto packet = fptn::common::network::IPPacket::Parse(std::move(storage));
      if (!packet) {
        client->NoteRejectedBeforeCopy(packets.size(), total_bytes);
        return PacketInputResult::invalid_packet;
      }
      client->NoteAdmissionCopy(lease.length);
      parsed.push_back(std::move(packet));
    }
  } catch (...) {
    return PacketInputResult::invalid_packet;
  }

  // 4. Enqueue the whole batch. A mid-batch failure leaves already-enqueued
  // copies in the transport but consumes no lease, so the caller still owns
  // every lease and the RAII reservation releases the un-enqueued slots.
  for (std::size_t i = 0; i < parsed.size(); ++i) {
    reservation.ForgetPacket(packets[i].length);
    const auto result = client->EnqueueReservedPacket(
        std::move(parsed[i]), packets[i].length);
    if (result != fptn::protocol::https::SendResult::accepted) {
      return MapSendResult(result);
    }
  }

  reservation.Commit();
  ReleasePacketBatch(packets);
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
