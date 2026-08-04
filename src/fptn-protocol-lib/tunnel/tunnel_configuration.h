/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <string>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/tunnel/data_plane_mode.h"
#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel {

struct TunnelL3Configuration {
  std::string server_ip;
  int server_port = 0;
  std::string tun_ipv4;
  std::string tun_ipv6;
  std::string sni;
  std::string access_token;
  std::string md5_fingerprint;
  fptn::protocol::https::CensorshipStrategy censorship_strategy =
      fptn::protocol::https::CensorshipStrategy::kSni;
  int idle_timeout_seconds = 60;
  int concurrency_hint = 1;
};

struct TunnelCallbacks {
  using PacketBatchCallback =
      std::function<void(fptn::common::network::BatchIPPacketPtr)>;
  using OwnedPacketBatchCallback = std::function<void(OwnedPacketBatch)>;
  using ConnectedCallback = std::function<void()>;
  using DisconnectedCallback =
      std::function<void(bool was_connected, const std::string& reason)>;

  PacketBatchCallback on_packet_batch;
  OwnedPacketBatchCallback on_owned_packet_batch;
  ConnectedCallback on_connected;
  DisconnectedCallback on_disconnected;
};

struct TunnelConfiguration {
  DataPlaneMode mode = DataPlaneMode::l3_tunnel;
  TunnelL3Configuration l3;
};

}  // namespace fptn::tunnel
