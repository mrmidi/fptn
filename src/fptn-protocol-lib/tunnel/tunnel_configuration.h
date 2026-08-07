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

struct TunnelFlowConfiguration {
  std::string tun_ipv4;
  std::string tun_ipv6;
  std::uint16_t mtu = 1400;
};

// Split-routing policy. Domains take the `domain:example.com` form or a bare
// domain, and match the name itself plus any subdomain. Anything unmatched (or
// unattributable, such as an IP-literal connection) is tunnelled.
struct TunnelRoutingConfiguration {
  std::vector<std::string> direct_domains;
  std::vector<std::string> reject_domains;
  std::vector<std::string> drop_domains;
  // Resolvers advertised to the OS. They live behind the tunnel, so their
  // traffic is pinned to the fptn verdict; this is what makes server-supplied
  // DNS work in split mode.
  std::vector<std::string> tunnel_resolvers;
};

struct TunnelCallbacks {
  using PacketBatchCallback =
      std::function<void(fptn::common::network::BatchIPPacketPtr)>;
  // Borrowed for the duration of the call; the stack recycles the buffers
  // afterwards, so consumers must copy anything they keep.
  using OwnedPacketBatchCallback = std::function<void(OwnedPacketBatchView)>;
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
  TunnelFlowConfiguration flow;
  TunnelRoutingConfiguration routing;
};

}  // namespace fptn::tunnel
