/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

namespace fptn::tunnel {

// Plain snapshot of the flow data plane's internal counters, taken under the
// plane's lock and copied out by value. Deliberately not atomics: callers
// sample this periodically for diagnostics, and a POD crosses the ObjC/Swift
// bridge without any shared-state lifetime questions.
//
// Reads as a funnel — ingress at the top, egress at the bottom. Whichever
// stage stops advancing is where packets are being lost.
struct FlowCounters {
  // Ingress: packets handed to lwIP.
  std::uint64_t input_packets = 0;
  std::uint64_t input_bytes = 0;
  std::uint64_t ingress_zero_copy_packets = 0;
  std::uint64_t ingress_copy_packets = 0;
  std::uint64_t lease_pool_exhaustions = 0;
  std::uint64_t dropped_packets = 0;

  // Flows created by the stack.
  std::uint64_t active_tcp_flows = 0;
  std::uint64_t peak_tcp_flows = 0;
  std::uint64_t active_udp_flows = 0;
  std::uint64_t peak_udp_flows = 0;
  std::uint64_t tcp_backpressure_events = 0;
  std::uint64_t tcp_resets = 0;
  std::uint64_t udp_drops = 0;

  // Outbound: sockets actually opened for those flows.
  std::uint64_t tcp_outbound_active = 0;
  std::uint64_t tcp_outbound_opened_total = 0;
  std::uint64_t udp_outbound_active = 0;

  // Egress: packets lwIP emitted back toward the packet flow.
  std::uint64_t output_packets = 0;
  std::uint64_t output_bytes = 0;
  // Batches handed to the platform packet-flow writer; output_packets divided
  // by this is the mean packets per write.
  std::uint64_t egress_batches = 0;
};

}  // namespace fptn::tunnel
