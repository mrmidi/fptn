/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <functional>
#include <vector>

#include "fptn-protocol-lib/tunnel/dns_observer.h"
#include "fptn-protocol-lib/tunnel/flow_classifier.h"
#include "fptn-protocol-lib/tunnel/flow_interfaces.h"
#include "fptn-protocol-lib/tunnel/i_data_plane.h"
#include "fptn-protocol-lib/tunnel/websocket_batch.h"
#include "fptn-protocol-lib/tunnel/routing_policy.h"
#include "fptn-protocol-lib/tunnel/tunnel_configuration.h"

namespace fptn::tunnel {

// Forward-declared on purpose: FlowProxyDataPlane pulls in the lwIP headers,
// and this header is included by the Apple ObjC++ shim, which is built without
// lwIP's include paths. The destructor is defined out of line so the
// incomplete type is fine here.
class FlowProxyDataPlane;

// Reads back the verdict the classifier already recorded at packet ingress,
// rather than deciding a second time. Keeping one decision point means the
// stack and the classifier cannot disagree about a flow.
//
// Only `direct` and `reject` can legitimately arrive here: `drop` never enters
// the stack and `fptn_l4` is forwarded raw to the L3 plane. Anything else is a
// bug, and an unknown flow fails closed.
class TableBackedRouter final : public IFlowRouter {
 public:
  explicit TableBackedRouter(const FlowClassifier& classifier) noexcept
      : classifier_(classifier) {}

  RouteAction Match(const FlowMetadata& metadata) override;

  std::uint64_t unknown_flows() const noexcept {
    return unknown_flows_.load(std::memory_order_relaxed);
  }
  std::uint64_t unexpected_verdicts() const noexcept {
    return unexpected_verdicts_.load(std::memory_order_relaxed);
  }

 private:
  const FlowClassifier& classifier_;
  std::atomic<std::uint64_t> unknown_flows_{0};
  std::atomic<std::uint64_t> unexpected_verdicts_{0};
};

// Supplies the websocket transport that carries `fptn`-verdict packets.
//
// The transport is injected rather than owned so the platform layer keeps the
// one it already has: on Apple that is the provider's websocket bridge, with
// its reconnect, generation tracking and diagnostics intact. It also means a
// websocket drop restarts only the transport -- lwIP and every live direct
// flow survive it, which owning the transport could not offer.
//
// Called on the ingress path; return null while no transport is connected.
using TransportProvider =
    std::function<fptn::protocol::https::WebsocketClientSPtr()>;

struct SplitCounters {
  std::uint64_t batches = 0;
  std::uint64_t packets_to_stack = 0;
  std::uint64_t packets_to_transport = 0;
  std::uint64_t packets_dropped = 0;
  std::uint64_t rollbacks = 0;
};

// Runs both planes in one session: lwIP terminates the flows routed `direct`
// (and RSTs those routed `reject`), while `fptn` packets are forwarded to the
// websocket transport untouched. Composition, not inheritance -- neither
// existing plane is modified structurally.
class SplitDataPlane final : public IDataPlane {
 public:
  SplitDataPlane(TunnelConfiguration config, TunnelCallbacks callbacks,
      TransportProvider transport,
      std::shared_ptr<const IRoutingPolicy> routing_policy = nullptr);
  ~SplitDataPlane() override;

  SplitDataPlane(const SplitDataPlane&) = delete;
  SplitDataPlane& operator=(const SplitDataPlane&) = delete;

  std::expected<void, TunnelError> Start() override;
  void Stop() noexcept override;

  PacketInputResult InputPackets(PacketBatchView packets) noexcept override;

  FlowCounters Counters() const noexcept override;
  SplitCounters SplitStatistics() const noexcept;
  // Flows that reached the stack with no recorded verdict. Non-zero means the
  // fan-out and the classifier table disagree.
  std::uint64_t RouterUnknownFlows() const noexcept {
    return router_ ? router_->unknown_flows() : 0;
  }

  // Read-only tap for packets arriving from the transport, which is where DNS
  // answers appear and therefore where domain -> IP is observed. The platform
  // layer calls this from its inbound callback; it never modifies or delays a
  // packet.
  void ObserveInbound(
      const fptn::common::network::BatchIPPacketPtr& packets) noexcept;
  void ObserveInboundPacket(
      const std::uint8_t* bytes, std::size_t length) noexcept;

  // Test seams.
  const FlowClassifier& ClassifierForTesting() const noexcept {
    return *classifier_;
  }
  DnsObserver& DnsObserverForTesting() noexcept { return *dns_observer_; }

 private:
  // Builds the policy and pinned rules from config_.routing.
  void ConfigureRouting();

  TunnelConfiguration config_;
  TunnelCallbacks callbacks_;

  // The platform may inject an immutable compiled policy (the Apple split
  // bridge does this for the shared geo database). Keep the explicit lists as
  // a compatibility fallback for native callers and tests.
  std::shared_ptr<const IRoutingPolicy> configured_policy_;
  std::shared_ptr<const IRoutingPolicy> policy_;
  std::unique_ptr<DnsObserver> dns_observer_;
  std::unique_ptr<FlowClassifier> classifier_;
  std::unique_ptr<TableBackedRouter> router_;

  TransportProvider transport_;
  std::unique_ptr<FlowProxyDataPlane> flow_plane_;

  std::atomic<bool> started_{false};

  mutable std::mutex counters_mutex_;
  SplitCounters counters_;
};

}  // namespace fptn::tunnel
