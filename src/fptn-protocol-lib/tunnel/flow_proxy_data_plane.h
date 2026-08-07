/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>
#include <mutex>

#include "fptn-protocol-lib/flow/direct_tcp_outbound.h"
#include "fptn-protocol-lib/flow/direct_udp_outbound.h"
#include "fptn-protocol-lib/flow/lwip_stack.h"
#include "fptn-protocol-lib/tunnel/i_data_plane.h"
#include "fptn-protocol-lib/tunnel/tunnel_configuration.h"
#include "fptn-protocol-lib/tunnel/tunnel_runtime.h"

namespace fptn::tunnel {

// One-shot data plane: after Stop(), Start() is rejected. Create a new
// engine per tunnel session.
class FlowProxyDataPlane final : public IDataPlane {
 public:
  // `router` is borrowed and may be null, in which case every flow is routed
  // direct (the debug-only flow_proxy mode). The split data plane injects a
  // router that reads verdicts already decided at packet ingress.
  FlowProxyDataPlane(TunnelConfiguration config, TunnelCallbacks callbacks,
      IFlowRouter* router = nullptr);
  ~FlowProxyDataPlane() override;

  FlowProxyDataPlane(const FlowProxyDataPlane&) = delete;
  FlowProxyDataPlane& operator=(const FlowProxyDataPlane&) = delete;

  std::expected<void, TunnelError> Start() override;
  void Stop() noexcept override;

  PacketInputResult InputPackets(PacketBatchView packets) noexcept override;

  // Two-phase ingress admission, so the split data plane can reserve here and
  // on the websocket transport before committing either half of a batch.
  // Mirrors LwipStack's contract; all three are no-ops once stopped.
  static bool ValidateIngressBatch(
      PacketBatchView packets, std::uint64_t& total_bytes) noexcept;
  bool TryReserveIngress(std::uint64_t total_bytes) noexcept;
  void AbandonIngressReservation(std::uint64_t total_bytes) noexcept;
  bool CommitReservedIngress(
      PacketBatchView packets, std::uint64_t total_bytes) noexcept;

  FlowCounters Counters() const noexcept override;

  std::uint64_t ReentrantStopAttempts() const noexcept {
    return reentrant_stop_attempts_.load(std::memory_order_relaxed);
  }

  // Test-only accessors for lifecycle assertions (reentrant stop, teardown).
  boost::asio::any_io_executor RuntimeExecutorForTesting() {
    return runtime_.Executor();
  }
  bool IsStartedForTesting() const noexcept {
    return started_.load(std::memory_order_acquire);
  }
  std::uint64_t ActiveTcpFlowsForTesting() const noexcept;
  std::uint64_t ActiveUdpFlowsForTesting() const noexcept;

 private:
  struct DirectRouter final : IFlowRouter {
    RouteAction Match(const FlowMetadata&) override {
      return RouteAction::direct;
    }
  };

  struct NullEventSink final : IFlowEventSink {
    void OnTcpOpen(FlowMetadata) override {}
    void OnTcpData(FlowId, OwnedBuffer) override {}
    void OnTcpHalfClose(FlowId) override {}
    void OnTcpReset(FlowId, FlowError) override {}
    void OnUdpDatagram(FlowMetadata, OwnedBuffer) override {}
  };

  TunnelConfiguration config_;
  TunnelCallbacks callbacks_;
  TunnelRuntime runtime_;

  // Borrowed when injected, owned when this plane supplies the default.
  IFlowRouter* injected_router_ = nullptr;
  std::unique_ptr<IFlowRouter> owned_router_;
  IFlowRouter* router_ = nullptr;
  std::unique_ptr<NullEventSink> event_sink_;
  std::unique_ptr<flow::DirectTcpOutbound> tcp_outbound_;
  std::unique_ptr<flow::DirectUdpOutbound> udp_outbound_;
  // Shared so InputPackets callers can outlive Stop() safely: they hold a
  // local reference, observe !IsRunning(), and drop it.
  std::shared_ptr<flow::LwipStack> stack_;
  mutable std::mutex stack_mutex_;
  // Requires stack_mutex_ and a non-null stack_.
  FlowCounters SnapshotLocked() const noexcept;
  // Final tallies captured during Stop(), so a post-mortem read after
  // teardown still reports what the session did rather than zeroes.
  FlowCounters last_counters_;

  std::atomic<bool> started_{false};
  bool stopped_ever_{false};
  std::atomic<std::uint64_t> reentrant_stop_attempts_{0};
};

}  // namespace fptn::tunnel
