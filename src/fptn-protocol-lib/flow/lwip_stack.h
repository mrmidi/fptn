/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <expected>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"
#include "fptn-protocol-lib/tunnel/flow_types.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/tunnel_error.h"

namespace fptn::tunnel::flow {

// Shared lifetime token for recurring executor callbacks (timeout pump,
// UDP expiry sweep). A callback that locks the token keeps the token
// alive; the stack destructor marks it dead and waits until no callback
// is in flight before destroying members, so timer handlers can never
// touch a destroyed stack even if the runtime outlives it.
struct StackLifeToken {
  std::atomic<bool> alive{true};
  std::atomic<int> in_flight{0};
};

struct StackConfiguration {
  std::string tun_ipv4 = "10.8.0.2";
  std::string tun_ipv6 = "fd00::1";
  std::uint16_t mtu = 1400;
  std::uint64_t max_ingress_inflight_bytes = 2 * 1024 * 1024;
  std::uint64_t max_udp_associations = 32;
  std::chrono::milliseconds udp_idle_timeout{30000};
};

struct StackCounters {
  std::atomic<std::uint64_t> input_packets{0};
  std::atomic<std::uint64_t> input_bytes{0};
  std::atomic<std::uint64_t> output_packets{0};
  std::atomic<std::uint64_t> output_bytes{0};
  std::atomic<std::uint64_t> ingress_copy_packets{0};
  std::atomic<std::uint64_t> ingress_copy_bytes{0};
  std::atomic<std::uint64_t> egress_coalesce_packets{0};
  std::atomic<std::uint64_t> egress_coalesce_bytes{0};
  std::atomic<std::uint64_t> dropped_packets{0};
  std::atomic<std::uint64_t> active_tcp_flows{0};
  std::atomic<std::uint64_t> peak_tcp_flows{0};
  std::atomic<std::uint64_t> active_udp_flows{0};
  std::atomic<std::uint64_t> peak_udp_flows{0};
  std::atomic<std::uint64_t> tcp_backpressure_events{0};
  std::atomic<std::uint64_t> tcp_resets{0};
  std::atomic<std::uint64_t> udp_drops{0};
};

struct PendingTcpData {
  struct pbuf* pbuf = nullptr;
  std::uint32_t length = 0;
};

// Indirection over the raw lwIP TCP close/abort calls so tests can inject a
// failing tcp_close() and observe the abort path without exhausting lwIP's
// real segment pool.
struct LwipTcpApi {
  using CloseFunction = err_t (*)(struct tcp_pcb*);
  using AbortFunction = void (*)(struct tcp_pcb*);

  CloseFunction close = &tcp_close;
  AbortFunction abort = &tcp_abort;
};

class LwipStack;

struct LwipTcpFlow {
  LwipStack* stack = nullptr;
  FlowId id = 0;
  struct tcp_pcb* pcb = nullptr;
  FlowMetadata metadata;
  std::deque<PendingTcpData> pending_to_outbound;
  bool app_fin_received = false;
  bool outbound_finished = false;
  // Finish() has been forwarded to the outbound. The application FIN may
  // arrive while lwIP still retains backpressured pbufs; forwarding Finish
  // before those bytes are admitted would let the outbound shut its send
  // side and truncate the stream, so the flag gates MaybeFinishTcpOutbound.
  bool outbound_finish_sent = false;
  bool closing = false;
};

struct LwipUdpFlow {
  LwipStack* stack = nullptr;
  FlowId id = 0;
  struct udp_pcb* pcb = nullptr;
  FlowMetadata metadata;
  std::chrono::steady_clock::time_point last_activity;
};

class LwipStack final : public INetworkStack, public ITcpOutboundSink,
                        public IUdpOutboundSink {
 public:
  LwipStack(boost::asio::any_io_executor executor,
      StackConfiguration config,
      IFlowEventSink& sink,
      IFlowRouter& router,
      ITcpOutbound& tcp_outbound,
      IUdpOutbound& udp_outbound,
      PacketOutputCallback output);
  ~LwipStack() override;

  LwipStack(const LwipStack&) = delete;
  LwipStack& operator=(const LwipStack&) = delete;

  std::expected<void, TunnelError> Start();
  void Stop() noexcept;
  bool IsRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
  }
  // Thread id of the executor driving this stack, used to execute
  // Start/Stop inline instead of deadlocking on a self-post.
  void SetExecutorThreadId(std::thread::id id) noexcept {
    executor_thread_id_ = id;
  }

  PacketInputResult InputPackets(PacketBatchView packets) noexcept override;

  WriteResult WriteTcp(FlowId flow, BufferSequence data) noexcept override;
  void FinishTcp(FlowId flow) noexcept override;
  void ResetTcp(FlowId flow) noexcept override;
  WriteResult WriteUdp(
      FlowId flow, IpEndpoint source, BufferView payload) noexcept override;

  void OnOutboundConnected(FlowId flow) override;
  bool OnOutboundData(FlowId flow, OwnedBuffer& data) override;
  void OnOutboundFinished(FlowId flow) override;
  void OnOutboundReset(FlowId flow, FlowError error) override;
  void OnOutboundWritable(FlowId flow) override;

  void OnUdpDatagramReceived(FlowId flow, OwnedBuffer payload) override;
  void OnUdpReset(FlowId flow, FlowError error) override;

  const StackCounters& counters() const noexcept { return counters_; }
  const StackConfiguration& configuration() const noexcept { return config_; }
  std::uint64_t ActiveTcpFlows() const noexcept {
    return counters_.active_tcp_flows.load(std::memory_order_relaxed);
  }

  // Test-only: replace the raw lwIP close/abort calls (e.g. with a
  // tcp_close() that fails) to exercise the abort-on-close-failure path.
  void SetTcpApiForTesting(LwipTcpApi api) noexcept {
    tcp_api_ = api;
  }

 private:
  std::expected<void, TunnelError> StartOnExecutor();
  void StopDrain(const std::shared_ptr<std::promise<void>>& done) noexcept;
  void StopOnExecutor() noexcept;
  bool OnExecutorThread() const noexcept;
  void PumpTimeouts(const boost::system::error_code& ec);
  void ScheduleTimeoutPump();

  static err_t NetifInit(struct netif* netif);
  static err_t OutputV4(
      struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr);
  static err_t OutputV6(
      struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr);
  err_t OutputPacket(struct pbuf* p, std::uint8_t ip_version);

  err_t StartTcpListener();
  void StopTcpFlows() noexcept;
  LwipTcpFlow* FindTcpFlow(FlowId flow) noexcept;
  void DestroyTcpFlow(FlowId flow) noexcept;
  void DrainPendingToOutbound(LwipTcpFlow& flow) noexcept;
  // Forwards Finish() to the outbound once the application FIN has arrived
  // and no backpressured pbufs remain retained by lwIP.
  void MaybeFinishTcpOutbound(LwipTcpFlow& flow) noexcept;
  // Closes a fully-finished flow. Returns ERR_ABRT when the pcb had to be
  // aborted (tcp_close failed) so the enclosing lwIP callback can propagate
  // it; ERR_OK otherwise (clean close, or nothing closed yet).
  err_t MaybeCloseFinishedFlow(LwipTcpFlow& flow) noexcept;
  err_t CloseFinishedTcpFlow(LwipTcpFlow& flow) noexcept;

  static err_t OnTcpAccept(
      void* arg, struct tcp_pcb* newpcb, err_t err);
  static err_t OnTcpRecv(
      void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
  static err_t OnTcpSent(void* arg, struct tcp_pcb* tpcb, u16_t len);
  static void OnTcpError(void* arg, err_t err);

  err_t StartUdpListener();
  void StopUdpFlows() noexcept;
  LwipUdpFlow* FindUdpFlow(FlowId flow) noexcept;
  void DestroyUdpFlow(FlowId flow) noexcept;
  void AbandonUdpFlowToRejected(FlowId flow) noexcept;
  void ScheduleUdpExpirySweep();
  void UdpExpirySweep(const boost::system::error_code& ec);

  static void OnUdpAccept(void* arg, struct udp_pcb* pcb, struct pbuf* p,
      const ip_addr_t* addr, u16_t port);
  static void OnUdpFlowRecv(void* arg, struct udp_pcb* pcb, struct pbuf* p,
      const ip_addr_t* addr, u16_t port);
  static void OnUdpDropRecv(void* arg, struct udp_pcb* pcb, struct pbuf* p,
      const ip_addr_t* addr, u16_t port);

  boost::asio::any_io_executor executor_;
  LwipTcpApi tcp_api_{};
  StackConfiguration config_;
  IFlowEventSink& sink_;
  IFlowRouter& router_;
  ITcpOutbound& tcp_outbound_;
  IUdpOutbound& udp_outbound_;
  PacketOutputCallback output_;
  StackCounters counters_;

  std::atomic<bool> running_{false};
  std::atomic<bool> stop_teardown_done_{false};
  std::atomic<std::uint64_t> inflight_bytes_{0};
  // Accepted-but-not-yet-executed ingress operations; Stop drains them
  // before removing the netif.
  std::atomic<std::uint64_t> pending_ingress_ops_{0};
  std::thread::id executor_thread_id_{};
  bool udp_in_accept_{false};

  struct netif netif_ {};
  bool netif_added_{false};
  boost::asio::steady_timer timeout_timer_;

  FlowId next_flow_id_{1};
  struct tcp_pcb* listener_{nullptr};
  std::unordered_map<FlowId, std::unique_ptr<LwipTcpFlow>> tcp_flows_;

  struct udp_pcb* udp_listener_{nullptr};
  std::unordered_map<FlowId, std::unique_ptr<LwipUdpFlow>> udp_flows_;
  // PCBs for tuples rejected at the association cap. They must stay in the
  // lwIP pcb list (matching their tuple) so the fork's accept loop does not
  // recreate them for every datagram; one is released whenever a slot frees.
  std::vector<struct udp_pcb*> rejected_udp_pcbs_;
  boost::asio::steady_timer udp_expiry_timer_;
  bool udp_expiry_scheduled_{false};

  std::shared_ptr<StackLifeToken> life_ = std::make_shared<StackLifeToken>();
};

}  // namespace fptn::tunnel::flow
