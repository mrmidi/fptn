/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <string>
#include <unordered_map>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <lwip/netif.h>
#include <lwip/tcp.h>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"
#include "fptn-protocol-lib/tunnel/flow_types.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/tunnel_error.h"

namespace fptn::tunnel::flow {

struct StackConfiguration {
  std::string tun_ipv4 = "10.8.0.2";
  std::string tun_ipv6 = "fd00::1";
  std::uint16_t mtu = 1400;
  std::uint64_t max_ingress_inflight_bytes = 2 * 1024 * 1024;
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

class LwipStack;

struct LwipTcpFlow {
  LwipStack* stack = nullptr;
  FlowId id = 0;
  struct tcp_pcb* pcb = nullptr;
  FlowMetadata metadata;
  std::deque<PendingTcpData> pending_to_outbound;
  bool app_fin_received = false;
  bool outbound_finished = false;
  bool closing = false;
};

class LwipStack final : public INetworkStack, public ITcpOutboundSink {
 public:
  LwipStack(boost::asio::any_io_executor executor,
      StackConfiguration config,
      IFlowEventSink& sink,
      IFlowRouter& router,
      ITcpOutbound& tcp_outbound,
      PacketOutputCallback output);
  ~LwipStack() override;

  LwipStack(const LwipStack&) = delete;
  LwipStack& operator=(const LwipStack&) = delete;

  std::expected<void, TunnelError> Start();
  void Stop() noexcept;
  bool IsRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
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

  const StackCounters& counters() const noexcept { return counters_; }
  const StackConfiguration& configuration() const noexcept { return config_; }
  std::uint64_t ActiveTcpFlows() const noexcept {
    return counters_.active_tcp_flows.load(std::memory_order_relaxed);
  }

 private:
  std::expected<void, TunnelError> StartOnExecutor();
  void StopOnExecutor() noexcept;
  void PumpTimeouts(const boost::system::error_code& ec);

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
  void MaybeCloseFinishedFlow(LwipTcpFlow& flow) noexcept;

  static err_t OnTcpAccept(
      void* arg, struct tcp_pcb* newpcb, err_t err);
  static err_t OnTcpRecv(
      void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
  static err_t OnTcpSent(void* arg, struct tcp_pcb* tpcb, u16_t len);
  static void OnTcpError(void* arg, err_t err);

  boost::asio::any_io_executor executor_;
  StackConfiguration config_;
  IFlowEventSink& sink_;
  IFlowRouter& router_;
  ITcpOutbound& tcp_outbound_;
  PacketOutputCallback output_;
  StackCounters counters_;

  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> inflight_bytes_{0};

  struct netif netif_ {};
  bool netif_added_{false};
  boost::asio::steady_timer timeout_timer_;

  FlowId next_flow_id_{1};
  struct tcp_pcb* listener_{nullptr};
  std::unordered_map<FlowId, std::unique_ptr<LwipTcpFlow>> tcp_flows_;
};

}  // namespace fptn::tunnel::flow
