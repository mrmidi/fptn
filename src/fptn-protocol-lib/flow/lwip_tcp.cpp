/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include <cstring>
#include <utility>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <lwip/ip_addr.h>

#include "fptn-protocol-lib/flow/pbuf_buffer_sequence.h"

namespace fptn::tunnel::flow {

namespace {

constexpr int kListenBacklog = 8;

// NOLINTNEXTLINE(bugprone-exception-escape): integer/bytes ctors do not throw.
IpEndpoint ToIpEndpoint(const ip_addr_t& addr, std::uint16_t port) noexcept {
  IpEndpoint endpoint;
  endpoint.port = port;
  if (IP_IS_V4_VAL(addr)) {
    endpoint.address = boost::asio::ip::make_address_v4(
        lwip_ntohl(ip_2_ip4(&addr)->addr));
  } else {
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), ip_2_ip6(&addr)->addr, bytes.size());
    endpoint.address = boost::asio::ip::address_v6(bytes);
  }
  return endpoint;
}

}  // namespace

err_t LwipStack::StartTcpListener() {
  struct tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (pcb == nullptr) {
    return ERR_MEM;
  }
  tcp_arg(pcb, this);

  tcp_bind_netif(pcb, &netif_);
  // The fork's transparent bind requires a literal NULL address
  // (IP_ANY_TYPE is a non-NULL pointer and would take the normal path).
  err_t err = tcp_bind(pcb, nullptr, 0);
  if (err != ERR_OK) {
    tcp_close(pcb);
    return err;
  }

  struct tcp_pcb* listening = tcp_listen_with_backlog(pcb, kListenBacklog);
  if (listening == nullptr) {
    tcp_close(pcb);
    return ERR_MEM;
  }
  listener_ = listening;
  tcp_accept(listener_, &LwipStack::OnTcpAccept);
  return ERR_OK;
}

void LwipStack::StopTcpFlows() noexcept {
  for (auto& entry : tcp_flows_) {
    LwipTcpFlow* flow = entry.second.get();
    if (flow->pcb != nullptr && !flow->closing) {
      tcp_arg(flow->pcb, nullptr);
      tcp_abort(flow->pcb);
    }
    for (const auto& pending : flow->pending_to_outbound) {
      pbuf_free(pending.pbuf);
    }
  }
  tcp_flows_.clear();
  counters_.active_tcp_flows.store(0, std::memory_order_relaxed);

  if (listener_ != nullptr) {
    tcp_arg(listener_, nullptr);
    tcp_close(listener_);
    listener_ = nullptr;
  }
}

LwipTcpFlow* LwipStack::FindTcpFlow(FlowId flow) noexcept {
  const auto it = tcp_flows_.find(flow);
  return it == tcp_flows_.end() ? nullptr : it->second.get();
}

void LwipStack::DestroyTcpFlow(FlowId flow) noexcept {
  const auto it = tcp_flows_.find(flow);
  if (it == tcp_flows_.end()) {
    return;
  }
  LwipTcpFlow* state = it->second.get();
  for (const auto& pending : state->pending_to_outbound) {
    pbuf_free(pending.pbuf);
  }
  tcp_flows_.erase(it);
  counters_.active_tcp_flows.fetch_sub(1, std::memory_order_relaxed);
}

void LwipStack::MaybeFinishTcpOutbound(LwipTcpFlow& flow) noexcept {
  // The application FIN may arrive while lwIP still retains backpressured
  // pbufs. Forwarding Finish() now would let the outbound drain its own
  // queue, shut its send side, and then receive the retained bytes after
  // shutdown — truncating the stream. Defer until the retention drains.
  if (!flow.app_fin_received || flow.outbound_finish_sent ||
      !flow.pending_to_outbound.empty()) {
    return;
  }
  flow.outbound_finish_sent = true;
  tcp_outbound_.Finish(flow.id);
}

err_t LwipStack::MaybeCloseFinishedFlow(LwipTcpFlow& flow) noexcept {
  if (flow.closing || flow.pcb == nullptr) {
    return ERR_OK;
  }
  if (!flow.app_fin_received || !flow.outbound_finished ||
      !flow.pending_to_outbound.empty()) {
    return ERR_OK;
  }
  return CloseFinishedTcpFlow(flow);
}

err_t LwipStack::CloseFinishedTcpFlow(LwipTcpFlow& flow) noexcept {
  flow.closing = true;
  tcp_arg(flow.pcb, nullptr);
  tcp_recv(flow.pcb, nullptr);
  tcp_sent(flow.pcb, nullptr);
  tcp_err(flow.pcb, nullptr);
  // tcp_close() can fail with data still queued or unacknowledged; the pcb
  // must then be aborted, and the enclosing lwIP callback must be told via
  // ERR_ABRT that the pcb is gone.
  const bool closed = tcp_api_.close(flow.pcb) == ERR_OK;
  if (!closed) {
    tcp_api_.abort(flow.pcb);
  }
  flow.pcb = nullptr;

  // Capture the id before erasing: the map owns the flow object, so the
  // reference becomes dangling the moment erase() runs.
  const FlowId flow_id = flow.id;
  const auto it = tcp_flows_.find(flow_id);
  if (it != tcp_flows_.end()) {
    tcp_flows_.erase(it);
    counters_.active_tcp_flows.fetch_sub(1, std::memory_order_relaxed);
  }
  tcp_outbound_.Complete(flow_id);
  return closed ? ERR_OK : ERR_ABRT;
}

void LwipStack::DrainPendingToOutbound(LwipTcpFlow& flow) noexcept {
  while (!flow.pending_to_outbound.empty()) {
    PendingTcpData& front = flow.pending_to_outbound.front();
    const PbufBufferSequence sequence(front.pbuf);
    const OutboundAdmission admission =
        tcp_outbound_.Write(flow.id, sequence.View());
    if (admission == OutboundAdmission::queue_full) {
      return;
    }
    if (admission == OutboundAdmission::flow_closed) {
      ResetTcp(flow.id);
      return;
    }
    if (flow.pcb != nullptr) {
      tcp_recved(flow.pcb, static_cast<u16_t>(front.length));
    }
    pbuf_free(front.pbuf);
    flow.pending_to_outbound.pop_front();
  }
  // The retention just emptied: an application FIN that was held back by
  // MaybeFinishTcpOutbound can now be forwarded, and a fully-finished flow
  // can close.
  MaybeFinishTcpOutbound(flow);
  // ERR_ABRT only matters inside a lwIP callback; this runs from the
  // outbound's writable notification, so the abort result is not propagated.
  static_cast<void>(MaybeCloseFinishedFlow(flow));
}

err_t LwipStack::OnTcpAccept(void* arg, struct tcp_pcb* newpcb, err_t err) {
  auto* self = static_cast<LwipStack*>(arg);
  if (self == nullptr || err != ERR_OK || newpcb == nullptr) {
    return ERR_OK;
  }
  if (!self->IsRunning()) {
    tcp_abort(newpcb);
    return ERR_ABRT;
  }

  auto flow = std::make_unique<LwipTcpFlow>();
  flow->stack = self;
  flow->id = self->next_flow_id_++;
  flow->pcb = newpcb;
  flow->metadata.id = flow->id;
  flow->metadata.protocol = TransportProtocol::tcp;
  flow->metadata.source =
      ToIpEndpoint(newpcb->remote_ip, newpcb->remote_port);
  flow->metadata.destination =
      ToIpEndpoint(newpcb->local_ip, newpcb->local_port);

  LwipTcpFlow* state = flow.get();
  self->tcp_flows_.emplace(flow->id, std::move(flow));
  const std::uint64_t active = self->counters_.active_tcp_flows.fetch_add(
      1, std::memory_order_relaxed) + 1;
  auto peak = self->counters_.peak_tcp_flows.load(std::memory_order_relaxed);
  while (active > peak &&
      !self->counters_.peak_tcp_flows.compare_exchange_weak(
          peak, active, std::memory_order_relaxed)) {
  }

  tcp_arg(newpcb, state);
  tcp_recv(newpcb, &LwipStack::OnTcpRecv);
  tcp_sent(newpcb, &LwipStack::OnTcpSent);
  tcp_err(newpcb, &LwipStack::OnTcpError);
  if (self->listener_ != nullptr) {
    tcp_accepted(self->listener_);
  }

  self->sink_.OnTcpOpen(state->metadata);

  const RouteAction action = self->router_.Match(state->metadata);
  if (action != RouteAction::direct) {
    self->ResetTcp(state->id);
    // ResetTcp aborted the pcb: lwIP must be told it is gone.
    return ERR_ABRT;
  }
  // Open() can synchronously fail (outbound stopping, socket.open() error)
  // and re-enter OnOutboundReset() -> ResetTcp(), which erases the
  // map-owned flow object and leaves `state` dangling. Capture everything
  // Open needs before the call; never touch `state` afterwards.
  const FlowId flow_id = state->id;
  const FlowMetadata metadata = state->metadata;
  self->tcp_outbound_.Open(metadata, *self);
  if (self->FindTcpFlow(flow_id) == nullptr) {
    // The outbound reported failure synchronously and reset the flow,
    // aborting the pcb.
    return ERR_ABRT;
  }
  return ERR_OK;
}

err_t LwipStack::OnTcpRecv(
    void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
  auto* flow = static_cast<LwipTcpFlow*>(arg);
  if (flow == nullptr) {
    if (p != nullptr) {
      pbuf_free(p);
    }
    return ERR_OK;
  }
  LwipStack& self = *flow->stack;

  if (err != ERR_OK || flow->closing) {
    if (p != nullptr) {
      pbuf_free(p);
    }
    return ERR_OK;
  }

  if (p == nullptr) {
    flow->app_fin_received = true;
    // Only forward Finish once lwIP no longer retains backpressured pbufs;
    // otherwise the outbound could shut its send side before the retained
    // bytes are admitted (truncation). MaybeFinishTcpOutbound applies the
    // gate and is re-attempted from DrainPendingToOutbound.
    self.MaybeFinishTcpOutbound(*flow);
    // Propagate ERR_ABRT when the close had to abort the pcb; lwIP requires
    // ERR_ABRT from any callback that aborts its pcb.
    return self.MaybeCloseFinishedFlow(*flow);
  }

  const PbufBufferSequence sequence(p);
  if (sequence.size_bytes() != p->tot_len) {
    // The sequence caps (segments/bytes) would silently truncate the stream;
    // refuse the segment instead of acknowledging partial data.
    pbuf_free(p);
    self.ResetTcp(flow->id);
    return ERR_ABRT;
  }
  const OutboundAdmission admission =
      self.tcp_outbound_.Write(flow->id, sequence.View());
  if (admission == OutboundAdmission::accepted) {
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
  }
  if (admission == OutboundAdmission::queue_full) {
    flow->pending_to_outbound.push_back(PendingTcpData{
        .pbuf = p, .length = static_cast<std::uint32_t>(p->tot_len)});
    self.counters_.tcp_backpressure_events.fetch_add(
        1, std::memory_order_relaxed);
    return ERR_OK;
  }
  pbuf_free(p);
  self.ResetTcp(flow->id);
  // ResetTcp aborted the pcb: lwIP must be told it is gone.
  return ERR_ABRT;
}

err_t LwipStack::OnTcpSent(void* arg, struct tcp_pcb*, u16_t) {
  auto* flow = static_cast<LwipTcpFlow*>(arg);
  if (flow == nullptr || flow->closing) {
    return ERR_OK;
  }
  flow->stack->tcp_outbound_.StackWindowOpen(flow->id);
  return ERR_OK;
}

void LwipStack::OnTcpError(void* arg, err_t) {
  auto* flow = static_cast<LwipTcpFlow*>(arg);
  if (flow == nullptr) {
    return;
  }
  LwipStack& self = *flow->stack;
  flow->pcb = nullptr;
  self.counters_.tcp_resets.fetch_add(1, std::memory_order_relaxed);
  self.tcp_outbound_.Reset(flow->id);
  self.DestroyTcpFlow(flow->id);
}

WriteResult LwipStack::WriteTcp(FlowId flow_id, BufferSequence data) noexcept {
  LwipTcpFlow* flow = FindTcpFlow(flow_id);
  if (flow == nullptr || flow->closing || flow->pcb == nullptr) {
    return WriteResult::flow_closed;
  }
  std::size_t total = 0;
  for (const auto& view : data) {
    total += view.size;
  }
  if (total == 0) {
    return WriteResult::accepted;
  }
  if (tcp_sndbuf(flow->pcb) < total) {
    return WriteResult::queue_full;
  }
  for (const auto& view : data) {
    if (view.size == 0) {
      continue;
    }
    if (tcp_write(flow->pcb, view.data, static_cast<u16_t>(view.size),
            TCP_WRITE_FLAG_COPY) != ERR_OK) {
      return WriteResult::queue_full;
    }
  }
  tcp_output(flow->pcb);
  return WriteResult::accepted;
}

void LwipStack::FinishTcp(FlowId flow_id) noexcept {
  LwipTcpFlow* flow = FindTcpFlow(flow_id);
  if (flow == nullptr || flow->closing) {
    return;
  }
  flow->outbound_finished = true;
  if (flow->pcb != nullptr) {
    tcp_shutdown(flow->pcb, 0, 1);
  }
  MaybeCloseFinishedFlow(*flow);
}

void LwipStack::ResetTcp(FlowId flow_id) noexcept {
  LwipTcpFlow* flow = FindTcpFlow(flow_id);
  if (flow == nullptr) {
    return;
  }
  counters_.tcp_resets.fetch_add(1, std::memory_order_relaxed);
  if (flow->pcb != nullptr && !flow->closing) {
    tcp_arg(flow->pcb, nullptr);
    tcp_abort(flow->pcb);
    flow->pcb = nullptr;
  }
  DestroyTcpFlow(flow_id);
}

void LwipStack::OnOutboundConnected(FlowId) {}

bool LwipStack::OnOutboundData(FlowId flow_id, OwnedBuffer& data) {
  if (data.empty()) {
    return true;
  }
  const BufferView view{.data = data.data(), .size = data.size()};
  const BufferSequence sequence{&view, 1};
  if (WriteTcp(flow_id, sequence) != WriteResult::accepted) {
    return false;
  }
  data.clear();
  return true;
}

void LwipStack::OnOutboundFinished(FlowId flow_id) {
  FinishTcp(flow_id);
}

void LwipStack::OnOutboundReset(FlowId flow_id, FlowError) {
  ResetTcp(flow_id);
}

void LwipStack::OnOutboundWritable(FlowId flow_id) {
  LwipTcpFlow* flow = FindTcpFlow(flow_id);
  if (flow == nullptr || flow->closing) {
    return;
  }
  DrainPendingToOutbound(*flow);
}

}  // namespace fptn::tunnel::flow
