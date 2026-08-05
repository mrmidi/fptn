/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include <cstring>
#include <utility>
#include <vector>

#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>

#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel::flow {

namespace {

IpEndpoint UdpEndpointFromPcb(const struct udp_pcb* pcb, bool remote) {
  IpEndpoint endpoint;
  const ip_addr_t& addr = remote ? pcb->remote_ip : pcb->local_ip;
  endpoint.port = remote ? pcb->remote_port : pcb->local_port;
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

err_t LwipStack::StartUdpListener() {
  struct udp_pcb* pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  if (pcb == nullptr) {
    return ERR_MEM;
  }
  udp_bind_netif(pcb, &netif_);
  // The fork's transparent bind requires a literal NULL address.
  const err_t err = udp_bind(pcb, nullptr, 0);
  if (err != ERR_OK) {
    udp_remove(pcb);
    return err;
  }
  udp_listener_ = pcb;
  udp_recv(pcb, &LwipStack::OnUdpAccept, this);
  return ERR_OK;
}

void LwipStack::OnUdpDropRecv(void* arg, struct udp_pcb*, struct pbuf* p,
    const ip_addr_t*, u16_t) {
  auto* self = static_cast<LwipStack*>(arg);
  if (self != nullptr) {
    self->counters_.udp_drops.fetch_add(1, std::memory_order_relaxed);
  }
  if (p != nullptr) {
    pbuf_free(p);
  }
}

void LwipStack::StopUdpFlows() noexcept {
  for (auto& entry : udp_flows_) {
    if (entry.second->pcb != nullptr) {
      udp_recv(entry.second->pcb, nullptr, nullptr);
      udp_remove(entry.second->pcb);
    }
  }
  udp_flows_.clear();
  counters_.active_udp_flows.store(0, std::memory_order_relaxed);

  for (struct udp_pcb* pcb : rejected_udp_pcbs_) {
    udp_recv(pcb, nullptr, nullptr);
    udp_remove(pcb);
  }
  rejected_udp_pcbs_.clear();

  if (udp_listener_ != nullptr) {
    udp_recv(udp_listener_, nullptr, nullptr);
    udp_remove(udp_listener_);
    udp_listener_ = nullptr;
  }
}

LwipUdpFlow* LwipStack::FindUdpFlow(FlowId flow) noexcept {
  const auto it = udp_flows_.find(flow);
  return it == udp_flows_.end() ? nullptr : it->second.get();
}

void LwipStack::DestroyUdpFlow(FlowId flow) noexcept {
  const auto it = udp_flows_.find(flow);
  if (it == udp_flows_.end()) {
    return;
  }
  if (it->second->pcb != nullptr) {
    udp_recv(it->second->pcb, nullptr, nullptr);
    udp_remove(it->second->pcb);
  }
  udp_flows_.erase(it);
  counters_.active_udp_flows.fetch_sub(1, std::memory_order_relaxed);

  if (!rejected_udp_pcbs_.empty()) {
    struct udp_pcb* rejected = rejected_udp_pcbs_.back();
    rejected_udp_pcbs_.pop_back();
    udp_recv(rejected, nullptr, nullptr);
    udp_remove(rejected);
  }
}

// NOLINTNEXTLINE(bugprone-exception-escape): rare push_back failure tolerated.
void LwipStack::AbandonUdpFlowToRejected(FlowId flow) noexcept {
  const auto it = udp_flows_.find(flow);
  if (it == udp_flows_.end()) {
    return;
  }
  struct udp_pcb* pcb = it->second->pcb;
  it->second->pcb = nullptr;
  udp_flows_.erase(it);
  counters_.active_udp_flows.fetch_sub(1, std::memory_order_relaxed);

  if (pcb != nullptr) {
    // Keep the pcb installed with a dropping handler so the fork's accept
    // loop finds a matching pcb and does not recreate one per datagram.
    udp_recv(pcb, &LwipStack::OnUdpDropRecv, this);
    rejected_udp_pcbs_.push_back(pcb);
  }
}

void LwipStack::OnUdpAccept(void* arg, struct udp_pcb* pcb, struct pbuf* /*p*/,
    const ip_addr_t* addr, u16_t port) {
  auto* self = static_cast<LwipStack*>(arg);
  if (self == nullptr || pcb == nullptr || !self->IsRunning()) {
    return;
  }

  if (self->udp_flows_.size() >= self->config_.max_udp_associations) {
    // The fork re-runs its accept loop after this callback returns and
    // recreates a pcb for any tuple that has no matching pcb. Removing the
    // pcb here would loop forever, so keep it with a dropping recv handler
    // until an association slot frees up.
    self->counters_.udp_drops.fetch_add(1, std::memory_order_relaxed);
    udp_recv(pcb, &LwipStack::OnUdpDropRecv, self);
    self->rejected_udp_pcbs_.push_back(pcb);
    return;
  }

  auto flow = std::make_unique<LwipUdpFlow>();
  flow->id = self->next_flow_id_++;
  flow->pcb = pcb;
  flow->last_activity = std::chrono::steady_clock::now();
  flow->metadata.id = flow->id;
  flow->metadata.protocol = TransportProtocol::udp;
  flow->metadata.source = UdpEndpointFromPcb(pcb, true);
  if (addr != nullptr) {
    if (IP_IS_V4_VAL(*addr)) {
      flow->metadata.destination.address = boost::asio::ip::make_address_v4(
          lwip_ntohl(ip_2_ip4(addr)->addr));
    } else {
      boost::asio::ip::address_v6::bytes_type bytes{};
      std::memcpy(bytes.data(), ip_2_ip6(addr)->addr, bytes.size());
      flow->metadata.destination.address =
          boost::asio::ip::address_v6(bytes);
    }
    flow->metadata.destination.port = port;
  }

  LwipUdpFlow* state = flow.get();
  state->stack = self;
  self->udp_flows_.emplace(flow->id, std::move(flow));
  const std::uint64_t active = self->counters_.active_udp_flows.fetch_add(
      1, std::memory_order_relaxed) + 1;
  auto peak = self->counters_.peak_udp_flows.load(std::memory_order_relaxed);
  while (active > peak &&
      !self->counters_.peak_udp_flows.compare_exchange_weak(
          peak, active, std::memory_order_relaxed)) {
  }

  udp_recv(pcb, &LwipStack::OnUdpFlowRecv, state);

  // The fork re-dispatches the current datagram after this callback returns
  // and expects the generated pcb to still be in the pcb list. Nothing in
  // this section may remove it synchronously: rejected tuples are abandoned
  // to the drop list, and outbound resets detected via udp_in_accept_ are
  // abandoned the same way.
  self->udp_in_accept_ = true;
  const RouteAction action = self->router_.Match(state->metadata);
  if (action != RouteAction::direct) {
    self->counters_.udp_drops.fetch_add(1, std::memory_order_relaxed);
    self->AbandonUdpFlowToRejected(state->id);
    self->udp_in_accept_ = false;
    return;
  }
  self->udp_outbound_.Open(state->metadata, *self);
  self->udp_in_accept_ = false;
}

void LwipStack::OnUdpFlowRecv(void* arg, struct udp_pcb*, struct pbuf* p,
    const ip_addr_t*, u16_t) {
  auto* flow = static_cast<LwipUdpFlow*>(arg);
  if (flow == nullptr || flow->stack == nullptr) {
    if (p != nullptr) {
      pbuf_free(p);
    }
    return;
  }
  LwipStack& self = *flow->stack;
  if (p == nullptr) {
    return;
  }

  flow->last_activity = std::chrono::steady_clock::now();

  OwnedBuffer payload(p->tot_len);
  pbuf_copy_partial(p, payload.data(), p->tot_len, 0);
  pbuf_free(p);
  if (payload.empty()) {
    return;
  }

  self.sink_.OnUdpDatagram(flow->metadata, payload);
  const BufferView view{.data = payload.data(), .size = payload.size()};
  if (self.udp_outbound_.Send(flow->id, view) !=
      OutboundAdmission::accepted) {
    self.counters_.udp_drops.fetch_add(1, std::memory_order_relaxed);
  }
}

WriteResult LwipStack::WriteUdp(
    FlowId flow_id, IpEndpoint, BufferView payload) noexcept {
  LwipUdpFlow* flow = FindUdpFlow(flow_id);
  if (flow == nullptr || flow->pcb == nullptr || payload.size == 0 ||
      payload.size > 0xFFFFU - 8U) {
    return WriteResult::flow_closed;
  }

  flow->last_activity = std::chrono::steady_clock::now();

  struct pbuf* p = pbuf_alloc(
      PBUF_TRANSPORT, static_cast<u16_t>(payload.size), PBUF_RAM);
  if (p == nullptr) {
    return WriteResult::queue_full;
  }
  std::memcpy(p->payload, payload.data, payload.size);
  const err_t err = udp_send(flow->pcb, p);
  pbuf_free(p);
  return err == ERR_OK ? WriteResult::accepted : WriteResult::flow_closed;
}

void LwipStack::OnUdpDatagramReceived(FlowId flow_id, OwnedBuffer payload) {
  if (payload.empty()) {
    return;
  }
  const BufferView view{.data = payload.data(), .size = payload.size()};
  if (WriteUdp(flow_id, IpEndpoint{}, view) != WriteResult::accepted) {
    counters_.udp_drops.fetch_add(1, std::memory_order_relaxed);
  }
}

void LwipStack::OnUdpReset(FlowId flow_id, FlowError) {
  if (udp_in_accept_) {
    // Called synchronously from the outbound's Open() during the accept
    // dispatch: the generated pcb must survive the fork's re-dispatch.
    AbandonUdpFlowToRejected(flow_id);
    return;
  }
  DestroyUdpFlow(flow_id);
}

void LwipStack::ScheduleUdpExpirySweep() {
  if (udp_expiry_scheduled_ || !IsRunning()) {
    return;
  }
  udp_expiry_scheduled_ = true;
  udp_expiry_timer_.expires_after(config_.udp_idle_timeout);
  std::weak_ptr<StackLifeToken> weak_life = life_;
  udp_expiry_timer_.async_wait(
      [this, weak_life](const boost::system::error_code& ec) {
        auto life = weak_life.lock();
        if (!life) {
          return;
        }
        life->in_flight.fetch_add(1, std::memory_order_acq_rel);
        if (life->alive.load(std::memory_order_acquire)) {
          UdpExpirySweep(ec);
        }
        life->in_flight.fetch_sub(1, std::memory_order_acq_rel);
      });
}

void LwipStack::UdpExpirySweep(const boost::system::error_code& ec) {
  udp_expiry_scheduled_ = false;
  if (ec || !IsRunning()) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  std::vector<FlowId> expired;
  for (const auto& entry : udp_flows_) {
    if (now - entry.second->last_activity > config_.udp_idle_timeout) {
      expired.push_back(entry.first);
    }
  }
  for (const FlowId flow_id : expired) {
    udp_outbound_.Reset(flow_id);
    DestroyUdpFlow(flow_id);
  }

  ScheduleUdpExpirySweep();
}

}  // namespace fptn::tunnel::flow
