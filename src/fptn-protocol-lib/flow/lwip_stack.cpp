/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip6_addr.h>
#include <lwip/pbuf.h>
#include <lwip/timeouts.h>

namespace fptn::tunnel::flow {

namespace {

constexpr std::chrono::milliseconds kTimeoutPumpInterval{125};

// lwip_init() is not reentrant: a second call re-registers the cyclic
// timers while nodes from the previous run are still linked into the
// timeout list and already recycled by memp_init, corrupting both lists.
// Initialize once per process; stack restarts rebuild netif/PCBs only.
void EnsureLwipInitialized() {
  static std::once_flag flag;
  std::call_once(flag, [] { lwip_init(); });
}

}  // namespace

LwipStack::LwipStack(boost::asio::any_io_executor executor,
    StackConfiguration config,
    IFlowEventSink& sink,
    IFlowRouter& router,
    ITcpOutbound& tcp_outbound,
    PacketOutputCallback output)
    : executor_(std::move(executor)),
      config_(std::move(config)),
      sink_(sink),
      router_(router),
      tcp_outbound_(tcp_outbound),
      output_(std::move(output)),
      timeout_timer_(executor_) {}

LwipStack::~LwipStack() {
  if (IsRunning()) {
    Stop();
  }
}

std::expected<void, TunnelError> LwipStack::Start() {
  if (IsRunning()) {
    return std::unexpected(TunnelError::already_running);
  }
  std::promise<std::expected<void, TunnelError>> done;
  auto future = done.get_future();
  boost::asio::post(executor_, [this, &done] {
    done.set_value(StartOnExecutor());
  });
  return future.get();
}

void LwipStack::Stop() noexcept {
  if (!IsRunning()) {
    return;
  }
  try {
    std::promise<void> done;
    auto future = done.get_future();
    boost::asio::post(executor_, [this, &done] {
      StopOnExecutor();
      done.set_value();
    });
    future.get();
  } catch (...) {
    running_.store(false, std::memory_order_release);
  }
}

std::expected<void, TunnelError> LwipStack::StartOnExecutor() {
  if (running_.load(std::memory_order_acquire)) {
    return std::unexpected(TunnelError::already_running);
  }

  ip4_addr_t addr4;
  if (!ip4addr_aton(config_.tun_ipv4.c_str(), &addr4)) {
    return std::unexpected(TunnelError::invalid_configuration);
  }
  ip6_addr_t addr6;
  const bool have_ipv6 = !config_.tun_ipv6.empty();
  if (have_ipv6 && !ip6addr_aton(config_.tun_ipv6.c_str(), &addr6)) {
    return std::unexpected(TunnelError::invalid_configuration);
  }

  EnsureLwipInitialized();

  if (netif_add_noaddr(&netif_, this, &LwipStack::NetifInit, ip_input) ==
      nullptr) {
    return std::unexpected(TunnelError::start_failed);
  }
  netif_added_ = true;

  netif_set_flags(
      &netif_, NETIF_FLAG_PRETEND_TCP | NETIF_FLAG_PRETEND_UDP);

  netif_set_ipaddr(&netif_, &addr4);
  if (have_ipv6) {
    netif_ip6_addr_set(&netif_, 0, &addr6);
    netif_ip6_addr_set_state(&netif_, 0, IP6_ADDR_PREFERRED);
  }

  netif_set_default(&netif_);
  netif_set_up(&netif_);
  netif_set_link_up(&netif_);

  auto listener_result = [&] {
    const err_t err = StartTcpListener();
    return err == ERR_OK
        ? std::expected<void, TunnelError>{}
        : std::unexpected(TunnelError::start_failed);
  }();
  if (!listener_result.has_value()) {
    netif_set_down(&netif_);
    netif_remove(&netif_);
    netif_added_ = false;
    std::memset(&netif_, 0, sizeof(netif_));
    return listener_result;
  }

  running_.store(true, std::memory_order_release);

  timeout_timer_.expires_after(kTimeoutPumpInterval);
  timeout_timer_.async_wait([this](const boost::system::error_code& ec) {
    PumpTimeouts(ec);
  });
  return {};
}

void LwipStack::StopOnExecutor() noexcept {
  if (!running_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }

  timeout_timer_.cancel();

  StopTcpFlows();

  if (netif_added_) {
    netif_set_link_down(&netif_);
    netif_set_down(&netif_);
    netif_remove(&netif_);
    netif_added_ = false;
    std::memset(&netif_, 0, sizeof(netif_));
  }
}

void LwipStack::PumpTimeouts(const boost::system::error_code& ec) {
  if (ec || !IsRunning()) {
    return;
  }
  sys_check_timeouts();
  timeout_timer_.expires_after(kTimeoutPumpInterval);
  timeout_timer_.async_wait([this](const boost::system::error_code& next_ec) {
    PumpTimeouts(next_ec);
  });
}

PacketInputResult LwipStack::InputPackets(PacketBatchView packets) noexcept {
  if (!IsRunning()) {
    return PacketInputResult::transport_stopped;
  }

  std::uint64_t total_bytes = 0;
  for (const auto& lease : packets) {
    if (lease.bytes == nullptr || lease.length == 0 ||
        lease.length > 0xFFFFu) {
      return PacketInputResult::invalid_packet;
    }
    if (lease.ip_version != 0 && lease.ip_version != 4 &&
        lease.ip_version != 6) {
      return PacketInputResult::invalid_packet;
    }
    total_bytes += lease.length;
  }

  const std::uint64_t previous =
      inflight_bytes_.fetch_add(total_bytes, std::memory_order_acq_rel);
  if (previous + total_bytes > config_.max_ingress_inflight_bytes) {
    inflight_bytes_.fetch_sub(total_bytes, std::memory_order_acq_rel);
    return PacketInputResult::queue_full;
  }

  auto pending = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
  pending->reserve(packets.size());
  for (const auto& lease : packets) {
    pending->emplace_back(lease.bytes, lease.bytes + lease.length);
  }
  counters_.input_packets.fetch_add(packets.size(), std::memory_order_relaxed);
  counters_.input_bytes.fetch_add(total_bytes, std::memory_order_relaxed);

  try {
    boost::asio::post(executor_, [this, pending, total_bytes] {
      for (const auto& data : *pending) {
        struct pbuf* p = pbuf_alloc(
            PBUF_RAW, static_cast<u16_t>(data.size()), PBUF_RAM);
        if (p == nullptr) {
          counters_.dropped_packets.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        std::memcpy(p->payload, data.data(), data.size());
        counters_.ingress_copy_packets.fetch_add(
            1, std::memory_order_relaxed);
        counters_.ingress_copy_bytes.fetch_add(
            data.size(), std::memory_order_relaxed);
        if (ip_input(p, &netif_) != ERR_OK) {
          pbuf_free(p);
        }
      }
      inflight_bytes_.fetch_sub(total_bytes, std::memory_order_acq_rel);
    });
  } catch (...) {
    inflight_bytes_.fetch_sub(total_bytes, std::memory_order_acq_rel);
    return PacketInputResult::queue_full;
  }
  return PacketInputResult::accepted;
}

err_t LwipStack::NetifInit(struct netif* netif) {
  auto* self = static_cast<LwipStack*>(netif->state);
  netif->name[0] = 'f';
  netif->name[1] = 'p';
  netif->mtu = self->config_.mtu;
  netif->output = &LwipStack::OutputV4;
#if LWIP_IPV6
  netif->output_ip6 = &LwipStack::OutputV6;
#endif
  netif->flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
  return ERR_OK;
}

err_t LwipStack::OutputV4(
    struct netif* netif, struct pbuf* p, const ip4_addr_t*) {
  auto* self = static_cast<LwipStack*>(netif->state);
  return self->OutputPacket(p, 4);
}

err_t LwipStack::OutputV6(
    struct netif* netif, struct pbuf* p, const ip6_addr_t*) {
  auto* self = static_cast<LwipStack*>(netif->state);
  return self->OutputPacket(p, 6);
}

err_t LwipStack::OutputPacket(struct pbuf* p, std::uint8_t ip_version) {
  if (p == nullptr || p->tot_len == 0) {
    return ERR_OK;
  }
  OwnedPacket packet;
  packet.ip_version = ip_version;
  packet.data.resize(p->tot_len);
  pbuf_copy_partial(p, packet.data.data(), p->tot_len, 0);

  counters_.output_packets.fetch_add(1, std::memory_order_relaxed);
  counters_.output_bytes.fetch_add(packet.data.size(),
      std::memory_order_relaxed);
  counters_.egress_coalesce_packets.fetch_add(1, std::memory_order_relaxed);
  counters_.egress_coalesce_bytes.fetch_add(packet.data.size(),
      std::memory_order_relaxed);

  if (output_) {
    OwnedPacketBatch batch;
    batch.push_back(std::move(packet));
    output_(std::move(batch));
  }
  return ERR_OK;
}

WriteResult LwipStack::WriteUdp(FlowId, IpEndpoint, BufferView) noexcept {
  return WriteResult::flow_closed;
}

}  // namespace fptn::tunnel::flow
