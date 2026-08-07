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
#include <new>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_addr.h>
#include <lwip/ip6_frag.h>
#include <lwip/pbuf.h>
#include <lwip/timeouts.h>

namespace fptn::tunnel::flow {

namespace {

constexpr std::chrono::milliseconds kTimeoutPumpInterval{125};

// Egress batch bounds, mirroring the L3 transport's inbound batching so both
// data planes hand the platform comparably sized writes.
constexpr std::size_t kMaxEgressBatchPackets = 32;
constexpr std::size_t kMaxEgressBatchBytes = 64 * 1024;

constexpr std::size_t kIpv4MinHeaderLength = 20;
constexpr std::size_t kIpv6FixedHeaderLength = 40;
constexpr std::uint8_t kIpProtoIcmp = 1;
constexpr std::uint8_t kIpProtoIpv6HopOpts = 0;
constexpr std::uint8_t kIpProtoIpv6Routing = 43;
constexpr std::uint8_t kIpProtoIpv6Fragment = 44;
constexpr std::uint8_t kIpProtoIcmpV6 = 58;
constexpr std::uint8_t kIpProtoIpv6DestOpts = 60;
// Bound the IPv6 extension-header walk; real chains are a handful of
// headers, and anything deeper is treated as malformed.
constexpr int kMaxIpv6ExtensionDepth = 8;

// lwip_init() is not reentrant: a second call re-registers the cyclic
// timers while nodes from the previous run are still linked into the
// timeout list and already recycled by memp_init, corrupting both lists.
// Initialize once per process; stack restarts rebuild netif/PCBs only.
void EnsureLwipInitialized() {
  static std::once_flag flag;
  std::call_once(flag, [] { lwip_init(); });
}

// lwIP global state (pcb lists, netifs, timers) supports exactly one
// active stack instance per process.
std::atomic<bool>& ActiveLwipStackFlag() {
  static std::atomic<bool> active{false};
  return active;
}

}  // namespace

LwipStack::LwipStack(boost::asio::any_io_executor executor,
    StackConfiguration config,
    IFlowEventSink& sink,
    IFlowRouter& router,
    ITcpOutbound& tcp_outbound,
    IUdpOutbound& udp_outbound,
    PacketOutputCallback output)
    : executor_(std::move(executor)),
      config_(std::move(config)),
      sink_(sink),
      router_(router),
      tcp_outbound_(tcp_outbound),
      udp_outbound_(udp_outbound),
      output_(std::move(output)),
      timeout_timer_(executor_),
      udp_expiry_timer_(executor_) {}

LwipStack::~LwipStack() {
  if (IsRunning()) {
    Stop();
  }
  life_->alive.store(false, std::memory_order_release);
  while (life_->in_flight.load(std::memory_order_acquire) != 0) {
    std::this_thread::yield();
  }
}

std::expected<void, TunnelError> LwipStack::Start() {
  if (IsRunning()) {
    return std::unexpected(TunnelError::already_running);
  }
  bool expected = false;
  if (!ActiveLwipStackFlag().compare_exchange_strong(expected, true)) {
    return std::unexpected(TunnelError::already_running);
  }
  stop_teardown_done_.store(false, std::memory_order_release);

  if (OnExecutorThread()) {
    auto result = StartOnExecutor();
    if (!result.has_value()) {
      ActiveLwipStackFlag().store(false, std::memory_order_release);
    }
    return result;
  }

  std::promise<std::expected<void, TunnelError>> done;
  auto future = done.get_future();
  try {
    boost::asio::post(executor_, [this, &done] {
      done.set_value(StartOnExecutor());
    });
  } catch (...) {
    ActiveLwipStackFlag().store(false, std::memory_order_release);
    return std::unexpected(TunnelError::start_failed);
  }
  auto result = future.get();
  if (!result.has_value()) {
    ActiveLwipStackFlag().store(false, std::memory_order_release);
  }
  return result;
}

// NOLINTNEXTLINE(bugprone-exception-escape): rare allocation failures are caught.
void LwipStack::Stop() noexcept {
  if (!IsRunning()) {
    return;
  }
  auto done = std::make_shared<std::promise<void>>();

  if (OnExecutorThread()) {
    // Cannot block on the executor's own thread: run teardown inline if
    // nothing is queued ahead, otherwise finish it asynchronously.
    running_.store(false, std::memory_order_release);
    if (pending_ingress_ops_.load(std::memory_order_acquire) == 0) {
      StopOnExecutor();
    } else {
      try {
        boost::asio::post(executor_, [this, done] { StopDrain(done); });
      } catch (...) {
        StopOnExecutor();
      }
    }
    return;
  }

  auto future = done->get_future();
  try {
    boost::asio::post(executor_, [this, done] { StopDrain(done); });
  } catch (...) {
    running_.store(false, std::memory_order_release);
    StopDrain(done);
    return;
  }
  future.get();
}

// NOLINTNEXTLINE(bugprone-exception-escape): post failure is caught below.
void LwipStack::StopDrain(
    const std::shared_ptr<std::promise<void>>& done) noexcept {
  running_.store(false, std::memory_order_release);
  if (pending_ingress_ops_.load(std::memory_order_acquire) != 0) {
    // Queued ingress handlers run before this re-posted task; retry once
    // they have all executed.
    try {
      boost::asio::post(executor_, [this, done] { StopDrain(done); });
      return;
    } catch (const std::bad_alloc&) {
      StopOnExecutor();
      done->set_value();
      return;
    }
  }
  StopOnExecutor();
  done->set_value();
}

bool LwipStack::OnExecutorThread() const noexcept {
  return executor_thread_id_ != std::thread::id{} &&
         std::this_thread::get_id() == executor_thread_id_;
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

  if (StartUdpListener() != ERR_OK) {
    tcp_arg(listener_, nullptr);
    tcp_close(listener_);
    listener_ = nullptr;
    netif_set_down(&netif_);
    netif_remove(&netif_);
    netif_added_ = false;
    std::memset(&netif_, 0, sizeof(netif_));
    return std::unexpected(TunnelError::start_failed);
  }

  running_.store(true, std::memory_order_release);

  ScheduleUdpExpirySweep();
  ScheduleTimeoutPump();
  return {};
}

// NOLINTNEXTLINE(bugprone-exception-escape): atomic/flag teardown cannot throw.
void LwipStack::StopOnExecutor() noexcept {
  if (stop_teardown_done_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  running_.store(false, std::memory_order_release);

  timeout_timer_.cancel();
  udp_expiry_timer_.cancel();
  udp_expiry_scheduled_ = false;

  StopTcpFlows();
  StopUdpFlows();

  // Deliver whatever the flow teardown just emitted (FIN/RST) plus anything
  // still pending, before the netif goes away. A deferred flush may also be
  // in the queue; FlushEgress is idempotent once the batch is empty.
  FlushEgress();

  // Age out process-wide IP reassembly state. Fragments always take the
  // copy fallback, so the reass queues hold lwIP-owned pbufs (no leases),
  // but without this they would outlive Stop for up to MAXAGE timer ticks.
  // Expiry frees datagrams; it never delivers them, so this is safe to run
  // during teardown.
#if IP_REASSEMBLY
  for (int i = 0; i < IP_REASS_MAXAGE; ++i) {
    ip_reass_tmr();
  }
#endif
#if LWIP_IPV6 && LWIP_IPV6_REASS
  for (int i = 0; i < IPV6_REASS_MAXAGE; ++i) {
    ip6_reass_tmr();
  }
#endif

  if (netif_added_) {
    netif_set_link_down(&netif_);
    netif_set_down(&netif_);
    netif_remove(&netif_);
    netif_added_ = false;
    std::memset(&netif_, 0, sizeof(netif_));
  }

  ActiveLwipStackFlag().store(false, std::memory_order_release);
}

void LwipStack::PumpTimeouts(const boost::system::error_code& ec) {
  if (ec || !IsRunning()) {
    return;
  }
  sys_check_timeouts();
  ScheduleTimeoutPump();
}

void LwipStack::ScheduleTimeoutPump() {
  timeout_timer_.expires_after(kTimeoutPumpInterval);
  std::weak_ptr<StackLifeToken> weak_life = life_;
  timeout_timer_.async_wait(
      [this, weak_life](const boost::system::error_code& next_ec) {
        auto life = weak_life.lock();
        if (!life) {
          return;
        }
        life->in_flight.fetch_add(1, std::memory_order_acq_rel);
        if (life->alive.load(std::memory_order_acquire)) {
          PumpTimeouts(next_ec);
        }
        life->in_flight.fetch_sub(1, std::memory_order_acq_rel);
      });
}

bool LwipStack::RequiresWritableIngress(
    const std::uint8_t* bytes, std::uint32_t length) noexcept {
  // Packets that lwIP may modify in place must take the copy fallback:
  // borrowed lease memory (e.g. immutable NSData) is not writable.
  if (bytes == nullptr || length < kIpv4MinHeaderLength) {
    return true;
  }
  const std::uint8_t version = bytes[0] >> 4;
  if (version == 4) {
    // ICMP echo replies are rewritten in place.
    if (bytes[9] == kIpProtoIcmp) {
      return true;
    }
    // IPv4 reassembly overwrites the fragment's IP header with an
    // ip_reass_helper, so any fragment (MF set or nonzero offset) needs
    // writable storage.
    const std::uint16_t flags_fragment = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[6]) << 8) | bytes[7]);
    const bool more_fragments = (flags_fragment & 0x2000U) != 0;
    const std::uint16_t fragment_offset =
        static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
    return more_fragments || fragment_offset != 0;
  }
  if (version == 6) {
    if (length < kIpv6FixedHeaderLength) {
      return true;
    }
    std::uint8_t next_header = bytes[6];
    std::size_t offset = kIpv6FixedHeaderLength;
    for (int depth = 0; depth < kMaxIpv6ExtensionDepth; ++depth) {
      if (next_header == kIpProtoIcmpV6) {
        // Echo replies are rewritten in place.
        return true;
      }
      if (next_header == kIpProtoIpv6Fragment) {
        // IPv6 reassembly needs writable fragment storage.
        return true;
      }
      if (next_header == kIpProtoIpv6HopOpts ||
          next_header == kIpProtoIpv6Routing ||
          next_header == kIpProtoIpv6DestOpts) {
        if (offset + 2 > length) {
          // Malformed chain: prefer the safe copy path.
          return true;
        }
        const std::uint8_t extension_next = bytes[offset];
        const std::size_t extension_length =
            (static_cast<std::size_t>(bytes[offset + 1]) + 1) * 8;
        next_header = extension_next;
        offset += extension_length;
        continue;
      }
      // TCP, UDP and any other terminal protocol: lwIP only reads.
      return false;
    }
    return true;
  }
  return true;
}

IngressLeaseWrapper* LwipStack::AcquireIngressWrapper() noexcept {
  if (!ingress_wrapper_free_.empty()) {
    auto* wrapper = ingress_wrapper_free_.back();
    ingress_wrapper_free_.pop_back();
    return wrapper;
  }
  if (ingress_wrapper_storage_.size() >= kIngressWrapperPoolCapacity) {
    return nullptr;
  }
  try {
    ingress_wrapper_storage_.push_back(
        std::make_unique<IngressLeaseWrapper>());
  } catch (const std::bad_alloc&) {
    return nullptr;
  }
  auto* wrapper = ingress_wrapper_storage_.back().get();
  wrapper->stack = this;
  return wrapper;
}

void LwipStack::ReturnIngressWrapper(IngressLeaseWrapper* wrapper) noexcept {
  wrapper->lease = PacketLease{};
  ingress_wrapper_free_.push_back(wrapper);
}

void LwipStack::FreeIngressLeasePbuf(struct pbuf* p) noexcept {
  // `p` is the embedded pbuf of the wrapper's leading pbuf_custom member.
  auto* wrapper = reinterpret_cast<IngressLeaseWrapper*>(p);
  ReleasePacketLease(wrapper->lease);
  wrapper->stack->ReturnIngressWrapper(wrapper);
}

void LwipStack::IngestLease(PacketLease lease) noexcept {
  const auto length = lease.length;
  if (!RequiresWritableIngress(lease.bytes, length)) {
    IngressLeaseWrapper* wrapper = AcquireIngressWrapper();
    if (wrapper != nullptr) {
      wrapper->lease = lease;
      wrapper->custom.custom_free_function = &LwipStack::FreeIngressLeasePbuf;
      struct pbuf* p = pbuf_alloced_custom(PBUF_RAW,
          static_cast<u16_t>(length), PBUF_REF, &wrapper->custom,
          const_cast<std::uint8_t*>(lease.bytes),
          static_cast<u16_t>(length));
      if (p != nullptr) {
        counters_.ingress_zero_copy_packets.fetch_add(
            1, std::memory_order_relaxed);
        counters_.ingress_zero_copy_bytes.fetch_add(
            length, std::memory_order_relaxed);
        if (ip_input(p, &netif_) != ERR_OK) {
          // Frees through the custom callback, releasing the lease.
          pbuf_free(p);
        }
        return;
      }
      // pbuf_alloced_custom rejected the buffer; recycle and fall back.
      wrapper->lease = PacketLease{};
      ReturnIngressWrapper(wrapper);
    } else {
      counters_.lease_pool_exhaustions.fetch_add(1, std::memory_order_relaxed);
    }
  }

  // Counted copy fallback: ICMP/ICMPv6, fragments, malformed headers,
  // exhausted wrapper pool, or pbuf_alloced_custom rejection.
  struct pbuf* p =
      pbuf_alloc(PBUF_RAW, static_cast<u16_t>(length), PBUF_RAM);
  if (p == nullptr) {
    ReleasePacketLease(lease);
    counters_.dropped_packets.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  std::memcpy(p->payload, lease.bytes, length);
  counters_.ingress_copy_packets.fetch_add(1, std::memory_order_relaxed);
  counters_.ingress_copy_bytes.fetch_add(length, std::memory_order_relaxed);
  // The pbuf now owns the copied bytes; the original lease is released.
  ReleasePacketLease(lease);
  if (ip_input(p, &netif_) != ERR_OK) {
    pbuf_free(p);
  }
}

PacketInputResult LwipStack::InputPackets(PacketBatchView packets) noexcept {
  if (!IsRunning()) {
    return PacketInputResult::transport_stopped;
  }

  std::uint64_t total_bytes = 0;
  for (const auto& lease : packets) {
    if (lease.bytes == nullptr || lease.length == 0 ||
        lease.length > 0xFFFFU) {
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

  // Reserve the operation slot, then re-check the running flag so Stop can
  // drain every accepted operation before tearing down the netif.
  pending_ingress_ops_.fetch_add(1, std::memory_order_acq_rel);
  if (!running_.load(std::memory_order_acquire)) {
    pending_ingress_ops_.fetch_sub(1, std::memory_order_release);
    inflight_bytes_.fetch_sub(total_bytes, std::memory_order_acq_rel);
    return PacketInputResult::transport_stopped;
  }

  try {
    // Ownership contract: returning `accepted` transfers every lease owner
    // to the engine. The descriptors are copied into the posted operation;
    // nothing may be released before post() succeeds.
    std::vector<PacketLease> leases(packets.begin(), packets.end());
    counters_.input_packets.fetch_add(packets.size(), std::memory_order_relaxed);
    counters_.input_bytes.fetch_add(total_bytes, std::memory_order_relaxed);

    boost::asio::post(executor_,
        [this, leases = std::move(leases), total_bytes]() mutable {
          if (running_.load(std::memory_order_acquire)) {
            for (auto& lease : leases) {
              IngestLease(lease);
            }
          } else {
            for (auto& lease : leases) {
              ReleasePacketLease(lease);
            }
            counters_.dropped_packets.fetch_add(
                leases.size(), std::memory_order_relaxed);
          }
          inflight_bytes_.fetch_sub(total_bytes, std::memory_order_acq_rel);
          pending_ingress_ops_.fetch_sub(1, std::memory_order_release);
        });
  } catch (...) {
    pending_ingress_ops_.fetch_sub(1, std::memory_order_release);
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
  if (!output_) {
    return ERR_OK;
  }

  // Reuse the slot from the previous batch; only the first few batches after
  // startup allocate. Filling with assign() rather than resize() matters: on
  // a vector whose size is below tot_len, resize() value-initialises the new
  // bytes and pbuf_copy_partial then overwrites every one of them, which
  // profiled as the single largest cost in the stack.
  if (egress_count_ == egress_slots_.size()) {
    egress_slots_.emplace_back();
  }
  OwnedPacket& slot = egress_slots_[egress_count_];
  slot.ip_version = ip_version;
  if (p->next == nullptr) {
    const auto* src = static_cast<const std::uint8_t*>(p->payload);
    slot.data.assign(src, src + p->tot_len);
  } else {
    // Chained pbuf: no contiguous source, so fall back to a gathered copy.
    slot.data.resize(p->tot_len);
    pbuf_copy_partial(p, slot.data.data(), p->tot_len, 0);
  }
  ++egress_count_;

  counters_.output_packets.fetch_add(1, std::memory_order_relaxed);
  counters_.output_bytes.fetch_add(p->tot_len, std::memory_order_relaxed);
  pending_egress_bytes_ += p->tot_len;

  if (egress_count_ >= kMaxEgressBatchPackets ||
      pending_egress_bytes_ >= kMaxEgressBatchBytes) {
    FlushEgress();
    return ERR_OK;
  }
  ScheduleEgressFlush();
  return ERR_OK;
}

// Flushing on the 125 ms timeout pump would add that much latency to every
// interactive packet, so the deferred flush runs at the end of the current
// executor turn instead: it coalesces exactly the burst lwIP emits while
// processing one ingress batch or one outbound socket read, and costs
// microseconds rather than a timer period.
void LwipStack::ScheduleEgressFlush() noexcept {
  if (egress_flush_scheduled_) {
    return;
  }
  std::weak_ptr<StackLifeToken> weak_life = life_;
  try {
    boost::asio::post(executor_, [this, weak_life] {
      auto life = weak_life.lock();
      if (!life) {
        return;
      }
      life->in_flight.fetch_add(1, std::memory_order_acq_rel);
      if (life->alive.load(std::memory_order_acquire)) {
        FlushEgress();
      }
      life->in_flight.fetch_sub(1, std::memory_order_acq_rel);
    });
  } catch (...) {
    // Cannot defer; deliver synchronously rather than stranding the packets.
    FlushEgress();
    return;
  }
  egress_flush_scheduled_ = true;
}

void LwipStack::FlushEgress() noexcept {
  egress_flush_scheduled_ = false;
  if (egress_count_ == 0 || !output_) {
    egress_count_ = 0;
    pending_egress_bytes_ = 0;
    return;
  }
  counters_.egress_coalesce_packets.fetch_add(
      egress_count_, std::memory_order_relaxed);
  counters_.egress_coalesce_bytes.fetch_add(
      pending_egress_bytes_, std::memory_order_relaxed);
  counters_.egress_batches.fetch_add(1, std::memory_order_relaxed);

  // The slots stay owned here so their buffers survive into the next batch;
  // the consumer borrows them for the duration of this call only. Reset the
  // count before the callback so a re-entrant output (lwIP emitting while the
  // consumer runs) starts a fresh batch rather than resending these.
  const OwnedPacketBatchView view(egress_slots_.data(), egress_count_);
  egress_count_ = 0;
  pending_egress_bytes_ = 0;
  output_(view);
}

}  // namespace fptn::tunnel::flow
