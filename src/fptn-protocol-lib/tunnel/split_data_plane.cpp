/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/split_data_plane.h"

#include "fptn-protocol-lib/tunnel/flow_proxy_data_plane.h"

#include <cassert>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include <spdlog/spdlog.h>

namespace fptn::tunnel {

namespace {

std::optional<IpKey> ParseAddress(const std::string& text) {
  if (text.empty()) {
    return std::nullopt;
  }
  boost::system::error_code ec;
  const auto address = boost::asio::ip::make_address(text, ec);
  if (ec) {
    return std::nullopt;
  }
  return ToIpKey(address);
}

}  // namespace

RouteAction TableBackedRouter::Match(const FlowMetadata& metadata) {
  const auto verdict = classifier_.LookupVerdict(metadata);
  if (!verdict.has_value()) {
    // The flow reached the stack without a recorded verdict. Fail closed: a
    // silent `direct` here would leak the user's real IP.
    unknown_flows_.fetch_add(1, std::memory_order_relaxed);
    return RouteAction::reject;
  }
  if (*verdict != RouteAction::direct && *verdict != RouteAction::reject) {
    // `drop` never enters the stack and `fptn_l4` is forwarded raw, so this
    // means the fan-out and the table disagree.
    unexpected_verdicts_.fetch_add(1, std::memory_order_relaxed);
    assert(false && "non-stack verdict reached the lwIP router");
    return RouteAction::reject;
  }
  return *verdict;
}

SplitDataPlane::SplitDataPlane(TunnelConfiguration config,
    TunnelCallbacks callbacks, TransportProvider transport,
    std::shared_ptr<const IRoutingPolicy> routing_policy)
    : config_(std::move(config)),
      callbacks_(std::move(callbacks)),
      configured_policy_(std::move(routing_policy)),
      transport_(std::move(transport)) {}

SplitDataPlane::~SplitDataPlane() { Stop(); }

void SplitDataPlane::ConfigureRouting() {
  if (configured_policy_) {
    policy_ = configured_policy_;
  } else {
    auto static_policy = std::make_shared<StaticDomainPolicy>(
        RouteAction::fptn_l4);
    static_policy->AddRules(config_.routing.direct_domains, RouteAction::direct);
    static_policy->AddRules(config_.routing.reject_domains, RouteAction::reject);
    static_policy->AddRules(config_.routing.drop_domains, RouteAction::drop);
    policy_ = std::move(static_policy);
  }

  dns_observer_ = std::make_unique<DnsObserver>();
  classifier_ = std::make_unique<FlowClassifier>(
      ClassifierConfiguration{}, *policy_, *dns_observer_);

  if (const auto server = ParseAddress(config_.l3.server_ip)) {
    classifier_->SetServerEndpoint(
        *server, static_cast<std::uint16_t>(config_.l3.server_port));
  }
  std::vector<IpKey> resolvers;
  resolvers.reserve(config_.routing.tunnel_resolvers.size());
  for (const auto& text : config_.routing.tunnel_resolvers) {
    if (const auto address = ParseAddress(text)) {
      resolvers.push_back(*address);
    }
  }
  classifier_->SetTunnelResolvers(resolvers);
  if (resolvers.size() != config_.routing.tunnel_resolvers.size()) {
    SPDLOG_WARN("{} of {} resolvers could not be parsed and are not pinned",
        config_.routing.tunnel_resolvers.size() - resolvers.size(),
        config_.routing.tunnel_resolvers.size());
  }

  std::vector<IpKey> direct_resolvers;
  direct_resolvers.reserve(config_.routing.direct_resolvers.size());
  for (const auto& text : config_.routing.direct_resolvers) {
    if (const auto address = ParseAddress(text)) {
      direct_resolvers.push_back(*address);
    }
  }
  classifier_->SetDirectResolvers(direct_resolvers);
  if (!direct_resolvers.empty()) {
    SPDLOG_INFO("{} user-chosen resolver(s) pinned direct", direct_resolvers.size());
  }
  if (direct_resolvers.size() != config_.routing.direct_resolvers.size()) {
    SPDLOG_WARN(
        "{} of {} direct resolvers could not be parsed and are not pinned",
        config_.routing.direct_resolvers.size() - direct_resolvers.size(),
        config_.routing.direct_resolvers.size());
  }

  router_ = std::make_unique<TableBackedRouter>(*classifier_);

  SPDLOG_INFO(
      "split routing policy: {} direct, {} reject, {} drop, {} resolvers; "
      "default fptn; source {}",
      config_.routing.direct_domains.size(),
      config_.routing.reject_domains.size(),
      config_.routing.drop_domains.size(), resolvers.size(),
      configured_policy_ ? "injected" : "static");
}

std::expected<void, TunnelError> SplitDataPlane::Start() {
  if (started_.load(std::memory_order_acquire)) {
    return std::unexpected(TunnelError::already_running);
  }
  if (config_.l3.server_ip.empty() || config_.l3.server_port <= 0) {
    return std::unexpected(TunnelError::invalid_configuration);
  }
  if (config_.flow.tun_ipv4.empty()) {
    return std::unexpected(TunnelError::invalid_configuration);
  }
  if (!transport_) {
    return std::unexpected(TunnelError::invalid_configuration);
  }

  SPDLOG_INFO("split plane starting: tun {} mtu {} server {}:{}",
      config_.flow.tun_ipv4, config_.flow.mtu, config_.l3.server_ip,
      config_.l3.server_port);
  ConfigureRouting();

  // The flow plane comes up first so the stack is ready before the transport
  // connects and the provider applies network settings. Note the lwIP netif
  // uses the configured tun address, not the server-assigned one: the
  // transport NATs between them on the wire, so the assigned address never
  // appears on this interface.
  TunnelCallbacks flow_callbacks;
  // The stack's egress is the return path for every `direct` flow, so it is
  // where a directly-resolved DNS answer appears. Without this tap, pinning a
  // resolver direct would silently disable domain attribution -- and with it
  // every domain rule in the compiled policy, leaving only the address tables.
  flow_callbacks.on_owned_packet_batch =
      [this](OwnedPacketBatchView batch) {
        ObserveEgress(batch);
        if (callbacks_.on_owned_packet_batch) {
          callbacks_.on_owned_packet_batch(batch);
        }
      };
  flow_plane_ = std::make_unique<FlowProxyDataPlane>(
      config_, std::move(flow_callbacks), router_.get());
  if (auto result = flow_plane_->Start(); !result.has_value()) {
    SPDLOG_ERROR("split plane failed to start the lwIP stack");
    flow_plane_.reset();
    return result;
  }

  started_.store(true, std::memory_order_release);
  SPDLOG_INFO("split plane started; awaiting transport for fptn traffic");
  return {};
}

void SplitDataPlane::Stop() noexcept {
  if (!started_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  {
    std::lock_guard lock(counters_mutex_);
    SPDLOG_INFO(
        "split plane stopping: {} batches, {} to stack, {} to transport, "
        "{} dropped, {} rollbacks",
        counters_.batches, counters_.packets_to_stack,
        counters_.packets_to_transport, counters_.packets_dropped,
        counters_.rollbacks);
  }
  if (flow_plane_) {
    flow_plane_->Stop();
  }
  flow_plane_.reset();
  router_.reset();
  classifier_.reset();
  dns_observer_.reset();
  policy_.reset();
}

PacketInputResult SplitDataPlane::InputPackets(
    PacketBatchView packets) noexcept {
  if (!started_.load(std::memory_order_acquire)) {
    return PacketInputResult::transport_stopped;
  }
  if (packets.empty()) {
    return PacketInputResult::accepted;
  }

  // Reusing the scratch buffers is sound only while this never runs
  // concurrently with itself. Refusing the batch is a safe degradation: the
  // contract leaves every lease with the caller on any non-accepted result.
  if (partition_in_progress_.exchange(true, std::memory_order_acq_rel)) {
    {
      std::lock_guard lock(counters_mutex_);
      ++counters_.partition_reentries;
    }
    assert(false && "InputPackets re-entered concurrently; scratch reuse unsafe");
    return PacketInputResult::queue_full;
  }
  // Clears the scratch on every exit path, so no batch can ever observe leases
  // left behind by the previous one -- those point at storage the caller has
  // since released.
  struct PartitionGuard {
    SplitDataPlane* self;
    ~PartitionGuard() {
      self->scratch_to_stack_.clear();
      self->scratch_to_transport_.clear();
      self->scratch_to_drop_.clear();
      self->partition_in_progress_.store(false, std::memory_order_release);
    }
  } partition_guard{this};

  // Partition by verdict. The batch ownership contract is all-or-nothing, so
  // nothing below may consume a lease until both planes have accepted their
  // half (H1).
  auto& to_stack = scratch_to_stack_;
  auto& to_transport = scratch_to_transport_;
  auto& to_drop = scratch_to_drop_;
  try {
    // Grows to the high-water batch size once, then stops allocating: capacity
    // survives the clear() in the guard.
    to_stack.reserve(packets.size());
    to_transport.reserve(packets.size());
  } catch (...) {
    return PacketInputResult::queue_full;
  }

  for (const auto& lease : packets) {
    switch (classifier_->Classify(lease)) {
      case RouteAction::direct:
      case RouteAction::reject:
        to_stack.push_back(lease);
        break;
      case RouteAction::fptn_l4:
        to_transport.push_back(lease);
        break;
      case RouteAction::drop:
        to_drop.push_back(lease);
        break;
    }
  }

  // Phase 1: reserve on both planes. Any failure returns with no lease
  // consumed and both reservations rolled back, so the caller still owns the
  // whole batch.
  auto transport_error = PacketInputResult::transport_stopped;
  auto transport_reservation =
      to_transport.empty()
          ? WebsocketBatchReservation{}
          : TryReserveWebsocketBatch(transport_(), to_transport,
                transport_error);
  if (!to_transport.empty() && !transport_reservation) {
    std::lock_guard lock(counters_mutex_);
    ++counters_.rollbacks;
    return transport_error;
  }

  std::uint64_t stack_bytes = 0;
  bool stack_reserved = false;
  if (!to_stack.empty()) {
    if (!FlowProxyDataPlane::ValidateIngressBatch(to_stack, stack_bytes)) {
      std::lock_guard lock(counters_mutex_);
      ++counters_.rollbacks;
      return PacketInputResult::invalid_packet;
    }
    if (!flow_plane_->TryReserveIngress(stack_bytes)) {
      std::lock_guard lock(counters_mutex_);
      ++counters_.rollbacks;
      return PacketInputResult::queue_full;
    }
    stack_reserved = true;
  }

  // Phase 2: commit. Past this point the batch is accepted and every lease
  // must be released exactly once, here or by the plane that took it.
  if (!to_transport.empty()) {
    CommitWebsocketBatch(to_transport, std::move(transport_reservation));
  }
  std::size_t dropped = to_drop.size();
  if (stack_reserved) {
    if (!flow_plane_->CommitReservedIngress(to_stack, stack_bytes)) {
      // Allocation failure posting the ingest. The transport half is already
      // committed, so these cannot be handed back -- drop them and let TCP
      // retransmit.
      ReleasePacketBatch(to_stack);
      dropped += to_stack.size();
    }
  }
  for (auto& lease : to_drop) {
    ReleasePacketLease(lease);
  }

  {
    std::lock_guard lock(counters_mutex_);
    ++counters_.batches;
    counters_.packets_to_stack += to_stack.size();
    counters_.packets_to_transport += to_transport.size();
    counters_.packets_dropped += dropped;
  }
  return PacketInputResult::accepted;
}

void SplitDataPlane::ObserveInbound(
    const fptn::common::network::BatchIPPacketPtr& packets) noexcept {
  if (dns_observer_) {
    dns_observer_->Observe(packets);
  }
}

void SplitDataPlane::ObserveEgress(OwnedPacketBatchView batch) noexcept {
  if (!dns_observer_) {
    return;
  }
  for (const OwnedPacket& packet : batch) {
    dns_observer_->ObservePacket(packet.data.data(), packet.data.size());
  }
}

void SplitDataPlane::ObserveInboundPacket(
    const std::uint8_t* bytes, std::size_t length) noexcept {
  if (dns_observer_) {
    dns_observer_->ObservePacket(bytes, length);
  }
}

FlowCounters SplitDataPlane::Counters() const noexcept {
  return flow_plane_ ? flow_plane_->Counters() : FlowCounters{};
}

SplitCounters SplitDataPlane::SplitStatistics() const noexcept {
  std::lock_guard lock(counters_mutex_);
  return counters_;
}

}  // namespace fptn::tunnel
