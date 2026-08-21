/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "fptn-protocol-lib/tunnel/flow_types.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/routing_policy.h"

namespace fptn::tunnel {

// Binary IP address, sized for v6 and reused for v4 (first four bytes). Kept a
// POD so the flow table key needs no allocation on the per-packet path.
struct IpKey {
  std::array<std::uint8_t, 16> bytes{};
  std::uint8_t version = 0;  // 4 or 6; 0 means unset

  bool operator==(const IpKey& other) const noexcept = default;
};

struct FiveTuple {
  IpKey source;
  IpKey destination;
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 0;
  TransportProtocol protocol = TransportProtocol::tcp;

  bool operator==(const FiveTuple& other) const noexcept = default;
};

struct IpKeyHash {
  std::size_t operator()(const IpKey& key) const noexcept;
};

struct FiveTupleHash {
  std::size_t operator()(const FiveTuple& tuple) const noexcept;
};

// Reads the 5-tuple straight out of the packet header. Returns false for
// anything the classifier cannot key on: a truncated packet, a non-first IPv4
// fragment (no transport header present), a protocol other than TCP/UDP, or an
// IPv6 packet carrying extension headers ahead of the transport header.
//
// Deliberately not IPPacket::Parse: this runs per packet and must not allocate.
bool PeekFiveTuple(const std::uint8_t* bytes, std::uint32_t length,
    FiveTuple& out) noexcept;

// Supplies the domain last observed resolving to an address. Implemented by
// DnsObserver; kept as an interface so the classifier is testable on its own.
class IDomainAttribution {
 public:
  virtual ~IDomainAttribution() = default;

  // Returns an empty string when the address cannot be attributed.
  virtual std::string LookupDomain(const IpKey& address) const = 0;
};

struct ClassifierConfiguration {
  // Idle flows are forgotten after this long. A verdict is decided once per
  // flow and never re-evaluated, so this only bounds the table.
  std::chrono::milliseconds flow_idle_timeout{120000};
  // Hard ceiling on remembered flows (H3). Once reached, further first-packets
  // are still classified correctly, just not cached.
  std::size_t max_flows = 4096;
  // Verdict for packets whose 5-tuple cannot be read (ICMP, fragments,
  // IPv6 with extension headers). Tunnelling is the safe answer.
  RouteAction unclassifiable_action = RouteAction::fptn_l4;
};

struct ClassifierCounters {
  std::uint64_t classified_packets = 0;
  std::uint64_t table_hits = 0;
  std::uint64_t decisions = 0;
  std::uint64_t unclassifiable = 0;
  std::uint64_t table_full_events = 0;
  std::uint64_t expired_flows = 0;
  std::uint64_t active_flows = 0;

  // Packets served by the 1-entry MRU, i.e. whose 5-tuple matched the
  // immediately preceding packet's. A subset of `table_hits`, counted
  // separately so a drop in locality is visible: measured 92.6% under load
  // and 18% idle, and the whole fast path is only worth its complexity while
  // the loaded figure stays high.
  //
  // Records only that two consecutive packets shared a flow, never which one,
  // so it reveals nothing about where the person went.
  std::uint64_t mru_hits = 0;

  // Verdict tally, one increment per new flow rather than per packet, so the
  // sum of the four equals `decisions`. This answers "is the policy actually
  // routing anything, and which way" — the question per-flow log lines were
  // meant to answer and could not, being both unreadable under load and a
  // record of every destination the person visited.
  std::uint64_t direct_flows = 0;
  std::uint64_t fptn_flows = 0;
  std::uint64_t rejected_flows = 0;
  std::uint64_t dropped_flows = 0;
};

// Decides one verdict per flow, at packet ingress, before anything reaches the
// lwIP stack. The verdict is cached on the first packet of a flow and reused
// unchanged for its lifetime: if a DNS update flipped a verdict mid-flow the
// packets would change planes and the connection would break.
class FlowClassifier {
 public:
  FlowClassifier(ClassifierConfiguration config, const IRoutingPolicy& policy,
      const IDomainAttribution& attribution);

  FlowClassifier(const FlowClassifier&) = delete;
  FlowClassifier& operator=(const FlowClassifier&) = delete;

  // Pinned rule 1: traffic to the FPTN server itself must never be tunnelled,
  // or the transport would carry its own packets.
  void SetServerEndpoint(const IpKey& address, std::uint16_t port);
  // Pinned rule 2: the resolvers advertised to the OS are reachable only
  // through the tunnel, so their traffic is always `fptn`. This is what makes
  // server-supplied DNS work in split mode.
  void SetTunnelResolvers(const std::vector<IpKey>& resolvers);
  // Pinned rule 3: a resolver the user chose is queried from this device's own
  // network position, so its traffic is always `direct`.
  //
  // Ranked below rule 2 on purpose. The two lists are built to be disjoint, so
  // an address in both means someone typed the server's own resolver into the
  // custom field — and answering `direct` there would make it unreachable and
  // take DNS down entirely, whereas `fptn` is simply what they already had.
  void SetDirectResolvers(const std::vector<IpKey>& resolvers);

  // Per-packet entry point. Never allocates on the cached path.
  RouteAction Classify(const PacketLease& lease) noexcept;

  // Verdict recorded for an established flow, for the stack-side router to
  // read back rather than deciding a second time. Empty when unknown.
  std::optional<RouteAction> LookupVerdict(
      const FlowMetadata& metadata) const noexcept;

  // Drops idle entries. Called inline from Classify on an amortised schedule;
  // exposed for tests and for an explicit sweep at quiet moments.
  std::size_t ExpireIdle(std::chrono::steady_clock::time_point now) noexcept;

  ClassifierCounters Counters() const noexcept;

 private:
  struct Entry {
    RouteAction action = RouteAction::fptn_l4;
    // Milliseconds since `epoch_`, sampled once per sweep rather than per
    // packet. Halves Entry from 16 bytes to 8, which is why the table's
    // payload and the sweep both got cheaper. Wraps at 49.7 days; unsigned
    // subtraction stays correct for any interval shorter than that, and the
    // idle timeout is minutes.
    std::uint32_t last_seen_ms = 0;
  };

  // Requires mutex_.
  RouteAction DecideLocked(const FiveTuple& tuple, const IpKey& destination,
      std::uint16_t destination_port);

  // Requires mutex_.
  void CountVerdictLocked(RouteAction action) noexcept;

  // Requires mutex_. Re-anchors coarse_now_ms_ to real time.
  void RefreshCoarseClockLocked(
      std::chrono::steady_clock::time_point now) noexcept;

  // Requires mutex_. Drops entries idle longer than the timeout, measured
  // against coarse_now_ms_.
  std::size_t ExpireIdleLocked() noexcept;

  ClassifierConfiguration config_;
  const IRoutingPolicy& policy_;
  const IDomainAttribution& attribution_;

  mutable std::mutex mutex_;
  std::unordered_map<FiveTuple, Entry, FiveTupleHash> flows_;
  std::optional<IpKey> server_address_;
  std::uint16_t server_port_ = 0;
  std::vector<IpKey> tunnel_resolvers_;
  std::vector<IpKey> direct_resolvers_;

  // 1-entry MRU over the flow table. Holds a pointer to the entry rather than
  // a copy of the verdict, so the hit path can refresh last_seen_ms without a
  // second lookup -- skipping that refresh would let the sweep expire a live
  // flow, and the re-decision on the next miss could flip a verdict mid-flow,
  // which is exactly what the pinned-verdict guarantee above exists to prevent.
  //
  // A plain member, not thread_local: the NE guarantees the read callback is
  // non-concurrent, not that it stays on one thread, so a thread-keyed cache
  // would go cold on migration.
  //
  // std::unordered_map keeps references stable across insert and rehash, so
  // the pointer only has to be dropped when an entry is erased -- which is
  // only in the sweep, and it is cleared there unconditionally.
  FiveTuple mru_tuple_;
  Entry* mru_entry_ = nullptr;

  // Wall clock sampled once per sweep, not once per packet. The only consumer
  // is the idle timeout, measured in minutes, so a sample every 2048 packets
  // is orders of magnitude finer than needed -- and reading steady_clock::now()
  // per packet cost 57 of the ~95 cycles this path used to spend, an
  // isb-serialised CNTVCT_EL0 read on arm64.
  std::chrono::steady_clock::time_point epoch_{};
  std::uint32_t coarse_now_ms_ = 0;
  std::uint32_t timeout_ms_ = 0;

  // Packets seen since the last idle sweep; the sweep is amortised onto the
  // ingress path so no timer thread has to touch the table.
  std::uint32_t packets_since_sweep_ = 0;
  static constexpr std::uint32_t kSweepIntervalPackets = 2048;

  ClassifierCounters counters_;
};

// Converts the boost address carried in FlowMetadata into the table key.
IpKey ToIpKey(const boost::asio::ip::address& address) noexcept;

// The inverse, for handing a decision back to a policy that matches on the
// address itself. An unset key yields an unspecified v4 address.
boost::asio::ip::address FromIpKey(const IpKey& key) noexcept;

}  // namespace fptn::tunnel
