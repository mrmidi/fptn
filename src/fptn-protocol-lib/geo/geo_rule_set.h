/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "fptn-protocol-lib/geo/geo_format.h"

namespace fptn::geo {

// Why a load can fail. Reported rather than thrown: the caller is a packet
// tunnel that must fall back to its built-in policy and keep running, not
// unwind.
enum class GeoLoadError : std::uint8_t {
  none = 0,
  cannot_open,
  too_small,
  bad_magic,
  unsupported_version,
  size_mismatch,
  section_out_of_bounds,
  offsets_not_monotonic,
  blob_size_mismatch,
  checksum_mismatch,
  mmap_failed,
};

const char* ToString(GeoLoadError error) noexcept;

// A compiled geo rule set, mapped and queried in place.
//
// The mapping is owned here and unmapped by the destructor. Deliberately NOT
// "caller maps it and passes a pointer": splitting a mapping's lifetime across
// a language boundary is how you get a use-after-unmap in the process that
// routes packets.
//
// Thread-safety: after a successful Open() the object is immutable, so
// concurrent lookups from any number of threads are safe. Open() itself is not.
//
// IMPORTANT invariant on the writer's side: a published artifact must never be
// modified in place. Truncating a file that is currently mapped turns the next
// touch of a page past the new end into SIGBUS, which kills the tunnel. Write
// to a temporary name and rename() over it -- a running tunnel then keeps its
// old inode and a consistent view.
class GeoRuleSet {
 public:
  GeoRuleSet() = default;
  ~GeoRuleSet();

  GeoRuleSet(const GeoRuleSet&) = delete;
  GeoRuleSet& operator=(const GeoRuleSet&) = delete;
  GeoRuleSet(GeoRuleSet&&) = delete;
  GeoRuleSet& operator=(GeoRuleSet&&) = delete;

  // Maps `path` and validates it completely before any lookup is possible.
  //
  // `verify_checksum` reads every byte to check the body digest. It costs one
  // pass over ~200 KB and leaves the pages clean, so it does not move the
  // process footprint; skip it only where the artifact was just written by
  // this same process.
  GeoLoadError Open(const std::string& path, bool verify_checksum = true);

  bool IsOpen() const noexcept { return header_ != nullptr; }

  // Verdict for an IPv4 address in HOST byte order, or `none` when no interval
  // claims it. One binary search: the intervals are disjoint and gap-filled, so
  // the predecessor is the answer and no containment test is needed.
  GeoAction LookupIpv4(std::uint32_t address) const noexcept;

  // Verdict for an IPv6 address given as its high and low halves, most
  // significant first.
  GeoAction LookupIpv6(std::uint64_t high, std::uint64_t low) const noexcept;

  // Verdict for a domain, or `none` when nothing matches.
  //
  // Order is longest-suffix first, then substring rules, then contains+suffix
  // pairs; the sorted table is consulted first because it is both the largest
  // and the cheapest.
  GeoAction LookupDomain(std::string_view domain) const noexcept;

  GeoAction default_action() const noexcept;

  std::uint32_t ipv4_count() const noexcept;
  std::uint32_t ipv6_count() const noexcept;
  std::uint32_t domain_count() const noexcept;
  std::uint32_t substring_count() const noexcept;
  std::uint32_t pair_count() const noexcept;

  // Hex digests, for logging which artifact actually loaded.
  std::string body_sha256_hex() const;

 private:
  // Bounds-checks every section against the mapped length. Runs once, before
  // the first lookup, because a wild offset here is a wild read in the tunnel.
  GeoLoadError Validate(bool verify_checksum) const noexcept;

  const std::uint8_t* base_ = nullptr;
  std::size_t size_ = 0;
  const GeoArtifactHeader* header_ = nullptr;

  // Cached section pointers, resolved once Validate() has proven them in range.
  const std::uint32_t* ipv4_starts_ = nullptr;
  const std::uint8_t* ipv4_actions_ = nullptr;
  const GeoIpv6Rule* ipv6_rules_ = nullptr;
  const std::uint32_t* domain_offsets_ = nullptr;
  const std::uint8_t* domain_actions_ = nullptr;
  const std::uint8_t* domain_kinds_ = nullptr;
  const char* domain_blob_ = nullptr;
  const std::uint32_t* substring_offsets_ = nullptr;
  const std::uint8_t* substring_actions_ = nullptr;
  const char* substring_blob_ = nullptr;
  const GeoPairRule* pair_rules_ = nullptr;
  const char* pair_blob_ = nullptr;
};

}  // namespace fptn::geo
