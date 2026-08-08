/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstddef>
#include <cstdint>

// On-disk layout of the compiled geo rule set.
//
// This file is the contract between the compiler (which runs in the app) and
// the rule set (which runs in the packet tunnel). Both include it, so the
// layout is defined exactly once and a writer/reader mismatch is a compile
// error rather than corrupt routing inside the tunnel.
//
// Design constraints, in the order that drove the layout:
//
//   1. The tunnel is memory-constrained (jetsam). The artifact is mapped and
//      queried IN PLACE, never parsed into heap objects: every structure here
//      is fixed-width, position-independent (offsets, never pointers) and
//      little-endian, so the mapped pages stay clean and evictable. Parsing it
//      into std::string/unordered_map would trade a few hundred KB of clean,
//      reclaimable pages for the same amount of dirty ones that jetsam counts
//      and can never drop.
//
//   2. It is read from a file that a wild offset would turn into a wild read
//      inside the process that routes packets. Every section carries an
//      explicit offset and count so the whole thing can be bounds-checked
//      against the mapped length before the first lookup.
//
//   3. Rule precedence is resolved at COMPILE time, not lookup time. The
//      published lists overlap heavily -- 98% of the WHITELIST ranges sit
//      inside a DIRECT range -- and re-deriving the winner per flow would be
//      both slower and a place for the two processes to disagree.
//
// Everything is little-endian. Apple platforms are, and the artifact never
// leaves the device that compiled it; a big-endian reader must byte-swap.

namespace fptn::geo {

// Bumped whenever the layout changes in a way an older reader would
// misinterpret. The reader refuses anything it does not recognise rather than
// guessing, and falls back to the built-in policy.
inline constexpr std::uint32_t kFormatVersion = 1;

inline constexpr char kMagic[8] = {'F', 'P', 'T', 'N', 'G', 'E', 'O', '1'};

// Sections are padded to this so every array is naturally aligned once the
// mapping itself is page-aligned.
inline constexpr std::size_t kSectionAlignment = 8;

inline constexpr std::size_t kSha256Size = 32;

// Mirrors fptn::tunnel::RouteAction, plus a `none` that only ever appears in
// the IPv4 interval table, where gaps between covered ranges must be explicit
// (see kIpv4 note below). Kept as its own type so the on-disk encoding cannot
// drift when RouteAction gains a value.
enum class GeoAction : std::uint8_t {
  none = 0,
  direct = 1,
  fptn = 2,
  reject = 3,
  drop = 4,
};

enum class GeoDomainKind : std::uint8_t {
  // Matches the name itself or any subdomain of it, label-aware.
  suffix = 0,
  // Matches only the whole name.
  exact = 1,
};

// Header flags.
// A hostname with no dot at all (`nas`, `router`) is a local name; the
// published lists express this as a regex, and it reduces to this one bit.
inline constexpr std::uint32_t kFlagBareHostnameIsDirect = 1u << 0;

#pragma pack(push, 1)

// One IPv6 rule. There are only ~88 of them, so they stay as (base, prefix)
// pairs scanned linearly rather than being flattened into intervals like IPv4:
// 128-bit interval arithmetic is not worth writing, or auditing, for a table
// this size, and the scan runs once per flow.
struct GeoIpv6Rule {
  std::uint64_t high;
  std::uint64_t low;
  std::uint8_t prefix;
  std::uint8_t action;
  std::uint8_t reserved[6];
};

// A rule of the form "contains X AND ends with Y".
//
// Every regex the published lists actually use reduces to this shape --
// `^github-production-release-asset-[0-9a-zA-Z]{6}\.s3\.amazonaws\.com$` is
// "contains the prefix, ends with the suffix" -- so the tunnel needs no regex
// engine. The compiler reduces them and REPORTS anything it cannot, rather
// than dropping it silently: an irregular pattern upstream must surface as a
// compile diagnostic in the app, not as traffic quietly taking the wrong route.
struct GeoPairRule {
  std::uint32_t contains_offset;
  std::uint32_t contains_size;
  std::uint32_t suffix_offset;
  std::uint32_t suffix_size;
  std::uint8_t action;
  std::uint8_t reserved[3];
};

// Fixed-size file header. Every offset is from the start of the file.
struct GeoArtifactHeader {
  char magic[8];
  std::uint32_t format_version;
  std::uint32_t flags;

  // Over every byte after this header. Verifying it reads the whole artifact,
  // which makes its pages resident -- but they stay CLEAN, so it costs I/O
  // time and not footprint. Cheap insurance for a file that decides where all
  // traffic goes.
  std::uint8_t body_sha256[kSha256Size];

  // Provenance of the inputs, so the app can tell whether a recompile is due
  // without re-reading them.
  std::uint8_t geoip_sha256[kSha256Size];
  std::uint8_t geosite_sha256[kSha256Size];

  std::uint64_t built_at_unix;

  // Identifies the group -> verdict mapping used. A changed mapping needs a
  // recompile even when the source files are untouched.
  std::uint32_t verdict_map_id;

  // Verdict when nothing matches.
  std::uint8_t default_action;
  // Longest label count of any stored domain rule. A query cannot match beyond
  // this depth, so it bounds the per-lookup work by the TABLE rather than by
  // the (attacker-influenceable) query.
  std::uint8_t max_domain_labels;
  std::uint8_t reserved0[2];

  // Sorted ascending. `ipv4_offset` points at u32 starts[count]; the parallel
  // u8 actions[count] follow immediately after them.
  //
  // The intervals are disjoint and cover the whole space: gaps carry
  // GeoAction::none explicitly. That is what lets a lookup be one binary
  // search with NO containment test -- the predecessor is always the answer.
  std::uint32_t ipv4_offset;
  std::uint32_t ipv4_count;

  std::uint32_t ipv6_offset;
  std::uint32_t ipv6_count;

  // Domain rules, stored with their labels REVERSED (`ru.mail.smtp`) and
  // sorted, which turns suffix matching into prefix matching so one sorted
  // blob serves it.
  //
  // Layout at domain_offset: u32 offsets[count + 1], then u8 actions[count],
  // then u8 kinds[count]. The trailing offset is the blob end, so a rule's
  // length is offsets[i + 1] - offsets[i] and no length array is needed.
  // Strings in the blob are NOT NUL-terminated.
  std::uint32_t domain_offset;
  std::uint32_t domain_count;
  std::uint32_t domain_blob_offset;
  std::uint32_t domain_blob_size;

  // Substring rules, in forward (unreversed) form. Scanned linearly, and only
  // when the sorted lookups miss. There are ~105, all in one group, and they
  // exist to override the IP table for geo-blocked services whose edge sits in
  // a range the IP table would otherwise send direct.
  std::uint32_t substring_offset;
  std::uint32_t substring_count;
  std::uint32_t substring_blob_offset;
  std::uint32_t substring_blob_size;

  std::uint32_t pair_offset;
  std::uint32_t pair_count;
  std::uint32_t pair_blob_offset;
  std::uint32_t pair_blob_size;

  // Total artifact size, checked against the real file size on load.
  std::uint32_t total_size;
  std::uint32_t reserved1;
};

#pragma pack(pop)

// The layout is written to disk, so its size is part of the contract: a field
// added without bumping kFormatVersion must not compile.
static_assert(sizeof(GeoIpv6Rule) == 24, "GeoIpv6Rule layout changed");
static_assert(sizeof(GeoPairRule) == 20, "GeoPairRule layout changed");
static_assert(sizeof(GeoArtifactHeader) == 200, "GeoArtifactHeader layout changed");

}  // namespace fptn::geo
