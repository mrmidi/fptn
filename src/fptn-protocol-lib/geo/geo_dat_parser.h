/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace fptn::geo {

// Reader for the V2Ray/Xray `geosite.dat` and `geoip.dat` containers.
//
// Only the wire format lives here. Which group means which verdict is a
// routing decision, not a file-format one, and lives in geo_inputs.h -- so this
// parser can be pointed at any publisher's lists without being edited.
//
// Nothing is deduplicated or collapsed on the way through. The published groups
// overlap heavily by design (98% of the WHITELIST ranges sit inside a DIRECT
// range), and merging them here would bake in a precedence decision that
// belongs to whoever assigns verdicts.

enum class GeoDatDomainType : std::uint8_t {
  // Substring of the name, anywhere in it.
  plain = 0,
  regex = 1,
  // The name itself or any subdomain of it.
  root_domain = 2,
  // The whole name only.
  full = 3,
};

struct GeoDatDomain {
  GeoDatDomainType type = GeoDatDomainType::plain;
  // Trimmed and lower-cased. Never empty: valueless rules are dropped, since
  // under `plain` an empty needle would match every name there is.
  std::string value;
};

struct GeoDatSiteGroup {
  // Upper-cased, from `code` when present and `country_code` otherwise.
  std::string name;
  std::vector<GeoDatDomain> domains;
};

struct GeoDatCidr {
  bool is_ipv6 = false;
  std::uint64_t high = 0;
  // IPv4 uses `low` only, in host byte order.
  std::uint64_t low = 0;
  std::uint8_t prefix = 0;
};

struct GeoDatIpGroup {
  std::string name;
  // "Everything EXCEPT these ranges". Unused by the lists we consume, and
  // carried rather than dropped so the inputs builder can refuse it loudly
  // instead of silently inverting where traffic goes.
  bool inverse_match = false;
  std::vector<GeoDatCidr> cidrs;
};

// Why a parse failed. Every one of these means the downloaded file is not what
// it claims to be, which is something a person may have to act on -- so the
// reason and the byte offset are reported rather than collapsed into "bad
// file".
enum class GeoDatError : std::uint8_t {
  none = 0,
  empty,
  gzipped,
  truncated,
  illegal_field_number,
  unsupported_wire_type,
  unexpected_wire_type,
  invalid_address_length,
  invalid_prefix,
  unnamed_group,
  no_groups,
};

const char* ToString(GeoDatError error) noexcept;

template <typename Group>
struct GeoDatResult {
  GeoDatError error = GeoDatError::none;
  // Byte offset the failure was detected at; meaningless when ok().
  std::size_t error_offset = 0;
  std::vector<Group> groups;

  bool ok() const noexcept { return error == GeoDatError::none; }
};

using GeoDatSiteResult = GeoDatResult<GeoDatSiteGroup>;
using GeoDatIpResult = GeoDatResult<GeoDatIpGroup>;

class GeoDatParser {
 public:
  // Both take the whole file. Neither retains the buffer.
  static GeoDatSiteResult ParseGeoSite(std::span<const std::uint8_t> bytes);
  static GeoDatIpResult ParseGeoIp(std::span<const std::uint8_t> bytes);
};

}  // namespace fptn::geo
