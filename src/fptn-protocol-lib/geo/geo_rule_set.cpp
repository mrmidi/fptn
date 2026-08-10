/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_rule_set.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <algorithm>
#include <cstring>

namespace fptn::geo {

namespace {

// The longest legal DNS name is 253 characters, so every lookup buffer is
// stack-sized. Nothing on this path allocates: it runs inside the tunnel, and
// a per-flow malloc is both footprint and a failure mode we do not need.
constexpr std::size_t kMaxDomainLength = 253;

bool InRange(std::uint64_t offset, std::uint64_t bytes,
    std::uint64_t total) noexcept {
  // Written as a subtraction so a huge `bytes` cannot wrap past the end.
  return offset <= total && bytes <= total - offset;
}

char ToLowerAscii(char c) noexcept {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Lowercases `in`, strips a trailing root dot, and writes it to `out`.
// Returns 0 when the name is empty or cannot fit, which the caller treats as
// "no match" rather than as an error.
std::size_t NormalizeDomain(
    std::string_view in, char* out, std::size_t cap) noexcept {
  while (!in.empty() && in.back() == '.') {
    in.remove_suffix(1);
  }
  if (in.empty() || in.size() > cap) {
    return 0;
  }
  for (std::size_t i = 0; i < in.size(); ++i) {
    out[i] = ToLowerAscii(in[i]);
  }
  return in.size();
}

// Reverses label order: `smtp.mail.ru` -> `ru.mail.smtp`.
//
// This is what turns suffix matching into prefix matching, so one sorted blob
// and a binary search per label boundary serves the whole domain table.
std::size_t ReverseLabels(
    const char* in, std::size_t len, char* out, std::size_t cap) noexcept {
  if (len == 0 || len > cap) {
    return 0;
  }
  std::size_t written = 0;
  std::size_t end = len;
  for (std::size_t i = len; i-- > 0;) {
    if (in[i] == '.') {
      const std::size_t label = end - i - 1;
      if (written != 0) {
        out[written++] = '.';
      }
      std::memcpy(out + written, in + i + 1, label);
      written += label;
      end = i;
    }
  }
  if (written != 0) {
    out[written++] = '.';
  }
  std::memcpy(out + written, in, end);
  written += end;
  return written;
}

}  // namespace

const char* ToString(GeoLoadError error) noexcept {
  switch (error) {
    case GeoLoadError::none:
      return "ok";
    case GeoLoadError::cannot_open:
      return "cannot open";
    case GeoLoadError::too_small:
      return "file smaller than the header";
    case GeoLoadError::bad_magic:
      return "not a geo artifact";
    case GeoLoadError::unsupported_version:
      return "unsupported format version";
    case GeoLoadError::size_mismatch:
      return "header size disagrees with the file";
    case GeoLoadError::section_out_of_bounds:
      return "a section falls outside the file";
    case GeoLoadError::offsets_not_monotonic:
      return "blob offsets are not monotonic";
    case GeoLoadError::blob_size_mismatch:
      return "blob size disagrees with its offsets";
    case GeoLoadError::checksum_mismatch:
      return "body checksum mismatch";
    case GeoLoadError::mmap_failed:
      return "mmap failed";
  }
  return "unknown";
}

GeoRuleSet::~GeoRuleSet() {
  if (base_ != nullptr && size_ != 0) {
    ::munmap(const_cast<std::uint8_t*>(base_), size_);
  }
}

GeoLoadError GeoRuleSet::Open(const std::string& path, bool verify_checksum) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return GeoLoadError::cannot_open;
  }

  struct stat st = {};
  if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
    ::close(fd);
    return GeoLoadError::cannot_open;
  }
  const auto file_size = static_cast<std::size_t>(st.st_size);
  if (file_size < sizeof(GeoArtifactHeader)) {
    ::close(fd);
    return GeoLoadError::too_small;
  }

  void* mapping = ::mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  // The descriptor is not needed once mapped; the mapping keeps the inode
  // alive even if the path is replaced underneath us.
  ::close(fd);
  if (mapping == MAP_FAILED) {
    return GeoLoadError::mmap_failed;
  }

  base_ = static_cast<const std::uint8_t*>(mapping);
  size_ = file_size;
  const auto* header = reinterpret_cast<const GeoArtifactHeader*>(base_);

  if (std::memcmp(header->magic, kMagic, sizeof(kMagic)) != 0) {
    ::munmap(mapping, size_);
    base_ = nullptr;
    size_ = 0;
    return GeoLoadError::bad_magic;
  }
  if (header->format_version != kFormatVersion) {
    ::munmap(mapping, size_);
    base_ = nullptr;
    size_ = 0;
    return GeoLoadError::unsupported_version;
  }

  header_ = header;
  const GeoLoadError error = Validate(verify_checksum);
  if (error != GeoLoadError::none) {
    ::munmap(mapping, size_);
    base_ = nullptr;
    size_ = 0;
    header_ = nullptr;
    return error;
  }

  // Only now, with every section proven in range, are the pointers resolved.
  ipv4_starts_ =
      reinterpret_cast<const std::uint32_t*>(base_ + header_->ipv4_offset);
  ipv4_actions_ = base_ + header_->ipv4_offset +
                  static_cast<std::size_t>(header_->ipv4_count) * sizeof(std::uint32_t);
  ipv6_rules_ =
      reinterpret_cast<const GeoIpv6Rule*>(base_ + header_->ipv6_offset);

  const std::size_t domain_actions_offset =
      header_->domain_offset +
      (static_cast<std::size_t>(header_->domain_count) + 1) * sizeof(std::uint32_t);
  domain_offsets_ =
      reinterpret_cast<const std::uint32_t*>(base_ + header_->domain_offset);
  domain_actions_ = base_ + domain_actions_offset;
  domain_kinds_ = domain_actions_ + header_->domain_count;
  domain_blob_ =
      reinterpret_cast<const char*>(base_ + header_->domain_blob_offset);

  const std::size_t substring_actions_offset =
      header_->substring_offset +
      (static_cast<std::size_t>(header_->substring_count) + 1) *
          sizeof(std::uint32_t);
  substring_offsets_ =
      reinterpret_cast<const std::uint32_t*>(base_ + header_->substring_offset);
  substring_actions_ = base_ + substring_actions_offset;
  substring_blob_ =
      reinterpret_cast<const char*>(base_ + header_->substring_blob_offset);

  pair_rules_ =
      reinterpret_cast<const GeoPairRule*>(base_ + header_->pair_offset);
  pair_blob_ = reinterpret_cast<const char*>(base_ + header_->pair_blob_offset);

  return GeoLoadError::none;
}

GeoLoadError GeoRuleSet::Validate(bool verify_checksum) const noexcept {
  const std::uint64_t total = size_;
  if (header_->total_size != size_) {
    return GeoLoadError::size_mismatch;
  }

  // Each section is checked as (offset, byte count) against the mapped
  // length. A wild offset here would be a wild read inside the process that
  // routes packets, so nothing is taken on trust.
  const std::uint64_t ipv4_bytes =
      static_cast<std::uint64_t>(header_->ipv4_count) *
      (sizeof(std::uint32_t) + 1);
  if (!InRange(header_->ipv4_offset, ipv4_bytes, total)) {
    return GeoLoadError::section_out_of_bounds;
  }

  const std::uint64_t ipv6_bytes =
      static_cast<std::uint64_t>(header_->ipv6_count) * sizeof(GeoIpv6Rule);
  if (!InRange(header_->ipv6_offset, ipv6_bytes, total)) {
    return GeoLoadError::section_out_of_bounds;
  }

  const std::uint64_t domain_bytes =
      (static_cast<std::uint64_t>(header_->domain_count) + 1) *
          sizeof(std::uint32_t) +
      static_cast<std::uint64_t>(header_->domain_count) * 2;
  if (!InRange(header_->domain_offset, domain_bytes, total) ||
      !InRange(header_->domain_blob_offset, header_->domain_blob_size, total)) {
    return GeoLoadError::section_out_of_bounds;
  }

  const std::uint64_t substring_bytes =
      (static_cast<std::uint64_t>(header_->substring_count) + 1) *
          sizeof(std::uint32_t) +
      header_->substring_count;
  if (!InRange(header_->substring_offset, substring_bytes, total) ||
      !InRange(header_->substring_blob_offset, header_->substring_blob_size,
          total)) {
    return GeoLoadError::section_out_of_bounds;
  }

  const std::uint64_t pair_bytes =
      static_cast<std::uint64_t>(header_->pair_count) * sizeof(GeoPairRule);
  if (!InRange(header_->pair_offset, pair_bytes, total) ||
      !InRange(header_->pair_blob_offset, header_->pair_blob_size, total)) {
    return GeoLoadError::section_out_of_bounds;
  }

  // Offset arrays index into their blob, so they must be monotonic and end
  // exactly at the blob's size. Checking it once here is what lets every
  // lookup index them without a bounds test.
  const auto check_offsets = [](const std::uint32_t* offsets,
                                 std::uint32_t count,
                                 std::uint32_t blob_size) -> GeoLoadError {
    if (count == 0) {
      return (offsets[0] == 0) ? GeoLoadError::none
                               : GeoLoadError::offsets_not_monotonic;
    }
    if (offsets[0] != 0) {
      return GeoLoadError::offsets_not_monotonic;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      if (offsets[i + 1] < offsets[i]) {
        return GeoLoadError::offsets_not_monotonic;
      }
    }
    if (offsets[count] != blob_size) {
      return GeoLoadError::blob_size_mismatch;
    }
    return GeoLoadError::none;
  };

  const auto* domain_offsets =
      reinterpret_cast<const std::uint32_t*>(base_ + header_->domain_offset);
  GeoLoadError error = check_offsets(
      domain_offsets, header_->domain_count, header_->domain_blob_size);
  if (error != GeoLoadError::none) {
    return error;
  }

  const auto* substring_offsets =
      reinterpret_cast<const std::uint32_t*>(base_ + header_->substring_offset);
  error = check_offsets(substring_offsets, header_->substring_count,
      header_->substring_blob_size);
  if (error != GeoLoadError::none) {
    return error;
  }

  const auto* pairs =
      reinterpret_cast<const GeoPairRule*>(base_ + header_->pair_offset);
  for (std::uint32_t i = 0; i < header_->pair_count; ++i) {
    if (!InRange(pairs[i].contains_offset, pairs[i].contains_size,
            header_->pair_blob_size) ||
        !InRange(pairs[i].suffix_offset, pairs[i].suffix_size,
            header_->pair_blob_size)) {
      return GeoLoadError::section_out_of_bounds;
    }
  }

  if (verify_checksum) {
    std::uint8_t digest[kSha256Size] = {};
    const std::size_t body_offset = sizeof(GeoArtifactHeader);
    ::SHA256(base_ + body_offset, size_ - body_offset, digest);
    if (std::memcmp(digest, header_->body_sha256, kSha256Size) != 0) {
      return GeoLoadError::checksum_mismatch;
    }
  }

  return GeoLoadError::none;
}

GeoAction GeoRuleSet::LookupIpv4(std::uint32_t address) const noexcept {
  if (header_ == nullptr || header_->ipv4_count == 0) {
    return GeoAction::none;
  }
  // The intervals are disjoint and cover the whole space -- gaps are explicit
  // `none` entries -- so the predecessor IS the answer and no containment
  // test is needed.
  const std::uint32_t* begin = ipv4_starts_;
  const std::uint32_t* end = begin + header_->ipv4_count;
  const std::uint32_t* it = std::upper_bound(begin, end, address);
  if (it == begin) {
    return GeoAction::none;
  }
  const auto index = static_cast<std::size_t>((it - 1) - begin);
  return static_cast<GeoAction>(ipv4_actions_[index]);
}

GeoAction GeoRuleSet::LookupIpv6(
    std::uint64_t high, std::uint64_t low) const noexcept {
  if (header_ == nullptr || header_->ipv6_count == 0) {
    return GeoAction::none;
  }
  // ~88 rules: a linear scan tracking the longest prefix is both obviously
  // correct and faster than the 128-bit interval machinery it would replace.
  GeoAction best = GeoAction::none;
  std::uint8_t best_prefix = 0;
  for (std::uint32_t i = 0; i < header_->ipv6_count; ++i) {
    const GeoIpv6Rule& rule = ipv6_rules_[i];
    if (rule.prefix > 128) {
      continue;
    }
    std::uint64_t masked_high = high;
    std::uint64_t masked_low = low;
    if (rule.prefix == 0) {
      masked_high = 0;
      masked_low = 0;
    } else if (rule.prefix <= 64) {
      masked_high = (rule.prefix == 64)
                        ? high
                        : (high & (~0ULL << (64 - rule.prefix)));
      masked_low = 0;
    } else {
      masked_low = (rule.prefix == 128)
                       ? low
                       : (low & (~0ULL << (128 - rule.prefix)));
    }
    if (masked_high == rule.high && masked_low == rule.low &&
        (best == GeoAction::none || rule.prefix > best_prefix)) {
      best = static_cast<GeoAction>(rule.action);
      best_prefix = rule.prefix;
    }
  }
  return best;
}

GeoAction GeoRuleSet::LookupDomain(std::string_view domain) const noexcept {
  if (header_ == nullptr) {
    return GeoAction::none;
  }

  char forward[kMaxDomainLength];
  const std::size_t forward_len =
      NormalizeDomain(domain, forward, sizeof(forward));
  if (forward_len == 0) {
    return GeoAction::none;
  }

  const std::string_view forward_view(forward, forward_len);

  // A name with no dot at all is a local hostname (`nas`, `router`). The
  // published lists express this as a regex; it reduces to one bit.
  if ((header_->flags & kFlagBareHostnameIsDirect) != 0 &&
      forward_view.find('.') == std::string_view::npos) {
    return GeoAction::direct;
  }

  if (header_->domain_count != 0) {
    char reversed[kMaxDomainLength];
    const std::size_t reversed_len =
        ReverseLabels(forward, forward_len, reversed, sizeof(reversed));
    if (reversed_len != 0) {
      const std::string_view query(reversed, reversed_len);

      // One binary search per label boundary, longest match wins. Bounded by
      // the TABLE's deepest rule, not by the query, so a name with a hundred
      // labels cannot turn a lookup into a hundred searches.
      GeoAction best = GeoAction::none;
      std::size_t label = 0;
      const std::size_t max_labels = header_->max_domain_labels;
      for (std::size_t i = 0; i <= reversed_len && label < max_labels; ++i) {
        if (i != reversed_len && reversed[i] != '.') {
          continue;
        }
        ++label;
        const std::string_view candidate = query.substr(0, i);

        std::uint32_t lo = 0;
        std::uint32_t hi = header_->domain_count;
        while (lo < hi) {
          const std::uint32_t mid = lo + (hi - lo) / 2;
          const std::string_view entry(
              domain_blob_ + domain_offsets_[mid],
              domain_offsets_[mid + 1] - domain_offsets_[mid]);
          if (entry < candidate) {
            lo = mid + 1;
          } else {
            hi = mid;
          }
        }
        if (lo < header_->domain_count) {
          const std::string_view entry(domain_blob_ + domain_offsets_[lo],
              domain_offsets_[lo + 1] - domain_offsets_[lo]);
          if (entry == candidate) {
            const auto kind = static_cast<GeoDomainKind>(domain_kinds_[lo]);
            // `exact` must match the whole name, not a suffix of it.
            if (kind == GeoDomainKind::suffix || i == reversed_len) {
              best = static_cast<GeoAction>(domain_actions_[lo]);
            }
          }
        }
      }
      if (best != GeoAction::none) {
        return best;
      }
    }
  }

  // Substring rules, consulted only after the sorted table misses. ~105 short
  // needles over a name of at most 253 bytes, once per flow.
  for (std::uint32_t i = 0; i < header_->substring_count; ++i) {
    const std::string_view needle(substring_blob_ + substring_offsets_[i],
        substring_offsets_[i + 1] - substring_offsets_[i]);
    if (!needle.empty() &&
        forward_view.find(needle) != std::string_view::npos) {
      return static_cast<GeoAction>(substring_actions_[i]);
    }
  }

  for (std::uint32_t i = 0; i < header_->pair_count; ++i) {
    const GeoPairRule& rule = pair_rules_[i];
    const std::string_view contains(
        pair_blob_ + rule.contains_offset, rule.contains_size);
    const std::string_view suffix(
        pair_blob_ + rule.suffix_offset, rule.suffix_size);
    if (forward_view.size() >= suffix.size() &&
        forward_view.compare(forward_view.size() - suffix.size(),
            suffix.size(), suffix) == 0 &&
        forward_view.find(contains) != std::string_view::npos) {
      return static_cast<GeoAction>(rule.action);
    }
  }

  return GeoAction::none;
}

GeoAction GeoRuleSet::default_action() const noexcept {
  return header_ == nullptr ? GeoAction::none
                            : static_cast<GeoAction>(header_->default_action);
}

std::uint32_t GeoRuleSet::verdict_map_id() const noexcept {
  return header_ == nullptr ? 0 : header_->verdict_map_id;
}

std::uint32_t GeoRuleSet::ipv4_count() const noexcept {
  return header_ == nullptr ? 0 : header_->ipv4_count;
}

std::uint32_t GeoRuleSet::ipv6_count() const noexcept {
  return header_ == nullptr ? 0 : header_->ipv6_count;
}

std::uint32_t GeoRuleSet::domain_count() const noexcept {
  return header_ == nullptr ? 0 : header_->domain_count;
}

std::uint32_t GeoRuleSet::substring_count() const noexcept {
  return header_ == nullptr ? 0 : header_->substring_count;
}

std::uint32_t GeoRuleSet::pair_count() const noexcept {
  return header_ == nullptr ? 0 : header_->pair_count;
}

std::string GeoRuleSet::body_sha256_hex() const {
  if (header_ == nullptr) {
    return {};
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(kSha256Size * 2);
  for (const std::uint8_t byte : header_->body_sha256) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

}  // namespace fptn::geo
