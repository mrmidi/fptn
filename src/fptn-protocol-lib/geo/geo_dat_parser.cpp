/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_dat_parser.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace fptn::geo {

namespace {

// Wire types we understand. Anything else is a file we should not be reading.
constexpr int kWireVarint = 0;
constexpr int kWireFixed64 = 1;
constexpr int kWireLengthDelimited = 2;
constexpr int kWireFixed32 = 5;

// Thrown internally and caught at the two public entry points. The parse is a
// deep recursive descent over a hostile file; threading an error code back up
// through every level would bury the actual logic.
struct ParseFailure {
  GeoDatError error;
  std::size_t offset;
};

// The slice of protobuf the geo formats need: varints, length-delimited
// submessages, and enough of the rest to SKIP fields we do not model. Unknown
// fields are skipped rather than rejected -- the publisher is free to add
// fields, and a reader that refuses to is a reader that breaks on the next
// release.
class Reader {
 public:
  Reader(std::span<const std::uint8_t> bytes, std::size_t begin,
      std::size_t end)
      : bytes_(bytes), position_(begin), end_(end) {}

  bool AtEnd() const noexcept { return position_ >= end_; }
  std::size_t offset() const noexcept { return position_; }

  std::uint64_t ReadVarint() {
    std::uint64_t result = 0;
    std::uint64_t shift = 0;
    const std::size_t start = position_;
    while (position_ < end_) {
      const std::uint8_t byte = bytes_[position_];
      ++position_;
      // Bits past 64 would silently wrap; a varint that long is malformed
      // rather than merely large.
      if (shift >= 64) {
        throw ParseFailure{GeoDatError::illegal_field_number, start};
      }
      result |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
      if ((byte & 0x80) == 0) {
        return result;
      }
      shift += 7;
    }
    throw ParseFailure{GeoDatError::truncated, start};
  }

  struct Field {
    int number = 0;
    int wire_type = 0;
  };

  // False at the end of the message.
  bool NextField(Field& field) {
    if (AtEnd()) {
      return false;
    }
    const std::size_t start = position_;
    const std::uint64_t key = ReadVarint();
    field.number = static_cast<int>(key >> 3);
    field.wire_type = static_cast<int>(key & 0x07);
    if (field.number == 0) {
      throw ParseFailure{GeoDatError::illegal_field_number, start};
    }
    return true;
  }

  // Range of a length-delimited payload, without copying it.
  std::pair<std::size_t, std::size_t> ReadLengthDelimited() {
    const std::size_t start = position_;
    const std::uint64_t length = ReadVarint();
    // A corrupt file can encode a length past the end of the buffer; compare
    // against what remains rather than computing position_ + length, which
    // would itself overflow.
    if (length > static_cast<std::uint64_t>(end_ - position_)) {
      throw ParseFailure{GeoDatError::truncated, start};
    }
    const std::size_t begin = position_;
    position_ += static_cast<std::size_t>(length);
    return {begin, position_};
  }

  std::string ReadString() {
    const auto [begin, end] = ReadLengthDelimited();
    return std::string(
        reinterpret_cast<const char*>(bytes_.data()) + begin, end - begin);
  }

  std::vector<std::uint8_t> ReadBytes() {
    const auto [begin, end] = ReadLengthDelimited();
    return std::vector<std::uint8_t>(
        bytes_.begin() + static_cast<std::ptrdiff_t>(begin),
        bytes_.begin() + static_cast<std::ptrdiff_t>(end));
  }

  void Skip(int wire_type) {
    const std::size_t start = position_;
    switch (wire_type) {
      case kWireVarint:
        (void)ReadVarint();
        return;
      case kWireFixed64:
        Advance(8, start);
        return;
      case kWireLengthDelimited:
        (void)ReadLengthDelimited();
        return;
      case kWireFixed32:
        Advance(4, start);
        return;
      default:
        throw ParseFailure{GeoDatError::unsupported_wire_type, start};
    }
  }

  Reader Sub(std::pair<std::size_t, std::size_t> range) const {
    return Reader(bytes_, range.first, range.second);
  }

  void Expect(const Field& field, int wire_type) const {
    if (field.wire_type != wire_type) {
      throw ParseFailure{GeoDatError::unexpected_wire_type, position_};
    }
  }

 private:
  void Advance(std::size_t count, std::size_t start) {
    if (count > end_ - position_) {
      throw ParseFailure{GeoDatError::truncated, start};
    }
    position_ += count;
  }

  std::span<const std::uint8_t> bytes_;
  std::size_t position_;
  std::size_t end_;
};

std::string ToUpperAscii(std::string value) {
  for (char& c : value) {
    if (c >= 'a' && c <= 'z') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  return value;
}

std::string TrimAndLower(std::string value) {
  const auto is_space = [](unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  std::size_t begin = 0;
  std::size_t end = value.size();
  while (begin < end && is_space(static_cast<unsigned char>(value[begin]))) {
    ++begin;
  }
  while (end > begin && is_space(static_cast<unsigned char>(value[end - 1]))) {
    --end;
  }
  std::string out = value.substr(begin, end - begin);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

// CIDR { bytes ip = 1; uint32 prefix = 2 }
GeoDatCidr ParseCidr(Reader reader) {
  std::vector<std::uint8_t> raw;
  std::uint64_t prefix = 0;
  const std::size_t start = reader.offset();

  Reader::Field field;
  while (reader.NextField(field)) {
    switch (field.number) {
      case 1:
        reader.Expect(field, kWireLengthDelimited);
        raw = reader.ReadBytes();
        break;
      case 2:
        reader.Expect(field, kWireVarint);
        prefix = reader.ReadVarint();
        break;
      default:
        reader.Skip(field.wire_type);
        break;
    }
  }

  GeoDatCidr cidr;
  if (raw.size() == 4) {
    cidr.is_ipv6 = false;
    cidr.low = (static_cast<std::uint64_t>(raw[0]) << 24) |
               (static_cast<std::uint64_t>(raw[1]) << 16) |
               (static_cast<std::uint64_t>(raw[2]) << 8) |
               static_cast<std::uint64_t>(raw[3]);
  } else if (raw.size() == 16) {
    cidr.is_ipv6 = true;
    for (std::size_t i = 0; i < 8; ++i) {
      cidr.high = (cidr.high << 8) | raw[i];
      cidr.low = (cidr.low << 8) | raw[i + 8];
    }
  } else {
    throw ParseFailure{GeoDatError::invalid_address_length, start};
  }

  const std::uint64_t width = cidr.is_ipv6 ? 128 : 32;
  if (prefix > width) {
    throw ParseFailure{GeoDatError::invalid_prefix, start};
  }
  cidr.prefix = static_cast<std::uint8_t>(prefix);
  return cidr;
}

// Domain { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//
// False for a rule with no usable value.
bool ParseDomain(Reader reader, GeoDatDomain& out) {
  std::uint64_t type = 0;
  std::string value;

  Reader::Field field;
  while (reader.NextField(field)) {
    switch (field.number) {
      case 1:
        reader.Expect(field, kWireVarint);
        type = reader.ReadVarint();
        break;
      case 2:
        reader.Expect(field, kWireLengthDelimited);
        value = reader.ReadString();
        break;
      default:
        // Field 3 is the attribute list (`@cn`, `@ads`), unused here.
        reader.Skip(field.wire_type);
        break;
    }
  }

  out.value = TrimAndLower(std::move(value));
  if (out.value.empty()) {
    return false;
  }
  // An unrecognised type reads as `plain`, which is the format's own default
  // for an absent field.
  out.type = (type <= static_cast<std::uint64_t>(GeoDatDomainType::full))
                 ? static_cast<GeoDatDomainType>(type)
                 : GeoDatDomainType::plain;
  return true;
}

// GeoSite { string country_code = 1; repeated Domain domain = 2;
//           bytes resource_hash = 3; string code = 4 }
GeoDatSiteGroup ParseSiteGroup(Reader reader) {
  const std::size_t start = reader.offset();
  std::string country_code;
  std::string code;
  GeoDatSiteGroup group;

  Reader::Field field;
  while (reader.NextField(field)) {
    switch (field.number) {
      case 1:
        reader.Expect(field, kWireLengthDelimited);
        country_code = reader.ReadString();
        break;
      case 2: {
        reader.Expect(field, kWireLengthDelimited);
        const auto range = reader.ReadLengthDelimited();
        GeoDatDomain domain;
        if (ParseDomain(reader.Sub(range), domain)) {
          group.domains.push_back(std::move(domain));
        }
        break;
      }
      case 4:
        reader.Expect(field, kWireLengthDelimited);
        code = reader.ReadString();
        break;
      default:
        reader.Skip(field.wire_type);
        break;
    }
  }

  group.name = ToUpperAscii(code.empty() ? country_code : code);
  if (group.name.empty()) {
    throw ParseFailure{GeoDatError::unnamed_group, start};
  }
  return group;
}

// GeoIP { string country_code = 1; repeated CIDR cidr = 2;
//         bool inverse_match = 3; bytes resource_hash = 4; string code = 5 }
GeoDatIpGroup ParseIpGroup(Reader reader) {
  const std::size_t start = reader.offset();
  std::string country_code;
  std::string code;
  GeoDatIpGroup group;

  Reader::Field field;
  while (reader.NextField(field)) {
    switch (field.number) {
      case 1:
        reader.Expect(field, kWireLengthDelimited);
        country_code = reader.ReadString();
        break;
      case 2: {
        reader.Expect(field, kWireLengthDelimited);
        const auto range = reader.ReadLengthDelimited();
        group.cidrs.push_back(ParseCidr(reader.Sub(range)));
        break;
      }
      case 3:
        reader.Expect(field, kWireVarint);
        group.inverse_match = reader.ReadVarint() != 0;
        break;
      case 5:
        reader.Expect(field, kWireLengthDelimited);
        code = reader.ReadString();
        break;
      default:
        reader.Skip(field.wire_type);
        break;
    }
  }

  group.name = ToUpperAscii(code.empty() ? country_code : code);
  if (group.name.empty()) {
    throw ParseFailure{GeoDatError::unnamed_group, start};
  }
  return group;
}

GeoDatError CheckContainer(std::span<const std::uint8_t> bytes) {
  if (bytes.empty()) {
    return GeoDatError::empty;
  }
  // These files are published uncompressed. Recognising the gzip magic gives a
  // precise answer instead of a stream of nonsense field numbers.
  if (bytes.size() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B) {
    return GeoDatError::gzipped;
  }
  return GeoDatError::none;
}

// Both containers are `repeated Entry entry = 1`, so the outer loop is the
// same for either; only the per-entry decoder differs.
template <typename Group, typename ParseGroup>
GeoDatResult<Group> ParseContainer(
    std::span<const std::uint8_t> bytes, ParseGroup parse_group) {
  GeoDatResult<Group> result;
  result.error = CheckContainer(bytes);
  if (!result.ok()) {
    return result;
  }

  try {
    Reader reader(bytes, 0, bytes.size());
    Reader::Field field;
    while (reader.NextField(field)) {
      if (field.number != 1) {
        reader.Skip(field.wire_type);
        continue;
      }
      reader.Expect(field, kWireLengthDelimited);
      const auto range = reader.ReadLengthDelimited();
      result.groups.push_back(parse_group(reader.Sub(range)));
    }
  } catch (const ParseFailure& failure) {
    result.error = failure.error;
    result.error_offset = failure.offset;
    result.groups.clear();
    return result;
  }

  if (result.groups.empty()) {
    result.error = GeoDatError::no_groups;
  }
  return result;
}

}  // namespace

const char* ToString(GeoDatError error) noexcept {
  switch (error) {
    case GeoDatError::none:
      return "none";
    case GeoDatError::empty:
      return "empty file";
    case GeoDatError::gzipped:
      return "gzip-compressed file";
    case GeoDatError::truncated:
      return "truncated record";
    case GeoDatError::illegal_field_number:
      return "illegal field number";
    case GeoDatError::unsupported_wire_type:
      return "unsupported wire type";
    case GeoDatError::unexpected_wire_type:
      return "unexpected wire type";
    case GeoDatError::invalid_address_length:
      return "address is neither 4 nor 16 bytes";
    case GeoDatError::invalid_prefix:
      return "prefix out of range";
    case GeoDatError::unnamed_group:
      return "group has no name";
    case GeoDatError::no_groups:
      return "file contains no groups";
  }
  return "unknown";
}

GeoDatSiteResult GeoDatParser::ParseGeoSite(
    std::span<const std::uint8_t> bytes) {
  return ParseContainer<GeoDatSiteGroup>(
      bytes, [](Reader reader) { return ParseSiteGroup(std::move(reader)); });
}

GeoDatIpResult GeoDatParser::ParseGeoIp(std::span<const std::uint8_t> bytes) {
  return ParseContainer<GeoDatIpGroup>(
      bytes, [](Reader reader) { return ParseIpGroup(std::move(reader)); });
}

}  // namespace fptn::geo
