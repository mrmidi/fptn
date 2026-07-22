#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "common/network/ip_packet.h"
#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"

namespace {

fptn::common::network::IPPacketPtr MakeIPv4Packet(std::uint8_t marker) {
  fptn::common::network::IPPacketData bytes(20, 0);
  bytes[0] = 0x45;
  bytes[2] = 0;
  bytes[3] = 20;
  bytes[8] = 64;
  bytes[9] = marker;
  bytes[12] = 10;
  bytes[15] = 1;
  bytes[16] = 10;
  bytes[19] = 2;
  return fptn::common::network::IPPacket::Parse(std::move(bytes));
}

fptn::common::network::BatchIPPacketPtr MakeBatch() {
  fptn::common::network::BatchIPPacketPtr batch;
  batch.push_back(MakeIPv4Packet(6));
  batch.push_back(MakeIPv4Packet(17));
  return batch;
}

TEST(PacketSerializerTest, OwnedAndLegacyFramesAreByteIdentical) {
  auto owned = fptn::protocol::yaff::SerializeBatchIPPacketOwned(MakeBatch());
  auto legacy = fptn::protocol::yaff::SerializeBatchIPPacket(MakeBatch());

  ASSERT_TRUE(owned.has_value());
  ASSERT_TRUE(legacy.has_value());
  ASSERT_EQ(owned->size(), legacy->size());
  EXPECT_EQ(0, std::memcmp(owned->data(), legacy->data(), owned->size()));
}

}  // namespace
