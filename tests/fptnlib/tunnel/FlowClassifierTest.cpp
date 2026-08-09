/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "fptn-protocol-lib/tunnel/flow_classifier.h"
#include "fptn-protocol-lib/tunnel/routing_policy.h"

namespace {

using namespace fptn::tunnel;

IpKey V4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  IpKey key;
  key.version = 4;
  key.bytes[0] = a;
  key.bytes[1] = b;
  key.bytes[2] = c;
  key.bytes[3] = d;
  return key;
}

IpKey V6(std::uint16_t last) {
  IpKey key;
  key.version = 6;
  key.bytes[0] = 0x20;
  key.bytes[1] = 0x01;
  key.bytes[14] = static_cast<std::uint8_t>(last >> 8);
  key.bytes[15] = static_cast<std::uint8_t>(last & 0xFFu);
  return key;
}

void PutBe16(std::vector<std::uint8_t>& out, std::size_t at,
    std::uint16_t value) {
  out[at] = static_cast<std::uint8_t>(value >> 8);
  out[at + 1] = static_cast<std::uint8_t>(value & 0xFFu);
}

// Minimal IPv4 header plus four bytes of transport ports.
std::vector<std::uint8_t> MakeV4(const IpKey& src, const IpKey& dst,
    std::uint16_t sport, std::uint16_t dport, std::uint8_t proto = 6,
    std::uint16_t fragment_offset = 0) {
  std::vector<std::uint8_t> packet(24, 0);
  packet[0] = 0x45;
  PutBe16(packet, 2, 24);
  PutBe16(packet, 6, fragment_offset);
  packet[8] = 64;
  packet[9] = proto;
  std::memcpy(packet.data() + 12, src.bytes.data(), 4);
  std::memcpy(packet.data() + 16, dst.bytes.data(), 4);
  PutBe16(packet, 20, sport);
  PutBe16(packet, 22, dport);
  return packet;
}

std::vector<std::uint8_t> MakeV6(const IpKey& src, const IpKey& dst,
    std::uint16_t sport, std::uint16_t dport, std::uint8_t next = 6) {
  std::vector<std::uint8_t> packet(44, 0);
  packet[0] = 0x60;
  PutBe16(packet, 4, 4);
  packet[6] = next;
  packet[7] = 64;
  std::memcpy(packet.data() + 8, src.bytes.data(), 16);
  std::memcpy(packet.data() + 24, dst.bytes.data(), 16);
  PutBe16(packet, 40, sport);
  PutBe16(packet, 42, dport);
  return packet;
}

PacketLease LeaseOf(const std::vector<std::uint8_t>& packet) {
  return PacketLease{packet.data(),
      static_cast<std::uint32_t>(packet.size()),
      static_cast<std::uint8_t>(packet[0] >> 4), nullptr, nullptr};
}

class FakeAttribution final : public IDomainAttribution {
 public:
  void Set(const IpKey& address, std::string domain) {
    entries_.emplace_back(address, std::move(domain));
  }

  std::string LookupDomain(const IpKey& address) const override {
    ++lookups;
    for (const auto& [key, domain] : entries_) {
      if (key == address) {
        return domain;
      }
    }
    return {};
  }

  mutable int lookups = 0;

 private:
  std::vector<std::pair<IpKey, std::string>> entries_;
};

class FlowClassifierTest : public ::testing::Test {
 protected:
  FlowClassifierTest() : policy_(RouteAction::fptn_l4) {}

  void SetUp() override {
    policy_.AddRule("2ip.ru", RouteAction::direct);
    policy_.AddRule("mail.ru", RouteAction::reject);
    policy_.AddRule("ads.example", RouteAction::drop);
  }

  std::unique_ptr<FlowClassifier> Make(ClassifierConfiguration config = {}) {
    return std::make_unique<FlowClassifier>(config, policy_, attribution_);
  }

  StaticDomainPolicy policy_;
  FakeAttribution attribution_;
};

// ---- PeekFiveTuple ----------------------------------------------------

TEST(PeekFiveTupleTest, ReadsIPv4TcpTuple) {
  const auto packet = MakeV4(V4(10, 8, 0, 2), V4(93, 184, 216, 34), 50000, 443);
  FiveTuple tuple;
  ASSERT_TRUE(PeekFiveTuple(packet.data(),
      static_cast<std::uint32_t>(packet.size()), tuple));

  EXPECT_EQ(tuple.protocol, TransportProtocol::tcp);
  EXPECT_EQ(tuple.source, V4(10, 8, 0, 2));
  EXPECT_EQ(tuple.destination, V4(93, 184, 216, 34));
  EXPECT_EQ(tuple.source_port, 50000);
  EXPECT_EQ(tuple.destination_port, 443);
}

TEST(PeekFiveTupleTest, ReadsIPv4UdpTuple) {
  const auto packet =
      MakeV4(V4(10, 8, 0, 2), V4(1, 1, 1, 1), 40000, 53, 17);
  FiveTuple tuple;
  ASSERT_TRUE(PeekFiveTuple(packet.data(),
      static_cast<std::uint32_t>(packet.size()), tuple));
  EXPECT_EQ(tuple.protocol, TransportProtocol::udp);
  EXPECT_EQ(tuple.destination_port, 53);
}

TEST(PeekFiveTupleTest, ReadsIPv6Tuple) {
  const auto packet = MakeV6(V6(2), V6(0x1001), 50000, 443);
  FiveTuple tuple;
  ASSERT_TRUE(PeekFiveTuple(packet.data(),
      static_cast<std::uint32_t>(packet.size()), tuple));
  EXPECT_EQ(tuple.source, V6(2));
  EXPECT_EQ(tuple.destination, V6(0x1001));
  EXPECT_EQ(tuple.destination_port, 443);
}

TEST(PeekFiveTupleTest, HonoursIPv4HeaderOptions) {
  auto packet = MakeV4(V4(10, 8, 0, 2), V4(8, 8, 8, 8), 1234, 443);
  // Grow the header to 24 bytes of options and push the ports out with it.
  packet[0] = 0x46;
  packet.insert(packet.begin() + 20, 4, 0);
  FiveTuple tuple;
  ASSERT_TRUE(PeekFiveTuple(packet.data(),
      static_cast<std::uint32_t>(packet.size()), tuple));
  EXPECT_EQ(tuple.source_port, 1234);
  EXPECT_EQ(tuple.destination_port, 443);
}

TEST(PeekFiveTupleTest, RejectsUnkeyableInput) {
  FiveTuple tuple;
  // Null and truncated.
  EXPECT_FALSE(PeekFiveTuple(nullptr, 20, tuple));
  const auto packet = MakeV4(V4(10, 8, 0, 2), V4(8, 8, 8, 8), 1, 2);
  EXPECT_FALSE(PeekFiveTuple(packet.data(), 19, tuple));
  // ICMP carries no ports.
  const auto icmp = MakeV4(V4(10, 8, 0, 2), V4(8, 8, 8, 8), 0, 0, 1);
  EXPECT_FALSE(PeekFiveTuple(icmp.data(),
      static_cast<std::uint32_t>(icmp.size()), tuple));
  // A non-first fragment has no transport header.
  const auto fragment =
      MakeV4(V4(10, 8, 0, 2), V4(8, 8, 8, 8), 1, 2, 6, 0x0025);
  EXPECT_FALSE(PeekFiveTuple(fragment.data(),
      static_cast<std::uint32_t>(fragment.size()), tuple));
  // IPv6 extension headers are not walked.
  const auto v6_ext = MakeV6(V6(2), V6(3), 1, 2, 43);
  EXPECT_FALSE(PeekFiveTuple(v6_ext.data(),
      static_cast<std::uint32_t>(v6_ext.size()), tuple));
}

// ---- Classification ---------------------------------------------------

TEST_F(FlowClassifierTest, UnattributedDestinationTunnels) {
  auto classifier = Make();
  const auto packet =
      MakeV4(V4(10, 8, 0, 2), V4(93, 184, 216, 34), 50000, 443);
  EXPECT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::fptn_l4);
}

TEST_F(FlowClassifierTest, AttributedDestinationTakesThePolicyVerdict) {
  attribution_.Set(V4(104, 21, 0, 1), "2ip.ru");
  attribution_.Set(V4(94, 100, 180, 200), "smtp.mail.ru");
  attribution_.Set(V4(203, 0, 113, 7), "tracker.ads.example");
  auto classifier = Make();

  const auto direct = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);
  const auto reject =
      MakeV4(V4(10, 8, 0, 2), V4(94, 100, 180, 200), 1001, 443);
  const auto drop = MakeV4(V4(10, 8, 0, 2), V4(203, 0, 113, 7), 1002, 443);

  EXPECT_EQ(classifier->Classify(LeaseOf(direct)), RouteAction::direct);
  EXPECT_EQ(classifier->Classify(LeaseOf(reject)), RouteAction::reject);
  EXPECT_EQ(classifier->Classify(LeaseOf(drop)), RouteAction::drop);
}

TEST_F(FlowClassifierTest, UnclassifiablePacketsTunnel) {
  auto classifier = Make();
  const auto icmp = MakeV4(V4(10, 8, 0, 2), V4(8, 8, 8, 8), 0, 0, 1);
  EXPECT_EQ(classifier->Classify(LeaseOf(icmp)), RouteAction::fptn_l4);
  EXPECT_EQ(classifier->Counters().unclassifiable, 1u);
}

TEST_F(FlowClassifierTest, ServerEndpointIsNeverTunnelled) {
  // The server's own address resolves to a tunnelled domain; the pinned rule
  // must win, or the transport would carry its own packets.
  attribution_.Set(V4(198, 51, 100, 5), "mail.ru");
  auto classifier = Make();
  classifier->SetServerEndpoint(V4(198, 51, 100, 5), 443);

  const auto packet =
      MakeV4(V4(10, 8, 0, 2), V4(198, 51, 100, 5), 50000, 443);
  EXPECT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::direct);
}

TEST_F(FlowClassifierTest, ResolverTrafficAlwaysTunnels) {
  // A resolver address that the policy would otherwise send direct.
  attribution_.Set(V4(10, 8, 0, 1), "2ip.ru");
  auto classifier = Make();
  classifier->SetTunnelResolvers({V4(10, 8, 0, 1), V4(10, 8, 0, 253)});

  const auto dns = MakeV4(V4(10, 8, 0, 2), V4(10, 8, 0, 1), 40000, 53, 17);
  EXPECT_EQ(classifier->Classify(LeaseOf(dns)), RouteAction::fptn_l4);
}

TEST_F(FlowClassifierTest, VerdictIsDecidedOncePerFlow) {
  attribution_.Set(V4(104, 21, 0, 1), "2ip.ru");
  auto classifier = Make();
  const auto packet = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);

  EXPECT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::direct);
  const int after_first = attribution_.lookups;
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::direct);
  }
  // Cached: no further attribution lookups, and the verdict cannot flip
  // mid-flow even if the DNS map changes.
  EXPECT_EQ(attribution_.lookups, after_first);
  EXPECT_EQ(classifier->Counters().decisions, 1u);
  EXPECT_EQ(classifier->Counters().table_hits, 5u);
}

TEST_F(FlowClassifierTest, VerdictTallyCountsFlowsNotPackets) {
  attribution_.Set(V4(104, 21, 0, 1), "2ip.ru");
  attribution_.Set(V4(104, 21, 0, 2), "mail.ru");
  attribution_.Set(V4(104, 21, 0, 3), "ads.example");
  auto classifier = Make();

  // One flow per verdict, each seen several times: the tally must follow the
  // decision, not the packet, or it would just restate the packet counters.
  const auto direct = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);
  const auto reject = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 2), 1001, 443);
  const auto drop = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 3), 1002, 443);
  const auto fptn = MakeV4(V4(10, 8, 0, 2), V4(93, 184, 216, 34), 1003, 443);

  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(classifier->Classify(LeaseOf(direct)), RouteAction::direct);
    EXPECT_EQ(classifier->Classify(LeaseOf(reject)), RouteAction::reject);
    EXPECT_EQ(classifier->Classify(LeaseOf(drop)), RouteAction::drop);
    EXPECT_EQ(classifier->Classify(LeaseOf(fptn)), RouteAction::fptn_l4);
  }

  const auto counters = classifier->Counters();
  EXPECT_EQ(counters.direct_flows, 1u);
  EXPECT_EQ(counters.rejected_flows, 1u);
  EXPECT_EQ(counters.dropped_flows, 1u);
  EXPECT_EQ(counters.fptn_flows, 1u);
  // The invariant the funnel line is read against: the four partition
  // `decisions`, so a nonzero remainder means a verdict went uncounted.
  EXPECT_EQ(counters.direct_flows + counters.rejected_flows +
                counters.dropped_flows + counters.fptn_flows,
      counters.decisions);
  EXPECT_EQ(counters.classified_packets, 12u);
}

TEST_F(FlowClassifierTest, VerdictTallyCountsThePinnedRules) {
  auto classifier = Make();
  classifier->SetServerEndpoint(V4(85, 155, 124, 43), 443);
  classifier->SetTunnelResolvers({V4(10, 8, 0, 1)});

  const auto server = MakeV4(V4(10, 8, 0, 2), V4(85, 155, 124, 43), 1000, 443);
  const auto resolver = MakeV4(V4(10, 8, 0, 2), V4(10, 8, 0, 1), 1001, 53, 17);
  EXPECT_EQ(classifier->Classify(LeaseOf(server)), RouteAction::direct);
  EXPECT_EQ(classifier->Classify(LeaseOf(resolver)), RouteAction::fptn_l4);

  // The pinned rules return before the policy is consulted, so they are the
  // easy ones to leave out of the tally and break the sum invariant.
  const auto counters = classifier->Counters();
  EXPECT_EQ(counters.direct_flows, 1u);
  EXPECT_EQ(counters.fptn_flows, 1u);
  EXPECT_EQ(counters.decisions, 2u);
}

TEST_F(FlowClassifierTest, DistinctFlowsAreKeyedSeparately) {
  attribution_.Set(V4(104, 21, 0, 1), "2ip.ru");
  auto classifier = Make();

  const auto a = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);
  const auto b = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1001, 443);
  const auto c = MakeV4(V4(10, 8, 0, 2), V4(93, 184, 216, 34), 1000, 443);

  EXPECT_EQ(classifier->Classify(LeaseOf(a)), RouteAction::direct);
  EXPECT_EQ(classifier->Classify(LeaseOf(b)), RouteAction::direct);
  EXPECT_EQ(classifier->Classify(LeaseOf(c)), RouteAction::fptn_l4);
  EXPECT_EQ(classifier->Counters().active_flows, 3u);
}

TEST_F(FlowClassifierTest, LookupVerdictReadsBackTheStackSideFlow) {
  attribution_.Set(V4(104, 21, 0, 1), "2ip.ru");
  auto classifier = Make();
  const auto packet = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);
  ASSERT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::direct);

  // lwIP reports the app as `source` and the real destination as
  // `destination`, matching the ingress packet's orientation.
  FlowMetadata metadata;
  metadata.protocol = TransportProtocol::tcp;
  metadata.source.address =
      boost::asio::ip::make_address("10.8.0.2");
  metadata.source.port = 1000;
  metadata.destination.address =
      boost::asio::ip::make_address("104.21.0.1");
  metadata.destination.port = 443;

  const auto verdict = classifier->LookupVerdict(metadata);
  ASSERT_TRUE(verdict.has_value());
  EXPECT_EQ(*verdict, RouteAction::direct);

  metadata.source.port = 9999;
  EXPECT_FALSE(classifier->LookupVerdict(metadata).has_value());
}

TEST_F(FlowClassifierTest, IdleFlowsExpire) {
  ClassifierConfiguration config;
  config.flow_idle_timeout = std::chrono::milliseconds(0);
  auto classifier = Make(config);

  const auto packet = MakeV4(V4(10, 8, 0, 2), V4(104, 21, 0, 1), 1000, 443);
  classifier->Classify(LeaseOf(packet));
  ASSERT_EQ(classifier->Counters().active_flows, 1u);

  const auto removed =
      classifier->ExpireIdle(std::chrono::steady_clock::now() +
          std::chrono::seconds(1));
  EXPECT_EQ(removed, 1u);
  EXPECT_EQ(classifier->Counters().active_flows, 0u);
}

TEST_F(FlowClassifierTest, TableGrowthIsBounded) {
  ClassifierConfiguration config;
  config.max_flows = 8;
  auto classifier = Make(config);

  for (int i = 0; i < 64; ++i) {
    const auto packet = MakeV4(V4(10, 8, 0, 2), V4(93, 184, 216, 34),
        static_cast<std::uint16_t>(1000 + i), 443);
    // Still classified correctly, just not remembered past the cap.
    EXPECT_EQ(classifier->Classify(LeaseOf(packet)), RouteAction::fptn_l4);
  }
  EXPECT_LE(classifier->Counters().active_flows, 8u);
  EXPECT_GT(classifier->Counters().table_full_events, 0u);
}

}  // namespace
