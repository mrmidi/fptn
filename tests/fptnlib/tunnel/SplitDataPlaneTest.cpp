/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "fptn-protocol-lib/tunnel/split_data_plane.h"
#include "fptn-protocol-lib/tunnel/tunnel_engine.h"

#include "../flow/flow_test_support.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr std::uint16_t kAppPort = 50000;
constexpr std::uint32_t kClientIss = 0x40000001;

class AlwaysDirectPolicy final : public IRoutingPolicy {
 public:
  RouteAction Decide(const FlowMetadata&, std::string_view) const override {
    return RouteAction::direct;
  }
};

void PushBe16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void PushBe16(std::vector<std::uint8_t>& out, std::size_t at,
    std::uint16_t value) {
  out[at] = static_cast<std::uint8_t>(value >> 8);
  out[at + 1] = static_cast<std::uint8_t>(value & 0xFFu);
}

void PushName(std::vector<std::uint8_t>& out, const std::string& domain) {
  std::size_t start = 0;
  while (start <= domain.size()) {
    const std::size_t dot = domain.find('.', start);
    const std::size_t end = dot == std::string::npos ? domain.size() : dot;
    out.push_back(static_cast<std::uint8_t>(end - start));
    out.insert(out.end(), domain.begin() + static_cast<long>(start),
        domain.begin() + static_cast<long>(end));
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  out.push_back(0);
}

// A DNS response carrying one A record, as an IPv4/UDP packet.
std::vector<std::uint8_t> MakeDnsResponseBytes(const std::string& domain,
    std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  std::vector<std::uint8_t> dns;
  PushBe16(dns, 0x1234);
  PushBe16(dns, 0x8180);  // response, recursion available
  PushBe16(dns, 1);       // qdcount
  PushBe16(dns, 1);       // ancount
  PushBe16(dns, 0);
  PushBe16(dns, 0);
  PushName(dns, domain);
  PushBe16(dns, 1);
  PushBe16(dns, 1);
  dns.push_back(0xC0);  // answer NAME: pointer to the question
  dns.push_back(0x0C);
  PushBe16(dns, 1);  // TYPE A
  PushBe16(dns, 1);  // CLASS IN
  PushBe16(dns, 0);
  PushBe16(dns, 300);  // TTL
  PushBe16(dns, 4);    // RDLENGTH
  dns.insert(dns.end(), {a, b, c, d});

  const std::size_t udp_length = 8 + dns.size();
  std::vector<std::uint8_t> packet(20, 0);
  packet[0] = 0x45;
  PushBe16(packet, 2, static_cast<std::uint16_t>(20 + udp_length));
  packet[8] = 64;
  packet[9] = 17;
  packet[12] = 10; packet[13] = 8; packet[14] = 0; packet[15] = 1;
  packet[16] = 10; packet[17] = 8; packet[18] = 0; packet[19] = 2;
  PushBe16(packet, 53);
  PushBe16(packet, 40000);
  PushBe16(packet, static_cast<std::uint16_t>(udp_length));
  PushBe16(packet, 0);
  packet.insert(packet.end(), dns.begin(), dns.end());
  return packet;
}

template <typename Predicate>
bool PollUntil(Predicate predicate,
    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return predicate();
}

class SplitDataPlaneTest : public ::testing::Test {
 protected:
  void Build(const TunnelRoutingConfiguration& routing,
      std::shared_ptr<const IRoutingPolicy> routing_policy = nullptr) {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::split;
    config.l3.server_ip = "127.0.0.1";
    config.l3.server_port = 443;
    config.l3.tun_ipv4 = kAppIp;
    config.l3.tun_ipv6 = "fd00::1";
    config.l3.sni = "split.test.example";
    config.l3.access_token = "test-token";
    config.flow.tun_ipv4 = kAppIp;
    config.flow.tun_ipv6 = "fd00::1";
    config.routing = routing;

    callbacks_.on_owned_packet_batch = [this](OwnedPacketBatchView batch) {
      collector_.Append(batch);
    };
    // No transport is connected in these tests, so fptn-verdict packets are
    // refused rather than sent. That is exactly what exercises the rollback.
    plane_ = std::make_unique<SplitDataPlane>(config, callbacks_,
        [this] { return transport_; }, std::move(routing_policy));
    ASSERT_TRUE(plane_->Start().has_value());
  }

  void TearDown() override {
    if (plane_) {
      plane_->Stop();
      plane_.reset();
    }
    // Every lease handed to the plane must have been released exactly once,
    // whichever half of the fan-out took it.
    EXPECT_EQ(leases_.LiveLeases(), 0u);
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    PacketLease lease = leases_.Make(packet, 4);
    const PacketLease batch[] = {lease};
    const auto result = plane_->InputPackets(batch);
    if (result != PacketInputResult::accepted) {
      ReleasePacketLease(lease);
    }
    return result;
  }

  PacketInputResult InjectBatch(
      const std::vector<std::vector<std::uint8_t>>& packets) {
    std::vector<PacketLease> batch;
    batch.reserve(packets.size());
    for (const auto& packet : packets) {
      batch.push_back(leases_.Make(packet, 4));
    }
    const auto result = plane_->InputPackets(batch);
    if (result != PacketInputResult::accepted) {
      for (auto& lease : batch) {
        ReleasePacketLease(lease);
      }
    }
    return result;
  }

  fptn::protocol::https::WebsocketClientSPtr transport_;
  TunnelCallbacks callbacks_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<SplitDataPlane> plane_;
};

TEST_F(SplitDataPlaneTest, UnroutableTransportRejectsTheWholeBatch) {
  Build({});
  // Two fptn-verdict packets: the transport is not connected, so nothing may
  // be consumed and the caller keeps both leases.
  const auto a = MakeTcpV4(
      kAppIp, "93.184.216.34", kAppPort, 443, kClientIss, 0, kFlagSyn);
  const auto b = MakeTcpV4(
      kAppIp, "93.184.216.35", kAppPort + 1, 443, kClientIss, 0, kFlagSyn);
  EXPECT_EQ(InjectBatch({a, b}), PacketInputResult::transport_stopped);
  EXPECT_EQ(leases_.LiveLeases(), 0u);
  EXPECT_GT(plane_->SplitStatistics().rollbacks, 0u);
}

// The whole point of the split: a `drop` verdict never reaches either plane,
// and its lease is still released exactly once.
TEST_F(SplitDataPlaneTest, DropVerdictConsumesTheLeaseAndReachesNoPlane) {
  TunnelRoutingConfiguration routing;
  routing.drop_domains = {"ads.example"};
  Build(routing);

  // Attribute 203.0.113.7 to ads.example by feeding the observer a response
  // through the transport tap.
  const auto dns_bytes = MakeDnsResponseBytes("ads.example", 203, 0, 113, 7);
  fptn::common::network::BatchIPPacketPtr batch;
  batch.push_back(fptn::common::network::IPPacket::Parse(
      dns_bytes.data(), dns_bytes.size()));
  plane_->DnsObserverForTesting().Observe(batch);

  const auto syn = MakeTcpV4(
      kAppIp, "203.0.113.7", kAppPort, 443, kClientIss, 0, kFlagSyn);
  EXPECT_EQ(Inject(syn), PacketInputResult::accepted);
  EXPECT_EQ(plane_->SplitStatistics().packets_dropped, 1u);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_stack, 0u);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_transport, 0u);
  // No SYN-ACK: the packet never entered lwIP.
  EXPECT_FALSE(collector_.WaitForCount(1, std::chrono::milliseconds(300)));
}

TEST_F(SplitDataPlaneTest, DirectVerdictReachesTheStackAndAnswers) {
  TunnelRoutingConfiguration routing;
  routing.direct_domains = {"2ip.ru"};
  Build(routing);

  const auto dns_bytes = MakeDnsResponseBytes("2ip.ru", 104, 21, 0, 1);
  fptn::common::network::BatchIPPacketPtr batch;
  batch.push_back(fptn::common::network::IPPacket::Parse(
      dns_bytes.data(), dns_bytes.size()));
  plane_->DnsObserverForTesting().Observe(batch);

  const auto syn = MakeTcpV4(
      kAppIp, "104.21.0.1", kAppPort, 443, kClientIss, 0, kFlagSyn);
  ASSERT_EQ(Inject(syn), PacketInputResult::accepted);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_stack, 1u);

  // lwIP terminated it and replied.
  ASSERT_TRUE(collector_.WaitFor(1,
      [](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
            return true;
          }
        }
        return false;
      },
      std::chrono::seconds(5)));
}

TEST_F(SplitDataPlaneTest, InjectedPolicyOverridesStaticDomainLists) {
  TunnelRoutingConfiguration routing;
  routing.reject_domains = {"would-have-been-rejected.example"};
  Build(routing, std::make_shared<AlwaysDirectPolicy>());

  const auto syn = MakeTcpV4(
      kAppIp, "203.0.113.7", kAppPort, 443, kClientIss, 0, kFlagSyn);
  ASSERT_EQ(Inject(syn), PacketInputResult::accepted);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_stack, 1u);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_transport, 0u);
}

// A mixed batch is the case the ownership contract is about.
TEST_F(SplitDataPlaneTest, MixedBatchRollsBackWithoutConsumingAnyLease) {
  TunnelRoutingConfiguration routing;
  routing.direct_domains = {"2ip.ru"};
  Build(routing);

  const auto dns_bytes = MakeDnsResponseBytes("2ip.ru", 104, 21, 0, 1);
  fptn::common::network::BatchIPPacketPtr batch;
  batch.push_back(fptn::common::network::IPPacket::Parse(
      dns_bytes.data(), dns_bytes.size()));
  plane_->DnsObserverForTesting().Observe(batch);

  const auto direct = MakeTcpV4(
      kAppIp, "104.21.0.1", kAppPort, 443, kClientIss, 0, kFlagSyn);
  const auto tunnelled = MakeTcpV4(
      kAppIp, "93.184.216.34", kAppPort + 1, 443, kClientIss, 0, kFlagSyn);

  // The transport half cannot be reserved (not connected), so the direct half
  // must not be consumed either: all-or-nothing.
  EXPECT_EQ(
      InjectBatch({direct, tunnelled}), PacketInputResult::transport_stopped);
  EXPECT_EQ(leases_.LiveLeases(), 0u);
  EXPECT_EQ(plane_->SplitStatistics().packets_to_stack, 0u);
  // Nothing entered lwIP, so no SYN-ACK.
  EXPECT_FALSE(collector_.WaitForCount(1, std::chrono::milliseconds(300)));
}

TEST_F(SplitDataPlaneTest, StoppedPlaneRejectsInput) {
  Build({});
  plane_->Stop();
  const auto syn = MakeTcpV4(
      kAppIp, "93.184.216.34", kAppPort, 443, kClientIss, 0, kFlagSyn);
  const PacketLease lease{syn.data(),
      static_cast<std::uint32_t>(syn.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ(plane_->InputPackets(batch), PacketInputResult::transport_stopped);
  plane_.reset();
}

TEST(TableBackedRouterTest, UnknownFlowFailsClosed) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  DnsObserver observer;
  FlowClassifier classifier(ClassifierConfiguration{}, policy, observer);
  TableBackedRouter router(classifier);

  FlowMetadata metadata;
  metadata.protocol = TransportProtocol::tcp;
  metadata.source.address = boost::asio::ip::make_address("10.8.0.2");
  metadata.source.port = 50000;
  metadata.destination.address =
      boost::asio::ip::make_address("93.184.216.34");
  metadata.destination.port = 443;

  // A flow the classifier never saw must never be routed direct: that would
  // leak the user's real IP.
  EXPECT_EQ(router.Match(metadata), RouteAction::reject);
  EXPECT_EQ(router.unknown_flows(), 1u);
}

TEST(TableBackedRouterTest, ReadsBackTheRecordedVerdict) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);

  class FixedAttribution final : public IDomainAttribution {
   public:
    std::string LookupDomain(const IpKey&) const override { return "2ip.ru"; }
  } attribution;

  FlowClassifier classifier(ClassifierConfiguration{}, policy, attribution);
  TableBackedRouter router(classifier);

  const auto syn = MakeTcpV4(
      kAppIp, "104.21.0.1", kAppPort, 443, kClientIss, 0, kFlagSyn);
  const PacketLease lease{syn.data(),
      static_cast<std::uint32_t>(syn.size()), 4, nullptr, nullptr};
  ASSERT_EQ(classifier.Classify(lease), RouteAction::direct);

  FlowMetadata metadata;
  metadata.protocol = TransportProtocol::tcp;
  metadata.source.address = boost::asio::ip::make_address(kAppIp);
  metadata.source.port = kAppPort;
  metadata.destination.address = boost::asio::ip::make_address("104.21.0.1");
  metadata.destination.port = 443;

  EXPECT_EQ(router.Match(metadata), RouteAction::direct);
  EXPECT_EQ(router.unknown_flows(), 0u);
}

}  // namespace
