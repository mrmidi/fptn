#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fptn-protocol-lib/flow/lwip_stack.h"
#include "fptn-protocol-lib/tunnel/tunnel_engine.h"

#include "fake_outbound.h"
#include "flow_test_support.h"
#include "posix_udp_echo_server.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr const char* kDstIp = "127.0.0.1";
constexpr const char* kAppIp6 = "fd00::2";
constexpr const char* kDstIp6 = "::1";
constexpr std::uint16_t kAppPort = 50000;

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

struct UdpOutputDatagram {
  std::uint8_t ip_version = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::vector<std::uint8_t> payload;
};

std::vector<UdpOutputDatagram> CollectUdpOutputs(
    const std::vector<OwnedPacket>& packets) {
  std::vector<UdpOutputDatagram> datagrams;
  for (const auto& packet : packets) {
    UdpOutputDatagram datagram;
    datagram.ip_version = packet.ip_version;
    const auto& data = packet.data;
    std::size_t udp_offset = 0;
    std::size_t total = data.size();
    if (packet.ip_version == 4) {
      if (data.size() < 28 || data[9] != 17) {
        continue;
      }
      udp_offset = 20;
      total = static_cast<std::size_t>(data[2]) << 8 | data[3];
      if (total > data.size()) {
        continue;
      }
    } else if (packet.ip_version == 6) {
      if (data.size() < 48 || data[6] != 17) {
        continue;
      }
      udp_offset = 40;
      const std::size_t payload_len =
          static_cast<std::size_t>(data[4]) << 8 | data[5];
      total = 40 + payload_len;
      if (total > data.size()) {
        continue;
      }
    } else {
      continue;
    }
    datagram.src_port = ReadPort(data, udp_offset);
    datagram.dst_port = ReadPort(data, udp_offset + 2);
    const std::size_t udp_len =
        static_cast<std::size_t>(data[udp_offset + 4]) << 8 |
        data[udp_offset + 5];
    const std::size_t payload_begin = udp_offset + 8;
    const std::size_t payload_end =
        std::min(udp_offset + udp_len, total);
    if (payload_end > payload_begin) {
      datagram.payload.assign(
          data.begin() + payload_begin, data.begin() + payload_end);
    }
    datagrams.push_back(std::move(datagram));
  }
  return datagrams;
}

class LwipUdpEngineTest : public ::testing::Test {
 protected:
  void SetUp() override {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.l3.tun_ipv4 = kAppIp;
    config.l3.tun_ipv6 = "fd00::1";
    callbacks_.on_owned_packet_batch = [this](OwnedPacketBatch batch) {
      collector_.Append(std::move(batch));
    };
    auto result = TunnelEngine::Create(config, callbacks_);
    ASSERT_TRUE(result.has_value());
    engine_ = std::move(*result);
    ASSERT_TRUE(engine_->Start().has_value());
  }

  void TearDown() override {
    if (engine_) {
      engine_->Stop();
      engine_.reset();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet,
      std::uint8_t ip_version) {
    const PacketLease lease{packet.data(),
        static_cast<std::uint32_t>(packet.size()), ip_version, nullptr,
        nullptr};
    const PacketLease batch[] = {lease};
    return engine_->InputPackets(batch);
  }

  TunnelCallbacks callbacks_;
  OutputCollector collector_;
  std::unique_ptr<TunnelEngine> engine_;
};

TEST_F(LwipUdpEngineTest, EchoRoundTripV4) {
  PosixUdpEchoServer server;
  ASSERT_TRUE(server.Start());

  const std::string message = "ping-fptn";
  const std::vector<std::uint8_t> payload(message.begin(), message.end());
  Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort, server.port(), payload), 4);

  ASSERT_TRUE(PollUntil([this, &payload, &server] {
    const auto datagrams = CollectUdpOutputs(collector_.Snapshot());
    for (const auto& datagram : datagrams) {
      if (datagram.ip_version == 4 &&
          datagram.src_port == server.port() &&
          datagram.dst_port == kAppPort && datagram.payload == payload) {
        return true;
      }
    }
    return false;
  },
      std::chrono::seconds(10)));

  server.Stop();
}

TEST_F(LwipUdpEngineTest, EchoRoundTripV6) {
  PosixUdpEchoServer server(true);
  ASSERT_TRUE(server.Start());

  const std::string message = "v6-ping";
  const std::vector<std::uint8_t> payload(message.begin(), message.end());
  Inject(MakeUdpV6(kAppIp6, kDstIp6, kAppPort, server.port(), payload), 6);

  ASSERT_TRUE(PollUntil([this, &payload, &server] {
    const auto datagrams = CollectUdpOutputs(collector_.Snapshot());
    for (const auto& datagram : datagrams) {
      if (datagram.ip_version == 6 &&
          datagram.src_port == server.port() &&
          datagram.dst_port == kAppPort && datagram.payload == payload) {
        return true;
      }
    }
    return false;
  },
      std::chrono::seconds(10)));

  server.Stop();
}

TEST_F(LwipUdpEngineTest, MultipleDatagramsShareAssociation) {
  PosixUdpEchoServer server;
  ASSERT_TRUE(server.Start());

  const std::vector<std::string> messages = {"aaa", "bbb", "ccc"};
  for (const auto& message : messages) {
    const std::vector<std::uint8_t> payload(message.begin(), message.end());
    Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort, server.port(), payload), 4);
  }

  ASSERT_TRUE(server.WaitForDatagrams(3, std::chrono::seconds(10)));
  ASSERT_TRUE(PollUntil([this, &messages, &server] {
    const auto datagrams = CollectUdpOutputs(collector_.Snapshot());
    for (const auto& message : messages) {
      const std::vector<std::uint8_t> payload(message.begin(), message.end());
      const bool found = std::any_of(datagrams.begin(), datagrams.end(),
          [&](const UdpOutputDatagram& datagram) {
            return datagram.ip_version == 4 &&
                   datagram.src_port == server.port() &&
                   datagram.dst_port == kAppPort &&
                   datagram.payload == payload;
          });
      if (!found) {
        return false;
      }
    }
    return true;
  },
      std::chrono::seconds(10)));

  server.Stop();
}

TEST_F(LwipUdpEngineTest, StopRejectsFurtherInput) {
  PosixUdpEchoServer server;
  ASSERT_TRUE(server.Start());

  const std::vector<std::uint8_t> payload = {'h', 'i'};
  Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort, server.port(), payload), 4);
  ASSERT_TRUE(server.WaitForDatagrams(1, std::chrono::seconds(10)));

  engine_->Stop();
  engine_.reset();

  auto config_result = [&] {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.l3.tun_ipv4 = kAppIp;
    return TunnelEngine::Create(config, callbacks_);
  }();
  ASSERT_TRUE(config_result.has_value());

  const auto packet =
      MakeUdpV4(kAppIp, kDstIp, kAppPort, server.port(), payload);
  const PacketLease lease{packet.data(),
      static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ((*config_result)->InputPackets(batch),
      PacketInputResult::transport_stopped);

  server.Stop();
}

class LwipUdpStackTest : public ::testing::Test {
 protected:
  void SetUp() override {
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        stack_config_, sink_, router_, tcp_outbound_, udp_outbound_,
        [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
    ASSERT_TRUE(stack_->Start().has_value());
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
      stack_.reset();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    const PacketLease lease{packet.data(),
        static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
    const PacketLease batch[] = {lease};
    return stack_->InputPackets(batch);
  }

  StackConfiguration stack_config_;
  TestRuntime runtime_;
  RecordingSink sink_;
  TestRouter router_;
  FakeTcpOutbound tcp_outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  std::unique_ptr<LwipStack> stack_;
};

TEST_F(LwipUdpStackTest, AssociationDeliversMetadataAndPayload) {
  const std::vector<std::uint8_t> payload = {'d', 'n', 's'};
  Inject(MakeUdpV4(kAppIp, "93.184.216.34", kAppPort, 53, payload));

  ASSERT_TRUE(PollUntil([this] { return !udp_outbound_.Opened().empty(); }));
  const FlowMetadata& metadata = udp_outbound_.Opened().front();
  EXPECT_EQ(metadata.protocol, TransportProtocol::udp);
  EXPECT_EQ(metadata.source.address.to_string(), kAppIp);
  EXPECT_EQ(metadata.source.port, kAppPort);
  EXPECT_EQ(metadata.destination.address.to_string(), "93.184.216.34");
  EXPECT_EQ(metadata.destination.port, 53);

  ASSERT_TRUE(PollUntil([this] { return !udp_outbound_.Sent().empty(); }));
  EXPECT_EQ(udp_outbound_.Sent().front().bytes, payload);

  ASSERT_EQ(sink_.UdpDatagrams().size(), 1u);
  EXPECT_EQ(sink_.UdpDatagrams().front().payload, payload);
}

TEST_F(LwipUdpStackTest, ReplyFromOutboundReachesApp) {
  const std::vector<std::uint8_t> payload = {'q'};
  Inject(MakeUdpV4(kAppIp, "93.184.216.34", kAppPort, 53, payload));

  ASSERT_TRUE(PollUntil([this] { return !udp_outbound_.Opened().empty(); }));
  const FlowId flow = udp_outbound_.Opened().front().id;

  const std::vector<std::uint8_t> reply = {'r', 'e', 'p', 'l', 'y'};
  OwnedBuffer reply_buffer = reply;
  udp_outbound_.LastSink()->OnUdpDatagramReceived(flow,
      std::move(reply_buffer));

  ASSERT_TRUE(PollUntil([this] {
    const auto datagrams = CollectUdpOutputs(collector_.Snapshot());
    for (const auto& datagram : datagrams) {
      if (datagram.ip_version == 4 && datagram.src_port == 53 &&
          datagram.dst_port == kAppPort &&
          datagram.payload == std::vector<std::uint8_t>({'r', 'e', 'p', 'l',
              'y'})) {
        return true;
      }
    }
    return false;
  }));
}

TEST_F(LwipUdpStackTest, IdleAssociationExpires) {
  stack_->Stop();
  stack_config_.udp_idle_timeout = std::chrono::milliseconds(150);
  stack_ = std::make_unique<LwipStack>(runtime_.Executor(), stack_config_,
      sink_, router_, tcp_outbound_, udp_outbound_,
      [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
  ASSERT_TRUE(stack_->Start().has_value());

  const std::vector<std::uint8_t> payload = {'x'};
  Inject(MakeUdpV4(kAppIp, "93.184.216.34", kAppPort, 53, payload));

  ASSERT_TRUE(PollUntil([this] { return !udp_outbound_.Opened().empty(); }));
  const FlowId flow = udp_outbound_.Opened().front().id;
  EXPECT_EQ(stack_->counters().active_udp_flows.load(), 1u);

  ASSERT_TRUE(PollUntil([this] {
    return stack_->counters().active_udp_flows.load() == 0;
  },
      std::chrono::seconds(5)));
  ASSERT_TRUE(PollUntil([this, flow] {
    const auto& reset = udp_outbound_.Reset();
    return std::find(reset.begin(), reset.end(), flow) != reset.end();
  }));
  EXPECT_EQ(stack_->counters().peak_udp_flows.load(), 1u);
}

TEST_F(LwipUdpStackTest, AssociationLimitDropsNewTuples) {
  stack_->Stop();
  stack_config_.max_udp_associations = 1;
  stack_ = std::make_unique<LwipStack>(runtime_.Executor(), stack_config_,
      sink_, router_, tcp_outbound_, udp_outbound_,
      [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
  ASSERT_TRUE(stack_->Start().has_value());

  const std::vector<std::uint8_t> payload = {'a'};
  Inject(MakeUdpV4(kAppIp, "93.184.216.34", kAppPort, 53, payload));
  ASSERT_TRUE(PollUntil([this] { return !udp_outbound_.Opened().empty(); }));

  Inject(MakeUdpV4(kAppIp, "93.184.216.34", kAppPort + 1, 53, payload));
  ASSERT_TRUE(PollUntil([this] {
    return stack_->counters().udp_drops.load() >= 1;
  }));
  EXPECT_EQ(udp_outbound_.Opened().size(), 1u);
  EXPECT_EQ(stack_->counters().active_udp_flows.load(), 1u);
}

}  // namespace
