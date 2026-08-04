#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include "fake_outbound.h"
#include "flow_test_support.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr const char* kDstIp = "93.184.216.34";
constexpr std::uint16_t kAppPort = 50000;
constexpr std::uint16_t kDstPort = 443;
constexpr std::uint32_t kClientIss = 0x11223344;

template <typename Predicate>
bool PollUntil(Predicate predicate,
    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return predicate();
}

class LwipTcpTest : public ::testing::Test {
 protected:
  void SetUp() override {
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        StackConfiguration{}, sink_, router_, outbound_, udp_outbound_,
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

  const OwnedPacket* FindPacket(std::uint8_t required_flags,
      std::uint8_t prohibited_flags = 0) {
    packets_ = collector_.Snapshot();
    for (const auto& packet : packets_) {
      if (packet.ip_version != 4 || packet.data.size() < 40) {
        continue;
      }
      const std::uint8_t flags = ReadFlags(packet.data, 20);
      if ((flags & required_flags) == required_flags &&
          (flags & prohibited_flags) == 0) {
        return &packet;
      }
    }
    return nullptr;
  }

  bool DoHandshake() {
    Inject(MakeTcpV4(
        kAppIp, kDstIp, kAppPort, kDstPort, kClientIss, 0, kFlagSyn));

    bool got_synack = collector_.WaitFor(1,
        [this](const std::vector<OwnedPacket>& packets) {
          for (const auto& packet : packets) {
            if (packet.ip_version == 4 && packet.data.size() >= 40 &&
                (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
              server_seq_ = ReadSeq(packet.data, 20) + 1;
              return true;
            }
          }
          return false;
        });
    if (!got_synack) {
      return false;
    }

    client_seq_ = kClientIss + 1;
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
        server_seq_, kFlagAck));

    return PollUntil([this] { return !outbound_.Opened().empty(); });
  }

  FlowId OpenedFlow() const {
    EXPECT_FALSE(outbound_.Opened().empty());
    return outbound_.Opened().front().metadata.id;
  }

  ITcpOutboundSink* OutboundSink() {
    EXPECT_FALSE(outbound_.Opened().empty());
    return outbound_.Opened().front().sink;
  }

  TestRuntime runtime_;
  RecordingSink sink_;
  TestRouter router_;
  FakeTcpOutbound outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  std::unique_ptr<LwipStack> stack_;
  std::vector<OwnedPacket> packets_;
  std::uint32_t client_seq_ = 0;
  std::uint32_t server_seq_ = 0;
};

TEST_F(LwipTcpTest, HandshakeOpensFlowAndRoutesDirect) {
  ASSERT_TRUE(DoHandshake());

  ASSERT_EQ(sink_.Opened().size(), 1u);
  const FlowMetadata& metadata = sink_.Opened().front();
  EXPECT_EQ(metadata.protocol, TransportProtocol::tcp);
  EXPECT_EQ(metadata.source.address.to_string(), kAppIp);
  EXPECT_EQ(metadata.source.port, kAppPort);
  EXPECT_EQ(metadata.destination.address.to_string(), kDstIp);
  EXPECT_EQ(metadata.destination.port, kDstPort);

  ASSERT_EQ(outbound_.Opened().size(), 1u);
  EXPECT_EQ(outbound_.Opened().front().metadata.id, metadata.id);
  EXPECT_EQ(stack_->ActiveTcpFlows(), 1u);
}

TEST_F(LwipTcpTest, AppDataDeliveredToOutboundAndAcked) {
  ASSERT_TRUE(DoHandshake());

  const std::string payload = "hello";
  const std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagAck, bytes));

  ASSERT_TRUE(PollUntil([this, &payload] {
    return !outbound_.Written().empty() &&
           outbound_.Written().front().flow == OpenedFlow() &&
           std::string(outbound_.Written().front().bytes.begin(),
               outbound_.Written().front().bytes.end()) == payload;
  }));

  const std::uint32_t expected_ack = client_seq_ +
      static_cast<std::uint32_t>(payload.size());
  ASSERT_TRUE(collector_.WaitFor(2,
      [expected_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadFlags(packet.data, 20) == kFlagAck &&
              ReadAck(packet.data, 20) == expected_ack) {
            return true;
          }
        }
        return false;
      }));
}

TEST_F(LwipTcpTest, OutboundDataReachesApp) {
  ASSERT_TRUE(DoHandshake());

  const std::string payload = "world";
  const FlowId flow = OpenedFlow();
  OwnedBuffer data(payload.begin(), payload.end());
  EXPECT_TRUE(OutboundSink()->OnOutboundData(flow, data));
  EXPECT_TRUE(data.empty());

  ASSERT_TRUE(collector_.WaitFor(2,
      [&payload](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 &&
              packet.data.size() == 40 + payload.size() &&
              std::memcmp(packet.data.data() + 40, payload.data(),
                  payload.size()) == 0) {
            return true;
          }
        }
        return false;
      }));

  const auto output = collector_.Snapshot();
  const OwnedPacket* data_packet = nullptr;
  for (const auto& packet : output) {
    if (packet.data.size() == 40 + payload.size()) {
      data_packet = &packet;
      break;
    }
  }
  ASSERT_NE(data_packet, nullptr);
  EXPECT_EQ(ReadSeq(data_packet->data, 20), server_seq_);
  EXPECT_EQ(ReadAck(data_packet->data, 20), client_seq_);
  EXPECT_EQ(ReadPort(data_packet->data, 20), kDstPort);
  EXPECT_EQ(ReadPort(data_packet->data, 22), kAppPort);
}

TEST_F(LwipTcpTest, BackpressureHoldsDataUntilOutboundAdmits) {
  ASSERT_TRUE(DoHandshake());
  outbound_.SetRejectWrites(true);

  const std::string payload = "stall";
  const std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagAck, bytes));

  EXPECT_FALSE(PollUntil([this] { return !outbound_.Written().empty(); },
      std::chrono::milliseconds(300)));
  EXPECT_GE(stack_->counters().tcp_backpressure_events.load(), 1u);

  outbound_.SetRejectWrites(false);
  OutboundSink()->OnOutboundWritable(OpenedFlow());

  ASSERT_TRUE(PollUntil([this, &payload] {
    if (outbound_.Written().empty()) {
      return false;
    }
    const auto& written = outbound_.Written().front();
    return std::string(written.bytes.begin(), written.bytes.end()) == payload;
  }));

  const std::uint32_t data_ack = client_seq_ +
      static_cast<std::uint32_t>(payload.size());
  ASSERT_TRUE(collector_.WaitFor(2,
      [data_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadAck(packet.data, 20) == data_ack) {
            return true;
          }
        }
        return false;
      }));
}

TEST_F(LwipTcpTest, AppFinPropagatesAndFlowCloses) {
  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();

  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagFin | kFlagAck));

  ASSERT_TRUE(PollUntil([this, flow] {
    const auto& finished = outbound_.Finished();
    return std::find(finished.begin(), finished.end(), flow) !=
        finished.end();
  }));

  const std::uint32_t fin_ack = client_seq_ + 1;
  ASSERT_TRUE(collector_.WaitFor(2,
      [fin_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadAck(packet.data, 20) == fin_ack &&
              (ReadFlags(packet.data, 20) & kFlagRst) == 0) {
            return true;
          }
        }
        return false;
      }));

  OutboundSink()->OnOutboundFinished(flow);

  ASSERT_TRUE(collector_.WaitFor(3,
      [fin_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagFin) != 0 &&
              ReadAck(packet.data, 20) == fin_ack) {
            return true;
          }
        }
        return false;
      }));

  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
}

TEST_F(LwipTcpTest, OutboundResetProducesRstToApp) {
  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();
  ASSERT_EQ(stack_->ActiveTcpFlows(), 1u);

  OutboundSink()->OnOutboundReset(flow, FlowError::reset);

  ASSERT_TRUE(collector_.WaitFor(2,
      [](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagRst) != 0) {
            return true;
          }
        }
        return false;
      }));
  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
  EXPECT_GE(stack_->counters().tcp_resets.load(), 1u);
}

TEST_F(LwipTcpTest, TeardownAbortsActiveFlows) {
  ASSERT_TRUE(DoHandshake());
  ASSERT_EQ(stack_->ActiveTcpFlows(), 1u);

  stack_->Stop();
  EXPECT_EQ(stack_->ActiveTcpFlows(), 0u);

  const auto syn = MakeTcpV4(
      kAppIp, kDstIp, kAppPort, kDstPort, kClientIss, 0, kFlagSyn);
  const PacketLease lease{syn.data(),
      static_cast<std::uint32_t>(syn.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ(stack_->InputPackets(batch), PacketInputResult::transport_stopped);
}

}  // namespace
