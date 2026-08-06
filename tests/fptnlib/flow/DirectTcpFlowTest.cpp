#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fptn-protocol-lib/tunnel/tunnel_engine.h"

#include "flow_test_support.h"
#include "posix_echo_server.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr const char* kDstIp = "127.0.0.1";
constexpr std::uint16_t kAppPort = 50000;
constexpr std::uint32_t kClientIss = 0x20000001;

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

class DirectTcpFlowTest : public ::testing::Test {
 protected:
  void SetUp() override {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.flow.tun_ipv4 = kAppIp;
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

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    const PacketLease lease{packet.data(),
        static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
    const PacketLease batch[] = {lease};
    return engine_->InputPackets(batch);
  }

  bool Handshake(std::uint16_t dst_port) {
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, kClientIss, 0,
        kFlagSyn));
    const bool got_synack = collector_.WaitFor(1,
        [this](const std::vector<OwnedPacket>& packets) {
          for (const auto& packet : packets) {
            if (packet.ip_version == 4 && packet.data.size() >= 40 &&
                (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
              server_seq_ = ReadSeq(packet.data, 20) + 1;
              server_seq_initial_ = server_seq_;
              return true;
            }
          }
          return false;
        });
    if (!got_synack) {
      return false;
    }
    client_seq_ = kClientIss + 1;
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_,
        server_seq_, kFlagAck));
    return true;
  }

  void SendData(std::uint16_t dst_port,
      const std::vector<std::uint8_t>& payload) {
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_,
        server_seq_, kFlagAck | 0x08, payload));
    client_seq_ += static_cast<std::uint32_t>(payload.size());
  }

  std::vector<std::uint8_t> AppPayload(std::uint16_t dst_port) {
    std::vector<std::uint8_t> payload;
    AppendServerPayload(dst_port, payload);
    return payload;
  }

  void AppendServerPayload(std::uint16_t dst_port,
      std::vector<std::uint8_t>& payload) {
    for (const auto& packet : collector_.Snapshot()) {
      if (packet.ip_version != 4 || packet.data.size() <= 40) {
        continue;
      }
      if (ReadPort(packet.data, 20) != dst_port ||
          ReadPort(packet.data, 22) != kAppPort) {
        continue;
      }
      const std::uint8_t* ip = packet.data.data();
      const std::size_t header_len = (ip[0] & 0x0Fu) * 4;
      const std::size_t tcp_offset = header_len;
      const std::size_t tcp_header_len =
          ((packet.data[tcp_offset + 12] & 0xF0u) >> 4) * 4;
      const std::size_t total =
          (static_cast<std::size_t>(ip[2]) << 8 | ip[3]);
      if (total > packet.data.size()) {
        continue;
      }
      const std::size_t payload_begin = tcp_offset + tcp_header_len;
      if (payload_begin < total) {
        payload.insert(payload.end(), packet.data.begin() + payload_begin,
            packet.data.begin() + total);
      }
    }
  }

  // Models the device TCP stack: ACK data delivered by the stack so its
  // congestion window and send buffer keep moving.
  void AckServerData(std::uint16_t dst_port) {
    std::vector<std::uint8_t> received;
    AppendServerPayload(dst_port, received);
    if (received.size() <= server_acked_bytes_) {
      return;
    }
    const std::uint32_t ack = server_seq_initial_ +
        static_cast<std::uint32_t>(received.size());
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_, ack,
        kFlagAck));
    server_acked_bytes_ = received.size();
    server_seq_ = ack;
  }

  TunnelCallbacks callbacks_;
  OutputCollector collector_;
  std::unique_ptr<TunnelEngine> engine_;
  std::uint32_t client_seq_ = 0;
  std::uint32_t server_seq_ = 0;
  std::uint32_t server_seq_initial_ = 0;
  std::size_t server_acked_bytes_ = 0;
};

TEST_F(DirectTcpFlowTest, EchoRoundTrip) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());

  ASSERT_TRUE(Handshake(server.port()));
  ASSERT_TRUE(server.WaitForAccepted(std::chrono::seconds(5)));

  const std::string message = "hello, fptn flow proxy";
  const std::vector<std::uint8_t> payload(message.begin(), message.end());
  SendData(server.port(), payload);

  ASSERT_TRUE(PollUntil([this, &payload, &server] {
    return AppPayload(server.port()) == payload;
  },
      std::chrono::seconds(10)));

  server.Stop();
}

TEST_F(DirectTcpFlowTest, LargeTransferEchoesAllBytes) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());

  ASSERT_TRUE(Handshake(server.port()));
  ASSERT_TRUE(server.WaitForAccepted(std::chrono::seconds(5)));

  std::vector<std::uint8_t> expected;
  for (int segment = 0; segment < 24; ++segment) {
    std::vector<std::uint8_t> chunk(1000,
        static_cast<std::uint8_t>('A' + (segment % 26)));
    expected.insert(expected.end(), chunk.begin(), chunk.end());
    SendData(server.port(), chunk);
  }

  ASSERT_TRUE(PollUntil([this, &expected, &server] {
    AckServerData(server.port());
    return AppPayload(server.port()) == expected;
  },
      std::chrono::seconds(20)));

  server.Stop();
}

TEST_F(DirectTcpFlowTest, RefusedConnectResetsAppFlow) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());
  const std::uint16_t closed_port = server.port();
  server.Stop();

  ASSERT_TRUE(Handshake(closed_port));

  ASSERT_TRUE(collector_.WaitFor(2,
      [](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagRst) != 0) {
            return true;
          }
        }
        return false;
      },
      std::chrono::seconds(10)));
}

TEST_F(DirectTcpFlowTest, PeerCloseDeliversFinToApp) {
  PosixEchoServer server(PosixEchoServer::Mode::close_after_echo_bytes, 5);
  ASSERT_TRUE(server.Start());

  ASSERT_TRUE(Handshake(server.port()));
  ASSERT_TRUE(server.WaitForAccepted(std::chrono::seconds(5)));

  const std::vector<std::uint8_t> payload = {'c', 'l', 'o', 's', 'e'};
  SendData(server.port(), payload);

  ASSERT_TRUE(collector_.WaitFor(2,
      [&server](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadPort(packet.data, 20) == server.port() &&
              (ReadFlags(packet.data, 20) & kFlagFin) != 0) {
            return true;
          }
        }
        return false;
      },
      std::chrono::seconds(10)));

  server.Stop();
}

TEST_F(DirectTcpFlowTest, StopDrainsActiveOutboundFlows) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());

  ASSERT_TRUE(Handshake(server.port()));
  ASSERT_TRUE(server.WaitForAccepted(std::chrono::seconds(5)));

  engine_->Stop();
  engine_.reset();

  const std::vector<std::uint8_t> payload = {'x'};
  const auto packet = MakeTcpV4(kAppIp, kDstIp, kAppPort, server.port(),
      kClientIss + 1, server_seq_, kFlagAck, payload);
  const PacketLease lease{packet.data(),
      static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};

  auto config_result = [&] {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.flow.tun_ipv4 = kAppIp;
    return TunnelEngine::Create(config, callbacks_);
  }();
  ASSERT_TRUE(config_result.has_value());
  EXPECT_EQ((*config_result)->InputPackets(batch),
      PacketInputResult::transport_stopped);

  server.Stop();
}

}  // namespace
