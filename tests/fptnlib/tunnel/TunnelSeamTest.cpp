#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include "fptn-protocol-lib/tunnel/flow_types.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/tunnel_engine.h"

namespace {

using namespace fptn::tunnel;

TunnelConfiguration MakeL3Configuration() {
  TunnelConfiguration config;
  config.mode = DataPlaneMode::l3_tunnel;
  config.l3.server_ip = "127.0.0.1";
  config.l3.server_port = 1;
  config.l3.tun_ipv4 = "10.8.0.2";
  config.l3.tun_ipv6 = "fd00::1";
  config.flow.tun_ipv4 = "10.8.0.2";
  config.flow.tun_ipv6 = "fd00::1";
  config.l3.sni = "seam.test.example";
  config.l3.access_token = "test-token";
  config.l3.concurrency_hint = 1;
  return config;
}

TEST(FlowTypesTest, EndpointIsTransportNeutral) {
  const IpEndpoint v4{boost::asio::ip::make_address("93.184.216.34"), 443};
  const IpEndpoint v6{
      boost::asio::ip::make_address("2606:2800:220:1:248:1893:25c8:1946"),
      443};

  const FlowMetadata tcp_flow{
      1, TransportProtocol::tcp,
      IpEndpoint{boost::asio::ip::make_address("10.8.0.2"), 50000}, v4};
  const FlowMetadata udp_flow{
      2, TransportProtocol::udp,
      IpEndpoint{boost::asio::ip::make_address("10.8.0.2"), 50000}, v4};

  EXPECT_EQ(tcp_flow.destination.address, udp_flow.destination.address);
  EXPECT_EQ(tcp_flow.destination.port, udp_flow.destination.port);
  EXPECT_TRUE(v4.address.is_v4());
  EXPECT_TRUE(v6.address.is_v6());
  EXPECT_EQ(v6.port, 443);
}

TEST(FlowTypesTest, EndpointConvertsToTransportSpecificEndpoints) {
  const IpEndpoint endpoint{boost::asio::ip::make_address("203.0.113.7"),
      8443};

  const boost::asio::ip::tcp::endpoint tcp_endpoint{
      endpoint.address, endpoint.port};
  const boost::asio::ip::udp::endpoint udp_endpoint{
      endpoint.address, endpoint.port};

  EXPECT_EQ(tcp_endpoint.address(), endpoint.address);
  EXPECT_EQ(tcp_endpoint.port(), endpoint.port);
  EXPECT_EQ(udp_endpoint.address(), endpoint.address);
  EXPECT_EQ(udp_endpoint.port(), endpoint.port);
}

TEST(PacketTypesTest, ReleasePacketLeaseRunsOnceAndClears) {
  int released = 0;
  PacketLease lease;
  lease.owner = &released;
  lease.release = [](void* owner) noexcept {
    ++(*static_cast<int*>(owner));
  };

  ReleasePacketLease(lease);
  EXPECT_EQ(released, 1);
  EXPECT_EQ(lease.owner, nullptr);
  EXPECT_EQ(lease.release, nullptr);

  ReleasePacketLease(lease);
  EXPECT_EQ(released, 1);
}

TEST(PacketTypesTest, ReleasePacketBatchReleasesEveryLease) {
  int released = 0;
  const PacketLease batch[] = {
      PacketLease{nullptr, 0, 4, &released,
          [](void* owner) noexcept { ++(*static_cast<int*>(owner)); }},
      PacketLease{nullptr, 0, 6, &released,
          [](void* owner) noexcept { ++(*static_cast<int*>(owner)); }},
      PacketLease{},
  };

  ReleasePacketBatch(batch);
  EXPECT_EQ(released, 2);
}

TEST(TunnelEngineTest, CreateRejectsInvalidL3Configuration) {
  TunnelCallbacks callbacks;

  auto no_server = MakeL3Configuration();
  no_server.l3.server_ip.clear();
  auto result = TunnelEngine::Create(no_server, callbacks);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), TunnelError::invalid_configuration);

  auto bad_port = MakeL3Configuration();
  bad_port.l3.server_port = 0;
  result = TunnelEngine::Create(bad_port, callbacks);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), TunnelError::invalid_configuration);
}

TEST(TunnelEngineTest, CreateFlowProxyDependsOnLwipBuild) {
  TunnelCallbacks callbacks;
  auto config = MakeL3Configuration();
  config.mode = DataPlaneMode::flow_proxy;

  auto result = TunnelEngine::Create(config, callbacks);
#ifdef FPTN_HAS_LWIP
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ((*result)->mode(), DataPlaneMode::flow_proxy);
#else
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), TunnelError::unsupported_mode);
#endif

  config.mode = static_cast<DataPlaneMode>(99);
  result = TunnelEngine::Create(config, callbacks);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), TunnelError::unsupported_mode);
}

TEST(TunnelEngineTest, InputBeforeStartIsRejected) {
  TunnelCallbacks callbacks;
  auto result = TunnelEngine::Create(MakeL3Configuration(), callbacks);
  ASSERT_TRUE(result.has_value());
  auto& engine = *result;

  const std::uint8_t packet[] = {0x45, 0x00, 0x00, 0x14};
  const PacketLease batch[] = {PacketLease{packet, sizeof(packet), 4, nullptr,
      nullptr}};
  EXPECT_EQ(engine->InputPackets(batch), PacketInputResult::transport_stopped);
  EXPECT_EQ(engine->mode(), DataPlaneMode::l3_tunnel);
  EXPECT_FALSE(engine->IsStarted());
}

TEST(TunnelEngineTest, L3ConnectFailureProducesDisconnectAndCleanStop) {
  std::mutex mutex;
  std::condition_variable cv;
  int disconnect_count = 0;

  TunnelCallbacks callbacks;
  callbacks.on_disconnected = [&](bool, const std::string&) {
    {
      std::lock_guard lock(mutex);
      ++disconnect_count;
    }
    cv.notify_all();
  };

  auto result = TunnelEngine::Create(MakeL3Configuration(), callbacks);
  ASSERT_TRUE(result.has_value());
  auto& engine = *result;

  ASSERT_TRUE(engine->Start().has_value());
  EXPECT_TRUE(engine->IsStarted());

  auto second = engine->Start();
  ASSERT_FALSE(second.has_value());
  EXPECT_EQ(second.error(), TunnelError::already_running);

  std::unique_lock lock(mutex);
  ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(15),
      [&] { return disconnect_count > 0; }));
  lock.unlock();

  engine->Stop();
  EXPECT_FALSE(engine->IsStarted());

  const std::uint8_t packet[] = {0x45, 0x00, 0x00, 0x14};
  const PacketLease batch[] = {PacketLease{packet, sizeof(packet), 4, nullptr,
      nullptr}};
  EXPECT_EQ(engine->InputPackets(batch), PacketInputResult::transport_stopped);

  engine->Stop();
}

class SilentTcpServer final {
 public:
  SilentTcpServer()
      : acceptor_(io_,
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::make_address("127.0.0.1"), 0)),
        port_(acceptor_.local_endpoint().port()) {
    server_thread_ = std::thread([this] {
      boost::system::error_code ec;
      acceptor_.accept(socket_, ec);
      {
        std::lock_guard lock(mutex_);
        accepted_ = true;
      }
      cv_.notify_all();
      while (!stop_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
      boost::system::error_code close_ec;
      socket_.close(close_ec);
    });
  }

  ~SilentTcpServer() {
    stop_.store(true);
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
  }

  std::uint16_t port() const noexcept { return port_; }

  bool WaitForAccept(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    return cv_.wait_for(lock, timeout, [&] { return accepted_; });
  }

 private:
  boost::asio::io_context io_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::ip::tcp::socket socket_{io_};
  std::uint16_t port_;
  std::thread server_thread_;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool accepted_ = false;
  std::atomic<bool> stop_{false};
};

TEST(TunnelEngineTest, L3InputAdmissionWhileTransportConnecting) {
  SilentTcpServer server;

  auto config = MakeL3Configuration();
  config.l3.server_port = server.port();

  TunnelCallbacks callbacks;
  auto result = TunnelEngine::Create(config, callbacks);
  ASSERT_TRUE(result.has_value());
  auto& engine = *result;

  ASSERT_TRUE(engine->Start().has_value());
  ASSERT_TRUE(server.WaitForAccept(std::chrono::seconds(10)));

  const std::uint8_t packet[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
      0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
      0x00, 0x01};
  const PacketLease valid_lease{packet, sizeof(packet), 4, nullptr, nullptr};
  const PacketLease null_lease{nullptr, 16, 4, nullptr, nullptr};
  const PacketLease empty_lease{packet, 0, 4, nullptr, nullptr};
  const PacketLease bad_version_lease{packet, sizeof(packet), 5, nullptr,
      nullptr};

  const PacketLease null_batch[] = {null_lease};
  EXPECT_EQ(engine->InputPackets(null_batch), PacketInputResult::invalid_packet);

  const PacketLease empty_batch[] = {empty_lease};
  EXPECT_EQ(
      engine->InputPackets(empty_batch), PacketInputResult::invalid_packet);

  const PacketLease bad_version_batch[] = {bad_version_lease};
  EXPECT_EQ(engine->InputPackets(bad_version_batch),
      PacketInputResult::invalid_packet);

  const PacketLease valid_batch[] = {valid_lease};
  EXPECT_EQ(engine->InputPackets(valid_batch),
      PacketInputResult::transport_stopped);

  engine->Stop();
  EXPECT_FALSE(engine->IsStarted());
}

}  // namespace
