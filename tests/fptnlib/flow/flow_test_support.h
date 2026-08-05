#pragma once

#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include "fptn-protocol-lib/flow/lwip_stack.h"
#include "fptn-protocol-lib/tunnel/flow_interfaces.h"

namespace fptn::tunnel::flow::testing {

inline std::uint32_t Sum16Folded(const void* data, std::size_t length,
    std::uint32_t initial = 0) noexcept {
  const std::uint8_t* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t sum = initial;
  for (std::size_t i = 0; i + 1 < length; i += 2) {
    sum += static_cast<std::uint32_t>(
        (static_cast<std::uint16_t>(bytes[i]) << 8) | bytes[i + 1]);
  }
  if (length % 2 != 0) {
    sum += static_cast<std::uint32_t>(bytes[length - 1]) << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return sum;
}

inline std::uint16_t Checksum(const void* data, std::size_t length,
    std::uint32_t initial = 0) noexcept {
  return static_cast<std::uint16_t>(
      ~Sum16Folded(data, length, initial) & 0xFFFFu);
}

inline std::uint32_t ParseV4(const char* text) {
  in_addr addr;
  EXPECT_EQ(1, inet_pton(AF_INET, text, &addr));
  return addr.s_addr;
}

inline void WriteU16(std::vector<std::uint8_t>& out, std::size_t offset,
    std::uint16_t value) {
  out[offset] = static_cast<std::uint8_t>(value >> 8);
  out[offset + 1] = static_cast<std::uint8_t>(value & 0xFFu);
}

inline void WriteU32(std::vector<std::uint8_t>& out, std::size_t offset,
    std::uint32_t value) {
  out[offset] = static_cast<std::uint8_t>(value >> 24);
  out[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  out[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[offset + 3] = static_cast<std::uint8_t>(value & 0xFFu);
}

constexpr std::uint8_t kFlagFin = 0x01;
constexpr std::uint8_t kFlagSyn = 0x02;
constexpr std::uint8_t kFlagRst = 0x04;
constexpr std::uint8_t kFlagAck = 0x10;

inline std::vector<std::uint8_t> MakeTcpV4(const char* src, const char* dst,
    std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
    std::uint32_t ack, std::uint8_t flags,
    const std::vector<std::uint8_t>& payload = {}) {
  const std::size_t total = 20 + 20 + payload.size();
  std::vector<std::uint8_t> packet(total, 0);

  packet[0] = 0x45;
  WriteU16(packet, 2, static_cast<std::uint16_t>(total));
  packet[8] = 64;
  packet[9] = 6;
  const std::uint32_t src_addr = ParseV4(src);
  const std::uint32_t dst_addr = ParseV4(dst);
  std::memcpy(packet.data() + 12, &src_addr, 4);
  std::memcpy(packet.data() + 16, &dst_addr, 4);
  WriteU16(packet, 10, Checksum(packet.data(), 20));

  std::uint8_t* tcp = packet.data() + 20;
  WriteU16(packet, 20, sport);
  WriteU16(packet, 22, dport);
  WriteU32(packet, 24, seq);
  WriteU32(packet, 28, ack);
  tcp[12] = 0x50;
  tcp[13] = flags;
  WriteU16(packet, 34, 65535);
  if (!payload.empty()) {
    std::memcpy(packet.data() + 40, payload.data(), payload.size());
  }

  std::uint32_t pseudo = Sum16Folded(packet.data() + 12, 8);
  pseudo += 6;
  pseudo += static_cast<std::uint32_t>(20 + payload.size());
  WriteU16(packet, 36, Checksum(tcp, 20 + payload.size(), pseudo));
  return packet;
}

inline std::vector<std::uint8_t> MakeTcpV6(const char* src, const char* dst,
    std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
    std::uint32_t ack, std::uint8_t flags,
    const std::vector<std::uint8_t>& payload = {}) {  const std::size_t tcp_length = 20 + payload.size();
  const std::size_t total = 40 + tcp_length;
  std::vector<std::uint8_t> packet(total, 0);

  packet[0] = 0x60;
  WriteU16(packet, 4, static_cast<std::uint16_t>(tcp_length));
  packet[6] = 6;
  packet[7] = 64;
  in6_addr src6;
  in6_addr dst6;
  EXPECT_EQ(1, inet_pton(AF_INET6, src, &src6));
  EXPECT_EQ(1, inet_pton(AF_INET6, dst, &dst6));
  std::memcpy(packet.data() + 8, &src6, 16);
  std::memcpy(packet.data() + 24, &dst6, 16);

  std::uint8_t* tcp = packet.data() + 40;
  WriteU16(packet, 40, sport);
  WriteU16(packet, 42, dport);
  WriteU32(packet, 44, seq);
  WriteU32(packet, 48, ack);
  tcp[12] = 0x50;
  tcp[13] = flags;
  WriteU16(packet, 54, 65535);
  if (!payload.empty()) {
    std::memcpy(packet.data() + 60, payload.data(), payload.size());
  }

  std::uint32_t pseudo = Sum16Folded(packet.data() + 8, 32);
  pseudo += static_cast<std::uint32_t>(tcp_length);
  pseudo += 6;
  WriteU16(packet, 56, Checksum(tcp, tcp_length, pseudo));
  return packet;
}

class TestRuntime final {
 public:
  TestRuntime()
      : work_(boost::asio::make_work_guard(ioc_)),
        thread_([this] { ioc_.run(); }) {}

  ~TestRuntime() {
    work_.reset();
    ioc_.stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  boost::asio::any_io_executor Executor() {
    return ioc_.get_executor();
  }

 private:
  boost::asio::io_context ioc_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      work_;
  std::thread thread_;
};

class TestRouter final : public IFlowRouter {
 public:
  RouteAction Match(const FlowMetadata&) override {
    return RouteAction::direct;
  }
};

class OutputCollector final {
 public:
  void Append(OwnedPacketBatch batch) {
    {
      std::lock_guard lock(mutex_);
      for (auto& packet : batch) {
        packets_.push_back(std::move(packet));
      }
    }
    cv_.notify_all();
  }

  bool WaitForCount(std::size_t count,
      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    std::unique_lock lock(mutex_);
    return cv_.wait_for(lock, timeout,
        [&] { return packets_.size() >= count; });
  }

  template <typename Predicate>
  bool WaitFor(std::size_t min_count, Predicate predicate,
      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    std::unique_lock lock(mutex_);
    return cv_.wait_for(lock, timeout, [&] {
      if (packets_.size() < min_count) {
        return false;
      }
      return predicate(packets_);
    });
  }

  std::vector<OwnedPacket> Snapshot() {
    std::lock_guard lock(mutex_);
    return packets_;
  }

  void Reset() {
    std::lock_guard lock(mutex_);
    packets_.clear();
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::vector<OwnedPacket> packets_;
};

inline std::uint16_t ReadPort(const std::vector<std::uint8_t>& data,
    std::size_t tcp_offset) {
  return static_cast<std::uint16_t>(
      (data[tcp_offset] << 8) | data[tcp_offset + 1]);
}

inline std::uint32_t ReadSeq(const std::vector<std::uint8_t>& data,
    std::size_t tcp_offset) {
  return (static_cast<std::uint32_t>(data[tcp_offset + 4]) << 24) |
         (static_cast<std::uint32_t>(data[tcp_offset + 5]) << 16) |
         (static_cast<std::uint32_t>(data[tcp_offset + 6]) << 8) |
         static_cast<std::uint32_t>(data[tcp_offset + 7]);
}

inline std::uint32_t ReadAck(const std::vector<std::uint8_t>& data,
    std::size_t tcp_offset) {
  return (static_cast<std::uint32_t>(data[tcp_offset + 8]) << 24) |
         (static_cast<std::uint32_t>(data[tcp_offset + 9]) << 16) |
         (static_cast<std::uint32_t>(data[tcp_offset + 10]) << 8) |
         static_cast<std::uint32_t>(data[tcp_offset + 11]);
}

inline std::uint8_t ReadFlags(const std::vector<std::uint8_t>& data,
    std::size_t tcp_offset) {
  return data[tcp_offset + 13];
}

inline std::vector<std::uint8_t> MakeUdpV4(const char* src, const char* dst,
    std::uint16_t sport, std::uint16_t dport,
    const std::vector<std::uint8_t>& payload) {
  const std::size_t udp_length = 8 + payload.size();
  const std::size_t total = 20 + udp_length;
  std::vector<std::uint8_t> packet(total, 0);

  packet[0] = 0x45;
  WriteU16(packet, 2, static_cast<std::uint16_t>(total));
  packet[8] = 64;
  packet[9] = 17;
  const std::uint32_t src_addr = ParseV4(src);
  const std::uint32_t dst_addr = ParseV4(dst);
  std::memcpy(packet.data() + 12, &src_addr, 4);
  std::memcpy(packet.data() + 16, &dst_addr, 4);
  WriteU16(packet, 10, Checksum(packet.data(), 20));

  std::uint8_t* udp = packet.data() + 20;
  WriteU16(packet, 20, sport);
  WriteU16(packet, 22, dport);
  WriteU16(packet, 24, static_cast<std::uint16_t>(udp_length));
  if (!payload.empty()) {
    std::memcpy(packet.data() + 28, payload.data(), payload.size());
  }

  std::uint32_t pseudo = Sum16Folded(packet.data() + 12, 8);
  pseudo += 17;
  pseudo += static_cast<std::uint32_t>(udp_length);
  WriteU16(packet, 26, Checksum(udp, udp_length, pseudo));
  return packet;
}

inline std::vector<std::uint8_t> MakeUdpV6(const char* src, const char* dst,
    std::uint16_t sport, std::uint16_t dport,
    const std::vector<std::uint8_t>& payload) {
  const std::size_t udp_length = 8 + payload.size();
  const std::size_t total = 40 + udp_length;
  std::vector<std::uint8_t> packet(total, 0);

  packet[0] = 0x60;
  WriteU16(packet, 4, static_cast<std::uint16_t>(udp_length));
  packet[6] = 17;
  packet[7] = 64;
  in6_addr src6;
  in6_addr dst6;
  EXPECT_EQ(1, inet_pton(AF_INET6, src, &src6));
  EXPECT_EQ(1, inet_pton(AF_INET6, dst, &dst6));
  std::memcpy(packet.data() + 8, &src6, 16);
  std::memcpy(packet.data() + 24, &dst6, 16);

  std::uint8_t* udp = packet.data() + 40;
  WriteU16(packet, 40, sport);
  WriteU16(packet, 42, dport);
  WriteU16(packet, 44, static_cast<std::uint16_t>(udp_length));
  if (!payload.empty()) {
    std::memcpy(packet.data() + 48, payload.data(), payload.size());
  }

  std::uint32_t pseudo = Sum16Folded(packet.data() + 8, 32);
  pseudo += static_cast<std::uint32_t>(udp_length);
  pseudo += 17;
  WriteU16(packet, 46, Checksum(udp, udp_length, pseudo));
  return packet;
}

}  // namespace fptn::tunnel::flow::testing
