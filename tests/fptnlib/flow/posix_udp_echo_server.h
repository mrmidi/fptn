#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace fptn::tunnel::flow::testing {

class PosixUdpEchoServer final {
 public:
  explicit PosixUdpEchoServer(bool ipv6 = false) : ipv6_(ipv6) {}

  ~PosixUdpEchoServer() { Stop(); }

  bool Start() {
    socket_fd_ = ::socket(ipv6_ ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
      return false;
    }
    int reuse = 1;
    ::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (ipv6_) {
      sockaddr_in6 addr{};
      addr.sin6_family = AF_INET6;
      addr.sin6_addr = in6addr_loopback;
      addr.sin6_port = 0;
      if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr),
              sizeof(addr)) < 0) {
        return false;
      }
      socklen_t len = sizeof(addr);
      ::getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
      port_ = ntohs(addr.sin6_port);
    } else {
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      addr.sin_port = 0;
      if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr),
              sizeof(addr)) < 0) {
        return false;
      }
      socklen_t len = sizeof(addr);
      ::getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
      port_ = ntohs(addr.sin_port);
    }

    running_.store(true);
    thread_ = std::thread([this] { Run(); });
    return true;
  }

  void Stop() {
    if (!running_.exchange(false)) {
      return;
    }
    if (socket_fd_ >= 0) {
      ::shutdown(socket_fd_, SHUT_RDWR);
      ::close(socket_fd_);
      socket_fd_ = -1;
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::uint16_t port() const { return port_; }

  bool WaitForDatagrams(std::uint64_t count,
      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (echoed_.load() >= count) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return echoed_.load() >= count;
  }

 private:
  void Run() {
    std::uint8_t buffer[65536];
    sockaddr_storage peer{};
    while (running_.load()) {
      socklen_t peer_len = sizeof(peer);
      const ssize_t n = ::recvfrom(socket_fd_, buffer, sizeof(buffer), 0,
          reinterpret_cast<sockaddr*>(&peer), &peer_len);
      if (n <= 0) {
        return;
      }
      ::sendto(socket_fd_, buffer, n, 0,
          reinterpret_cast<sockaddr*>(&peer), peer_len);
      echoed_.fetch_add(1);
    }
  }

  bool ipv6_;
  int socket_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> echoed_{0};
  std::thread thread_;
};

}  // namespace fptn::tunnel::flow::testing
