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

class PosixEchoServer final {
 public:
  enum class Mode {
    echo,
    close_after_echo_bytes,
  };

  explicit PosixEchoServer(Mode mode = Mode::echo,
      std::size_t close_after_bytes = 0)
      : mode_(mode), close_after_bytes_(close_after_bytes) {}

  ~PosixEchoServer() { Stop(); }

  bool Start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
      return false;
    }
    int reuse = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) <
        0) {
      return false;
    }
    socklen_t len = sizeof(addr);
    ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    port_ = ntohs(addr.sin_port);
    if (::listen(listen_fd_, 8) < 0) {
      return false;
    }
    running_.store(true);
    thread_ = std::thread([this] { Run(); });
    return true;
  }

  void Stop() {
    if (!running_.exchange(false)) {
      return;
    }
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      // No write-back of listen_fd_ here: Run() may still be reading it in
      // accept(); the running_ flag already prevents a second Stop().
    }
    const int connection_fd = current_fd_.exchange(-1);
    if (connection_fd >= 0) {
      ::shutdown(connection_fd, SHUT_RDWR);
      ::close(connection_fd);
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::uint16_t port() const { return port_; }

  bool WaitForAccepted(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (accepted_.load() > 0) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return accepted_.load() > 0;
  }

  // Waits until the most recent connection has echoed exactly
  // expected_bytes and then seen a clean EOF (peer FIN delivered).
  bool WaitForConnectionEof(std::size_t expected_bytes,
      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (last_conn_eof_.load() &&
          last_conn_bytes_.load() == expected_bytes) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return last_conn_eof_.load() &&
           last_conn_bytes_.load() == expected_bytes;
  }

  bool LastConnectionCleanEof() const { return last_conn_eof_.load(); }
  std::size_t LastConnectionBytes() const { return last_conn_bytes_.load(); }
  // Live count of bytes received on the current (most recent) connection,
  // updated as data arrives (before EOF).
  std::size_t LiveReceivedBytes() const {
    return received_bytes_live_.load();
  }

 private:
  void Run() {
    while (running_.load()) {
      const int fd = ::accept(listen_fd_, nullptr, nullptr);
      if (fd < 0) {
        return;
      }
      accepted_.fetch_add(1);
      current_fd_.store(fd);
      received_bytes_live_.store(0);
      last_conn_eof_.store(false);
      Serve(fd);
      current_fd_.store(-1);
      ::close(fd);
    }
  }

  void Serve(int fd) {
    std::uint8_t buffer[4096];
    std::size_t echoed = 0;
    std::size_t received = 0;
    bool clean_eof = false;
    while (running_.load()) {
      const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
      if (n == 0) {
        clean_eof = true;
        break;
      }
      if (n < 0) {
        break;
      }
      received += n;
      received_bytes_live_.fetch_add(n);
      echoed += n;
      std::size_t offset = 0;
      while (offset < static_cast<std::size_t>(n)) {
        const ssize_t written =
            ::send(fd, buffer + offset, n - offset, 0);
        if (written <= 0) {
          clean_eof = false;
          break;
        }
        offset += written;
      }
      if (offset < static_cast<std::size_t>(n)) {
        break;
      }
      if (mode_ == Mode::close_after_echo_bytes &&
          echoed >= close_after_bytes_) {
        clean_eof = true;
        break;
      }
    }
    last_conn_bytes_.store(received);
    last_conn_eof_.store(clean_eof);
  }

  Mode mode_;
  std::size_t close_after_bytes_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> running_{false};
  std::atomic<int> accepted_{0};
  std::atomic<int> current_fd_{-1};
  std::atomic<std::size_t> last_conn_bytes_{0};
  std::atomic<bool> last_conn_eof_{false};
  std::atomic<std::size_t> received_bytes_live_{0};
  std::thread thread_;
};

}  // namespace fptn::tunnel::flow::testing
