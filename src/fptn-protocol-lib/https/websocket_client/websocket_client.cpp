/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

// PR1A: compile-time socket buffer experiment parameter.
// 0 = kernel default. Set via CMake: -DFPTN_IOS_SOCKET_BUFFER_BYTES=262144
#ifndef FPTN_IOS_SOCKET_BUFFER_BYTES
#define FPTN_IOS_SOCKET_BUFFER_BYTES 0
#endif

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#include <https/utils/change_cipher_spec.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <camouflage/tls/builder.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/network/utils.h"  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <netinet/tcp.h>
#elif defined(__linux__) && !defined(__ANDROID__)
#include <netinet/tcp.h>
#endif

#ifdef _WIN32
#include <mstcpip.h>  // NOLINT(build/include_order)
#endif

namespace fptn::protocol::https {

namespace {
// PR1A: iOS socket buffer experiment. 0 = kernel default.
// Subsequent builds test 262144 (256 KiB) and 524288 (512 KiB)
// via -DFPTN_IOS_SOCKET_BUFFER_BYTES without editing source.
#if defined(__APPLE__) && TARGET_OS_IOS
constexpr int kRequestedSocketBufferBytes = FPTN_IOS_SOCKET_BUFFER_BYTES;
#else
constexpr int kRequestedSocketBufferBytes = 0;
#endif
}  // namespace

// PR1A: process-wide lifecycle counters.
std::atomic<int> WebsocketClient::live_clients_{0};
std::atomic<int> WebsocketClient::active_reader_coroutines_{0};
std::atomic<int> WebsocketClient::active_sender_coroutines_{0};

WebsocketClient::WebsocketClient(Config config, int concurrency_hint)
    : ioc_(concurrency_hint),
      ctx_(https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      strand_(boost::asio::make_strand(ioc_)),
      watchdog_timer_(strand_),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), nullptr),
          ctx_)),
      write_channel_(strand_, kMaxSizeOutQueue_),
      config_(std::move(config)) {
  auto* ssl = ws_.next_layer().native_handle();
  https::utils::SetHandshakeSni(ssl, config_.sni);
  https::utils::SetHandshakeSessionID(ssl);

  // Set SSL buffer sizes
  SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);

  if (config_.censorship_strategy == CensorshipStrategy::kTlsObfuscator) {
    obfuscator_ =
        std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator2>();
    ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
  }

  https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (config_.expected_md5_fingerprint.empty()) {
          return true;
        }
        if (md5_fingerprint == config_.expected_md5_fingerprint) {
          return true;
        }
        SPDLOG_ERROR("Certificate MD5 mismatch. Expected: {}, got: {}.",
            config_.expected_md5_fingerprint, md5_fingerprint);
        return false;
      });

  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(false);
  ws_.read_message_max(256 * 1024);
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));

  live_clients_.fetch_add(1, std::memory_order_relaxed);
}

WebsocketClient::~WebsocketClient() {
  try {
    Stop();
  } catch (...) {
    SPDLOG_WARN("Unknown error in ~WebsocketClient");
  }

  // Stop io_context
  try {
    if (!ioc_.stopped()) {
      SPDLOG_INFO("Stopping io_context...");
      ioc_.stop();
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }
  SPDLOG_INFO("WebsocketClient removed");
  // PR1A: decrement after Stop() and ioc_.stop() complete, so the
  // counter reflects the client as alive until fully torn down.
  live_clients_.fetch_sub(1, std::memory_order_relaxed);
}

void WebsocketClient::Run() {
  if (running_.exchange(true)) {
    SPDLOG_WARN("WebsocketClient is already running");
    return;
  }

  SPDLOG_INFO("Connecting to {}:{} [strategy={}]", config_.server_ip.ToString(),
      config_.server_port, ToString(config_.censorship_strategy));

  auto self = weak_from_this();
  boost::asio::co_spawn(
      ioc_,
      [self]() -> boost::asio::awaitable<void> {
        if (auto shared_self = self.lock()) {
          const bool status = co_await shared_self->RunInternal();
          if (!status) {
            shared_self->Stop();
          }
        }
      },
      boost::asio::detached);
  try {
    while (running_ || !was_stopped_) {
      const std::size_t processed = ioc_.poll_one();
      if (processed == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  } catch (...) {
    SPDLOG_WARN("Exception while running");
  }
}

bool WebsocketClient::Stop() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return false;
  }

  SPDLOG_INFO("Marked client as stopped and disconnected");

  running_ = false;
  was_connected_ = false;

  boost::system::error_code ec;

  try {
    watchdog_timer_.cancel();
  } catch (const boost::system::system_error&) {
    SPDLOG_WARN("Cancellation timer error");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping timer");
  }

  try {
    SPDLOG_INFO("Emit cancel signal");
    if (was_inited_) {
      cancel_signal_.emit(boost::asio::cancellation_type::all);
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception during cancellation");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during cancellation");
  }

  try {
    SPDLOG_INFO("Closing write_channel");
    if (was_inited_) {
      write_channel_.close();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception closing write channel");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing write channel");
  }

  try {
    SPDLOG_INFO("Closing resolver");
    if (was_inited_) {
      resolver_.cancel();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception cancelling resolver");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing resolver");
  }

  // Close TCP connection
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down TCP socket...");

      auto& tcp = boost::beast::get_lowest_layer(ws_);
      const boost::asio::socket_base::linger linger(true, 0);
      tcp.socket().set_option(linger);

      if (tcp.socket().is_open()) {
        tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::asio::error::not_connected) {
          SPDLOG_WARN("TCP socket shutdown error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket shutdown successfully");
        }

        tcp.socket().close(ec);
        if (ec) {
          SPDLOG_WARN("TCP socket close error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket closed successfully");
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during TCP shutdown");
  }

  // Close SSL
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down SSL layer...");
      auto& ssl = ws_.next_layer();
      if (ssl.native_handle()) {
        // More robust SSL shutdown
        ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
        ::SSL_shutdown(ssl.native_handle());
      }
      ssl.shutdown(ec);
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during SSL shutdown: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during SSL shutdown");
  }

  if (auto* ssl = ws_.next_layer().native_handle()) {
    https::utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  was_stopped_ = true;
  SPDLOG_INFO("WebSocket client stopped successfully");

  return true;
}

// PR1B: overflow-safe byte reservation via CAS loop.
std::optional<std::uint64_t> WebsocketClient::tryReserveQueuedBytes(
    std::uint64_t packet_size) noexcept {
  auto current = queued_bytes_.load(std::memory_order_relaxed);
  for (;;) {
    if (packet_size > kMaxQueuedBytes ||
        current > kMaxQueuedBytes - packet_size) {
      return std::nullopt;
    }
    const auto desired = current + packet_size;
    if (queued_bytes_.compare_exchange_weak(
            current, desired,
            std::memory_order_relaxed, std::memory_order_relaxed)) {
      return desired;
    }
  }
}

void WebsocketClient::updateQueuedBytesPeak(std::uint64_t new_total) noexcept {
  auto peak = queued_bytes_peak_.load(std::memory_order_relaxed);
  while (new_total > peak) {
    if (queued_bytes_peak_.compare_exchange_weak(
            peak, new_total,
            std::memory_order_relaxed, std::memory_order_relaxed)) {
      break;
    }
  }
}

void WebsocketClient::releaseDequeuedPacketAccounting(
    const IPPacketPtr& packet) noexcept {
  if (!packet) {
    return;
  }
  queued_packets_.fetch_sub(1, std::memory_order_relaxed);
  queued_bytes_.fetch_sub(packet->Data().size(), std::memory_order_relaxed);
}

SendResult WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !was_connected_) {
    return SendResult::transport_stopped;
  }
  if (!packet || packet->Data().empty()) {
    return SendResult::invalid_packet;
  }

  const auto packet_size =
      static_cast<std::uint64_t>(packet->Data().size());

  // Reserve bytes before try_send. Both bytes and packet count are
  // reserved before the channel operation so the sender cannot dequeue
  // and decrement between the two producer increments.
  const auto reserved_total = tryReserveQueuedBytes(packet_size);
  if (!reserved_total.has_value()) {
    queue_full_count_.fetch_add(1, std::memory_order_relaxed);
    return SendResult::queue_full;
  }

  queued_packets_.fetch_add(1, std::memory_order_relaxed);

  bool sent = false;
  try {
    sent = write_channel_.try_send(
        boost::system::error_code(), std::move(packet));
  } catch (...) {
    sent = false;
  }

  if (!sent) {
    // Rollback both counters on channel-full or exception.
    queued_packets_.fetch_sub(1, std::memory_order_relaxed);
    queued_bytes_.fetch_sub(packet_size, std::memory_order_relaxed);

    if (running_ && was_connected_) {
      queue_full_count_.fetch_add(1, std::memory_order_relaxed);
      return SendResult::queue_full;
    }
    return SendResult::transport_stopped;
  }

  updateQueuedBytesPeak(*reserved_total);
  return SendResult::accepted;
}

bool WebsocketClient::IsStarted() const { return running_ && was_connected_; }

boost::asio::awaitable<bool> WebsocketClient::RunInternal() {
  try {
    const bool connected = co_await Connect();
    if (!connected) {
      co_return false;
    }

    const bool ip_assigned = co_await ReceiveIPAssignment();
    if (!ip_assigned) {
      co_return false;
    }

    // PR1A: commented out for iOS memory optimization testing.
    // Previously overwrote Connect()'s buffer sizes to 1 MiB after
    // IP assignment. Socket buffers are now controlled by the
    // FPTN_IOS_SOCKET_BUFFER_BYTES CMake parameter (applied before
    // connect in Connect()). Uncomment to restore legacy behavior.
    // try {
    //   boost::beast::get_lowest_layer(ws_).socket().set_option(
    //       boost::asio::socket_base::receive_buffer_size(1 * 1024 * 1024));
    //   boost::beast::get_lowest_layer(ws_).socket().set_option(
    //       boost::asio::socket_base::send_buffer_size(1 * 1024 * 1024));
    // } catch (const boost::system::system_error& e) {
    //   SPDLOG_WARN("Failed to set socket options: {}", e.what());
    // }

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(3));

    // Start timer
    StartWatchdog();

    // Start reader and sender
    was_inited_ = true;
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunReader(); }, boost::asio::detached);
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunSender(); }, boost::asio::detached);

    SPDLOG_INFO("WebSocket connection established successfully");
    SPDLOG_INFO("Using serializer: yaff");

    if (config_.on_connected_callback) {
      config_.on_connected_callback();
    }

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunInternal exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while running");
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::Connect() {
  try {
    boost::system::error_code ec;

    // DNS resolution
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(5));
    const auto server_port_str = std::to_string(config_.server_port);
    const auto results = co_await resolver_.async_resolve(
        config_.server_ip.ToString(), server_port_str,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Resolve error: {}", ec.message());
      co_return false;
    }

    // TCP connect
    // PR1A: pre-open socket and apply buffer sizes before connect so
    // they may influence TCP receive-window negotiation.
    {
      auto& tcp = boost::beast::get_lowest_layer(ws_);
      auto& sock = tcp.socket();
      if (!sock.is_open()) {
        sock.open(boost::asio::ip::tcp::v4(), ec);
        if (ec) {
          SPDLOG_ERROR("Socket open error: {}", ec.message());
          co_return false;
        }
      }
      requested_rcvbuf_bytes_.store(kRequestedSocketBufferBytes, std::memory_order_relaxed);
      requested_sndbuf_bytes_.store(kRequestedSocketBufferBytes, std::memory_order_relaxed);
      if (kRequestedSocketBufferBytes > 0) {
        boost::system::error_code buf_ec;
        sock.set_option(
            boost::asio::socket_base::receive_buffer_size(kRequestedSocketBufferBytes), buf_ec);
        if (buf_ec) {
          socket_buffer_set_error_count_.fetch_add(1, std::memory_order_relaxed);
        }
        buf_ec.clear();
        sock.set_option(
            boost::asio::socket_base::send_buffer_size(kRequestedSocketBufferBytes), buf_ec);
        if (buf_ec) {
          socket_buffer_set_error_count_.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
    co_await boost::beast::get_lowest_layer(ws_).async_connect(
        results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Connect error: {}", ec.message());
      co_return false;
    }

    auto& socket = boost::beast::get_lowest_layer(ws_).socket();
    if (!socket.is_open()) {
      SPDLOG_ERROR("Socket not open after connect");
      co_return false;
    }

    const auto remote_ep = socket.remote_endpoint(ec);
    if (ec) {
      SPDLOG_ERROR("Socket reported connected but remote_endpoint() failed: {}",
          ec.message());
      co_return false;
    }

    SPDLOG_INFO("Successfully connected to {}:{}",
        remote_ep.address().to_string(), remote_ep.port());

    // PR1A: query effective socket buffer sizes after connect.
    // Uses Boost.Asio get_option for cross-platform compatibility.
    // Failure stores 0; never fails the tunnel.
    {
      boost::system::error_code option_ec;
      boost::asio::socket_base::receive_buffer_size receive_option;
      socket.get_option(receive_option, option_ec);
      effective_rcvbuf_bytes_.store(
          option_ec ? 0 : receive_option.value(), std::memory_order_relaxed);

      option_ec.clear();
      boost::asio::socket_base::send_buffer_size send_option;
      socket.get_option(send_option, option_ec);
      effective_sndbuf_bytes_.store(
          option_ec ? 0 : send_option.value(), std::memory_order_relaxed);
    }

    // TCP options
    socket.set_option(boost::asio::ip::tcp::no_delay(true));
    socket.set_option(boost::asio::socket_base::reuse_address(true));

    socket.set_option(boost::asio::socket_base::keep_alive(true));

#if defined(__APPLE__) && TARGET_OS_OSX
    {
      int fd = socket.native_handle();
      int keepidle = 5;
      int keepintvl = 2;
      int keepcnt = 3;
      int rxt_droptime = 10;
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle, sizeof(keepidle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
      setsockopt(fd, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &rxt_droptime,
          sizeof(rxt_droptime));
    }
#elif defined(__linux__) && !defined(__ANDROID__)
    {
      int fd = socket.native_handle();
      int keepidle = 5;
      int keepintvl = 2;
      int keepcnt = 3;
      int user_timeout = 10000;
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
      setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout,
          sizeof(user_timeout));
    }
#elif defined(_WIN32)
    {
      SOCKET s = socket.native_handle();
      tcp_keepalive ka = {1, 4000, 1000};
      DWORD bytes = 0;
      WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes,
          nullptr, nullptr);
      DWORD maxrt = 10;
      setsockopt(s, IPPROTO_TCP, TCP_MAXRT,
          reinterpret_cast<const char*>(&maxrt), sizeof(maxrt));
    }
#endif

    // PR1A: commented out for iOS memory optimization testing.
    // Previously requested 4 MiB TCP send/receive buffers here (after
    // connect). Socket buffers are now controlled by the
    // FPTN_IOS_SOCKET_BUFFER_BYTES CMake parameter and applied before
    // connect. Uncomment to restore legacy behavior.
    // try {
    //   constexpr int kBufferSize = 4 * 1024 * 1024;
    //   socket.set_option(
    //       boost::asio::socket_base::receive_buffer_size(kBufferSize));
    //   socket.set_option(
    //       boost::asio::socket_base::send_buffer_size(kBufferSize));
    // } catch (...) {
    //   SPDLOG_WARN("Failed to set socket buffer sizes in Connect()");
    // }

    // Reality Mode: Enhanced stealth connection protocol
    // First, establishes a genuine TLS handshake as a decoy to bypass deep
    // packet inspection Then resets the connection state and activates
    // obfuscation for the real encrypted tunnel This dual-handshake approach
    // makes traffic analysis significantly more difficult
    if (IsRealityModeWithFakeHandshake(config_.censorship_strategy)) {
      const bool status = co_await PerformFakeHandshake2();
      if (!status) {
        co_return false;
      }
      // For Reality Mode we use TLS obfuscator after fake handshake
      // This provides additional encryption layer for the real connection
      ws_.next_layer().next_layer().set_obfuscator(
          std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
    } else if (obfuscator_ != nullptr) {  // Set obfuscator
      ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
    }

    // SSL handshake
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150)}
        .async_wait(boost::asio::use_awaitable);

    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return false;
    }

    // [diag] before detaching, check for leftover obfuscated bytes. If the peer
    // sent post-handshake records (e.g. a TLS 1.3 NewSessionTicket) while its
    // obfuscator was still attached, they get read raw after we detach here and
    // desync the WebSocket -- a likely cause of the intermittent reality drop.
    {
      boost::system::error_code diag_ec;
      const std::size_t raw_available =
          boost::beast::get_lowest_layer(ws_).socket().available(diag_ec);
      const auto diag_obf = ws_.next_layer().next_layer().get_obfuscator();
      SPDLOG_INFO(
          "Detaching obfuscator after TLS handshake: raw_bytes_available={}, "
          "obfuscator_pending={}",
          raw_available, (diag_obf && diag_obf->HasPendingData()));
    }
    // Reset obfuscator after TLS-handshake
    ws_.next_layer().next_layer().set_obfuscator(nullptr);

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150)}
        .async_wait(boost::asio::use_awaitable);

    SPDLOG_INFO("SSL handshake completed");

    // WebSocket connection options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(10);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }
    // WebSocket handshake
    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [this](boost::beast::websocket::request_type& req) {
          req.set("Authorization", "Bearer " + config_.access_token);
          req.set("X-Serializer", "yaff");
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
        }));
    // Websocket handshake
    co_await ws_.async_handshake(config_.server_ip.ToString(),
        common::api::kApiWebSocketUrl,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return false;
    }

    was_connected_ = true;
    // WebSocket options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(15);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(10)}
        .async_wait(boost::asio::use_awaitable);

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception");
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::ReceiveIPAssignment() {
  boost::beast::flat_buffer buffer;
  buffer.reserve(16 * 1024);
  try {
    boost::system::error_code ec;
    co_await ws_.async_read(
        buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec || buffer.size() == 0) {
      SPDLOG_ERROR("Failed to read IP assignment: {}", ec.message());
      co_return false;
    }

    const auto ip_pair = fptn::protocol::yaff::DeserializeIPAssignmentMessage(
        boost::beast::buffers_to_string(buffer.data()));

    if (!ip_pair.has_value()) {
      SPDLOG_ERROR("Failed to parse IP assignment message");
      co_return false;
    }
    const auto& [ipv4_str, ipv6_str] = ip_pair.value();
    if (ipv4_str.empty() || ipv6_str.empty()) {
      SPDLOG_ERROR(
          "Invalid IP assignment: IPv4='{}', IPv6='{}'", ipv4_str, ipv6_str);
      co_return false;
    }

    ip_assigned_ = true;
    assigned_ipv4_ = common::network::IPv4Address(ipv4_str);
    assigned_ipv6_ = common::network::IPv6Address(ipv6_str);

    SPDLOG_INFO("Received IP assignment from server: IPv4={}, IPv6={}",
        ipv4_str, ipv6_str);

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("ReceiveIPAssignment exception: {}", e.what());
    co_return false;
  }
}

boost::asio::awaitable<void> WebsocketClient::RunReader() {
  AtomicActivityGuard guard(active_reader_coroutines_);
  boost::beast::flat_buffer buffer;
  // PR1A: 64 KiB initial reserve with a 256 KiB WebSocket message limit.
  // Beast grows the buffer dynamically up to read_message_max as needed.
  buffer.reserve(64 * 1024);
  // cppcheck-suppress variableScope
  std::size_t inbound_batches = 0;  // [diag] persists across the read loop
  try {
    boost::system::error_code ec;
    while (running_ && was_connected_ && ws_.is_open()) {
      co_await ws_.async_read(
          buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        // [diag] always surface why the reader stopped (was DEBUG, and silent
        // on a clean close) so the disconnect reason is not hidden behind the
        // watchdog. closed=true means the peer (likely the server) closed it.
        SPDLOG_WARN(
            "RunReader stopped after {} inbound batches: {} [closed={}]",
            inbound_batches, ec.message(),
            ec == boost::beast::websocket::error::closed);
        break;
      }

      if (buffer.size() == 0) {
        continue;
      }
      ++inbound_batches;  // [diag]

      auto batch_packets =
          fptn::protocol::yaff::DeserializeBatchIPPacket(buffer);
      if (!batch_packets.empty()) {
        for (auto& raw_ip_opt : batch_packets) {
          auto packet =
              fptn::common::network::IPPacket::Parse(std::move(raw_ip_opt));
          if (running_ && packet && config_.new_ip_pkt_callback) {
            // change IP addresses
            if (packet->IsIPv4()) {
              packet->SetDstIPv4Address(config_.tun_interface_address_ipv4);
            } else if (packet->IsIPv6()) {
              packet->SetDstIPv6Address(config_.tun_interface_address_ipv6);
            } else {
              continue;
            }
            config_.new_ip_pkt_callback(std::move(packet));
          }
        }
      }
      buffer.consume(buffer.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("RunReader unknown exception");
  }
  was_connected_ = false;
  co_return;
}

boost::asio::awaitable<void> WebsocketClient::RunSender() {
  AtomicActivityGuard guard(active_sender_coroutines_);
  constexpr std::size_t kMaxBatchSize = 32;
  auto token = boost::asio::bind_cancellation_slot(
      cancel_signal_.slot(), boost::asio::as_tuple(boost::asio::use_awaitable));

  // PR1B: append a packet to the batch if it is valid IPv4/IPv6.
  // Rewrites the source address. Returns the packet's raw size, or 0
  // if the packet was discarded (non-IP family).
  auto appendPacketIfValid =
      [this](fptn::common::network::BatchIPPacketPtr& packets,
             IPPacketPtr& packet,
             std::size_t& batch_raw_bytes) -> bool {
    if (!packet) {
      return false;
    }
    if (packet->IsIPv4()) {
      packet->SetSrcIPv4Address(assigned_ipv4_);
    } else if (packet->IsIPv6()) {
      packet->SetSrcIPv6Address(assigned_ipv6_);
    } else {
      return false;
    }
    batch_raw_bytes += packet->Data().size();
    packets.push_back(std::move(packet));
    return true;
  };

  try {
    // PR1B: carried packet prevents batch overshoot. When the next
    // packet would exceed kMaxBatchRawBytes, it is saved here and
    // becomes the first packet of the next batch.
    IPPacketPtr pending_packet;

    while (running_ && was_connected_ && ws_.is_open()) {
      IPPacketPtr first_packet;

      if (pending_packet) {
        first_packet = std::move(pending_packet);
      } else {
        auto [ec, packet] = co_await write_channel_.async_receive(token);
        if (ec || !packet) {
          continue;
        }
        releaseDequeuedPacketAccounting(packet);
        first_packet = std::move(packet);
      }

      fptn::common::network::BatchIPPacketPtr packets;
      std::size_t batch_raw_bytes = 0;

      appendPacketIfValid(packets, first_packet, batch_raw_bytes);

      // Drain additional packets up to packet and byte caps.
      while (packets.size() < kMaxBatchSize) {
        IPPacketPtr next_packet;
        const bool received = write_channel_.try_receive(
            [&](const boost::system::error_code& ec2,
                IPPacketPtr p) {
              if (!ec2) {
                next_packet = std::move(p);
              }
            });
        if (!received || !next_packet) {
          break;
        }

        releaseDequeuedPacketAccounting(next_packet);

        const auto next_size = next_packet->Data().size();
        if (!packets.empty() &&
            batch_raw_bytes + next_size > kMaxBatchRawBytes) {
          // Carry this packet to the next batch to avoid overshoot.
          pending_packet = std::move(next_packet);
          break;
        }

        appendPacketIfValid(packets, next_packet, batch_raw_bytes);
      }

      if (!packets.empty()) {
        auto batch_data = fptn::protocol::yaff::SerializeBatchIPPacket(
            std::move(packets));
        if (batch_data.has_value()) {
          boost::system::error_code ec;
          co_await ws_.async_write(boost::asio::buffer(batch_data.value()),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            SPDLOG_ERROR("WebSocket error: {}", ec.message());
            break;
          }
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    if (err.code() != boost::asio::error::operation_aborted) {
      SPDLOG_ERROR("RunSender error: {}", err.what());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunSender exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("RunSender unknown exception");
  }
  was_connected_ = false;
  co_return;
}

boost::asio::awaitable<bool> WebsocketClient::PerformFakeHandshake2() {
  try {
    boost::system::error_code ec;
    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    auto& tcp_socket = tcp_layer.socket();

    SPDLOG_INFO("Fake TLS handshake started for SNI: {}", config_.sni);

    /* Send client hello */
    const auto client_hello = GenerateHandshakePacket();
    if (client_hello.empty()) {
      SPDLOG_WARN("Failed to generate ClientHello for SNI: {}", config_.sni);
      co_return false;
    }
    const std::size_t client_hello_bytes_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(client_hello),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR(
          "Failed to send ClientHello to {}: {}", config_.sni, ec.message());
      co_return false;
    }
    if (client_hello_bytes_size != client_hello.size()) {
      SPDLOG_ERROR("Error ClientHello sent: {} of {} bytes",
          client_hello_bytes_size, client_hello.size());
      co_return false;
    }

    /* Wait for server answer */
    const auto server_hello =
        co_await common::network::WaitForServerTlsHelloAsync(
            tcp_socket, std::chrono::milliseconds(1500));
    if (!server_hello.has_value()) {
      SPDLOG_ERROR("Failed to receive ServerHello from {}", config_.sni);
      co_return false;
    }

    /* Send change cipher spec */
    const auto change_cipher_spec =
        fptn::protocol::https::utils::MakeClientChangeCipherSpec();
    const std::size_t change_cipher_spec_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(change_cipher_spec),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR(
          "Failed to send ClientHello to {}: {}", config_.sni, ec.message());
      co_return false;
    }
    if (change_cipher_spec_size != change_cipher_spec.size()) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}",
          change_cipher_spec_size, change_cipher_spec.size());
      co_return false;
    }

    // timeout
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150));
    co_await timer.async_wait(boost::asio::use_awaitable);

    SPDLOG_INFO(
        "Fake TLS handshake completed for {}, received {} bytes from server",
        config_.sni, server_hello.value().size());
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Fake TLS handshake exception for {}: {}", config_.sni, e.what());
  }
  co_return false;
}

void WebsocketClient::StartWatchdog() {
  if (!running_) return;

  constexpr std::chrono::milliseconds kTimeout(300);

  auto weak_self = weak_from_this();
  watchdog_timer_.expires_after(kTimeout);
  watchdog_timer_.async_wait([weak_self](const boost::system::error_code& ec) {
    auto shared_self = weak_self.lock();
    if (!shared_self) {
      return;
    }

    if (ec == boost::asio::error::operation_aborted) {
      return;
    }

    if (shared_self->running_ && !shared_self->was_connected_) {
      SPDLOG_INFO("Watchdog detected disconnected state");
      shared_self->Stop();
    } else if (shared_self->running_) {
      shared_self->StartWatchdog();
    }
  });
}

std::vector<std::uint8_t> WebsocketClient::GenerateHandshakePacket() const {
  auto builder = camouflage::tls::Builder::Create();
  switch (config_.censorship_strategy) {
    /* Chrome */
    case CensorshipStrategy::kSniRealityModeChrome149:
      SPDLOG_INFO("Selected strategy: Chrome 149");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_149_0_7827_103);
      break;
    case CensorshipStrategy::kSniRealityModeChrome148:
      SPDLOG_INFO("Selected strategy: Chrome 148");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_148_0_7778_216);
      break;
    case CensorshipStrategy::kSniRealityModeChrome147:
      SPDLOG_INFO("Selected strategy: Chrome 147");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_147_0_7727_56);
      break;
    case CensorshipStrategy::kSniRealityModeChrome146:
      SPDLOG_INFO("Selected strategy: Chrome 146");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_146_0_7680_178);
      break;
    case CensorshipStrategy::kSniRealityModeChrome145:
      SPDLOG_INFO("Selected strategy: Chrome 145");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_145_0_7632_46);
      break;
      /* Firefox */
    case CensorshipStrategy::kSniRealityModeFirefox151:
      SPDLOG_INFO("Selected strategy: Firefox 151");
      builder.Firefox(camouflage::tls::firefox::Version::kV_151_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox150:
      SPDLOG_INFO("Selected strategy: Firefox 150");
      builder.Firefox(camouflage::tls::firefox::Version::kV_150_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox149:
      SPDLOG_INFO("Selected strategy: Firefox 149");
      builder.Firefox(camouflage::tls::firefox::Version::kV_149_0);
      break;
    /* Safari */
    case CensorshipStrategy::kSniRealityModeSafari26_5:
      SPDLOG_INFO("Selected strategy: Safari 26.5");
      builder.Safari(camouflage::tls::safari::Version::kV_26_5);
      break;
    case CensorshipStrategy::kSniRealityModeSafari26_4:
      SPDLOG_INFO("Selected strategy: Safari 26.4");
      builder.Safari(camouflage::tls::safari::Version::kV_26_4);
      break;
    /* Yandex */
    case CensorshipStrategy::kSniRealityModeYandex26_4:
      SPDLOG_INFO("Selected strategy: Yandex 26.4");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_4_3_897);
      break;
    case CensorshipStrategy::kSniRealityModeYandex26_3:
      SPDLOG_INFO("Selected strategy: Yandex 26.3");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_3_3_881);
      break;
    case CensorshipStrategy::kSniRealityModeYandex25:
      SPDLOG_INFO("Selected strategy: Yandex 25");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_25_8_3_828);
      break;
    case CensorshipStrategy::kSniRealityModeYandex24:
      SPDLOG_INFO("Selected strategy: Yandex 24");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_24_12_0_1772);
      break;
    default:
      SPDLOG_DEBUG("Using fallback handshake generator for SNI: {}", sni_);
      return utils::GenerateDecoyTlsHandshake(config_.sni);
  }

  const auto session_id = utils::GenerateDecoyTlsSessionId2();
  if (!session_id.has_value()) {
    SPDLOG_WARN("Session ID generation failed");
    return utils::GenerateDecoyTlsHandshake(config_.sni);
  }

  const auto handshake =
      builder.SetSNI(config_.sni).SetSessionId(session_id.value()).Generate();
  if (!handshake.has_value()) {
    SPDLOG_WARN(
        "Handshake generation failed for SNI: {}, using fallback", config_.sni);
    return utils::GenerateDecoyTlsHandshake(config_.sni);
  }

  SPDLOG_INFO("Handshake generated: SNI={}, size={} bytes", config_.sni,
      handshake->handshake_packet_size);

  return std::vector<std::uint8_t>(handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size);
}

}  // namespace fptn::protocol::https
