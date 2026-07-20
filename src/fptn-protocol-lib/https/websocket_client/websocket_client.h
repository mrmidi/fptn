/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protocol/protobuf/protobuf_serializer.h"

// PR1B: iOS-specific queue and batch caps. Other platforms keep the
// existing 256-packet channel bound with no byte limit.
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

namespace fptn::protocol::https {

// PR1B: typed send result for the outbound queue.
enum class SendResult : std::uint8_t {
  accepted = 0,
  queue_full = 1,
  transport_stopped = 2,
  invalid_packet = 3,
};

#if defined(__APPLE__) && TARGET_OS_IOS
inline constexpr std::uint64_t kMaxQueuedBytes = 256 * 1024;
inline constexpr std::size_t kMaxBatchRawBytes = 64 * 1024;
#else
inline constexpr std::uint64_t kMaxQueuedBytes =
    std::numeric_limits<std::uint64_t>::max();
inline constexpr std::size_t kMaxBatchRawBytes =
    std::numeric_limits<std::size_t>::max();
#endif

using fptn::common::network::IPPacketPtr;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

using OnIPRecvPacketCallback = std::function<void(IPPacketPtr packet)>;

using OnConnectedCallback = std::function<void()>;

using OnIPAssignedCallback =
std::function<void(const IPv4Address& ipv4, const IPv6Address& ipv6)>;

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
 public:
  struct Config {
    IPv4Address server_ip;
    int server_port;

    IPv4Address tun_interface_address_ipv4;
    IPv6Address tun_interface_address_ipv6;

    std::string sni;
    std::string access_token;
    std::string expected_md5_fingerprint;
    CensorshipStrategy censorship_strategy;
    OnConnectedCallback on_connected_callback;
    OnIPRecvPacketCallback new_ip_pkt_callback;
  };

  // PR1A: renamed from thread_number. This is an io_context concurrency
  // hint, not a thread count — the wrapper runs the context from one
  // native thread regardless of this value.
  explicit WebsocketClient(Config config, int concurrency_hint = 1);

  virtual ~WebsocketClient();

  WebsocketClient(const WebsocketClient&) = delete;
  WebsocketClient& operator=(const WebsocketClient&) = delete;
  WebsocketClient(WebsocketClient&&) = delete;
  WebsocketClient& operator=(WebsocketClient&&) = delete;

  void Run();
  bool Stop();
  // PR1B: typed send result replaces the previous bool return.
  SendResult Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted() const;

  // PR1A: read-only numeric diagnostics for the wrapper layer.
  int GetEffectiveRcvbufBytes() const noexcept { return effective_rcvbuf_bytes_.load(std::memory_order_relaxed); }
  int GetEffectiveSndbufBytes() const noexcept { return effective_sndbuf_bytes_.load(std::memory_order_relaxed); }
  int GetRequestedRcvbufBytes() const noexcept { return requested_rcvbuf_bytes_.load(std::memory_order_relaxed); }
  int GetRequestedSndbufBytes() const noexcept { return requested_sndbuf_bytes_.load(std::memory_order_relaxed); }
  int GetSocketBufferSetErrorCount() const noexcept { return socket_buffer_set_error_count_.load(std::memory_order_relaxed); }
  static int GetLiveClients() { return live_clients_.load(std::memory_order_relaxed); }
  static int GetActiveReaderCoroutines() { return active_reader_coroutines_.load(std::memory_order_relaxed); }
  static int GetActiveSenderCoroutines() { return active_sender_coroutines_.load(std::memory_order_relaxed); }
  // PR1B: outbound queue diagnostics.
  std::uint64_t GetQueuedPackets() const noexcept { return queued_packets_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueuedBytes() const noexcept { return queued_bytes_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueuedBytesPeak() const noexcept { return queued_bytes_peak_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueueFullCount() const noexcept { return queue_full_count_.load(std::memory_order_relaxed); }

 protected:
  boost::asio::awaitable<bool> RunInternal();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  boost::asio::awaitable<bool> Connect();
  boost::asio::awaitable<bool> ReceiveIPAssignment();

  boost::asio::awaitable<bool> PerformFakeHandshake2();

  void StartWatchdog();

  std::vector<std::uint8_t> GenerateHandshakePacket() const;

 private:
  // PR1A: process-wide lifecycle counters. Per-client counters cannot
  // detect an old client still running after replacement; these can.
  static std::atomic<int> live_clients_;
  static std::atomic<int> active_reader_coroutines_;
  static std::atomic<int> active_sender_coroutines_;

  // PR1A: RAII guard for coroutine counters. Handles normal returns,
  // exceptions, and co_return paths uniformly.
  class AtomicActivityGuard {
   public:
    explicit AtomicActivityGuard(std::atomic<int>& counter)
        : counter_(counter) {
      counter_.fetch_add(1, std::memory_order_relaxed);
    }
    ~AtomicActivityGuard() {
      counter_.fetch_sub(1, std::memory_order_relaxed);
    }
    AtomicActivityGuard(const AtomicActivityGuard&) = delete;
    AtomicActivityGuard& operator=(const AtomicActivityGuard&) = delete;

   private:
    std::atomic<int>& counter_;
  };

  const std::size_t kMaxSizeOutQueue_ = 256;

  mutable std::mutex mutex_;
  std::atomic<bool> running_{false};
  std::atomic<bool> was_stopped_{false};
  std::atomic<bool> was_inited_{false};
  std::atomic<bool> was_connected_{false};
  std::atomic<bool> ip_assigned_{false};

  // PR1A: socket buffer diagnostics. Requested = what the build asked for
  // (0 = kernel default). Effective = what get_option reports after
  // connect. Failure to set or query stores 0; never fails the tunnel.
  // Atomic because Connect() writes on the native thread while
  // getStatus() may read from another queue.
  std::atomic<int> requested_rcvbuf_bytes_{0};
  std::atomic<int> requested_sndbuf_bytes_{0};
  std::atomic<int> effective_rcvbuf_bytes_{0};
  std::atomic<int> effective_sndbuf_bytes_{0};
  std::atomic<int> socket_buffer_set_error_count_{0};

  // PR1B: outbound queue byte accounting. Unsigned lifetime/gauge
  // counters — never reset in Stop(). A new client starts at zero.
  // PR1C will verify gauges reach zero after all coroutines complete.
  std::atomic<std::uint64_t> queued_packets_{0};
  std::atomic<std::uint64_t> queued_bytes_{0};
  std::atomic<std::uint64_t> queued_bytes_peak_{0};
  std::atomic<std::uint64_t> queue_full_count_{0};

  // PR1B: overflow-safe CAS reservation. Returns the new total on
  // success, nullopt if the byte cap would be exceeded.
  std::optional<std::uint64_t> tryReserveQueuedBytes(
      std::uint64_t packet_size) noexcept;
  void updateQueuedBytesPeak(std::uint64_t new_total) noexcept;
  // Release accounting for a dequeued packet. Must be called before
  // IP-version validation so discarded packets still release bytes.
  void releaseDequeuedPacketAccounting(const IPPacketPtr& packet) noexcept;

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::asio::steady_timer watchdog_timer_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;

  websocket_type ws_;

  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;

  boost::asio::cancellation_signal cancel_signal_;
  obfuscator::IObfuscatorSPtr obfuscator_;

  const Config config_;

  IPv4Address assigned_ipv4_;
  IPv6Address assigned_ipv6_;
};

using WebsocketClientSPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
