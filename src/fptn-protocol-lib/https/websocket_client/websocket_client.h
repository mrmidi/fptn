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

struct PacketCopyCounters {
  std::uint64_t outbound_admission_copy_operations{0};
  std::uint64_t outbound_admission_copy_bytes{0};
  std::uint64_t outbound_rejected_before_copy_packets{0};
  std::uint64_t outbound_rejected_before_copy_bytes{0};
  std::uint64_t outbound_copied_but_rejected_packets{0};
  std::uint64_t outbound_copied_but_rejected_bytes{0};
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

inline constexpr std::size_t kMaxInboundBatchPackets = 32;
inline constexpr std::size_t kMaxInboundBatchRawBytes = 64 * 1024;
inline constexpr std::size_t kMaxInboundPacketBytes = 64 * 1024;

// PR6: inbound in-flight backpressure watermarks. On iOS the parsed native
// IPPackets are leased to Swift zero-copy and stay alive until packetFlow
// drains them; under a fast download the reader can outrun packetFlow and pile
// up leases until jetsam. RunReader stops issuing reads while the leased-but-
// undrained byte count is at/above the high-water mark and resumes once it
// falls below the low-water mark, so TCP flow control throttles the server.
// Only active when Config::inbound_inflight_bytes is set (iOS bridge).
inline constexpr std::size_t kInboundInflightHighWaterBytes = 2 * 1024 * 1024;
inline constexpr std::size_t kInboundInflightLowWaterBytes = 1 * 1024 * 1024;

// PR1C: numeric disconnect diagnostics. Explicit ABI values so C++
// and Swift raw values match exactly.
enum class DisconnectCode : std::uint16_t {
  none = 0,
  peer_closed = 1,
  tcp_error = 2,
  tls_error = 3,
  websocket_error = 4,
  watchdog = 5,
  local_stop = 6,
  queue_failure = 7,
  unknown = 255,
};

enum class StopOrigin : std::uint16_t {
  none = 0,
  swift_tunnel_stop = 1,
  swift_reconnect = 2,
  native_failure = 3,
  peer = 4,
  unknown = 255,
};

// PR1C: pack code + origin into one uint32 for atomic first-writer-wins.
constexpr std::uint32_t packTerminalReason(
    DisconnectCode code, StopOrigin origin) noexcept {
  return std::uint32_t(code) | (std::uint32_t(origin) << 16);
}

constexpr DisconnectCode unpackDisconnectCode(std::uint32_t packed) noexcept {
  return DisconnectCode(packed & 0xFFFF);
}

constexpr StopOrigin unpackStopOrigin(std::uint32_t packed) noexcept {
  return StopOrigin(packed >> 16);
}

using fptn::common::network::IPPacketPtr;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

using OnIPRecvPacketCallback = std::function<void(IPPacketPtr packet)>;
using OnIPRecvPacketBatchCallback =
    std::function<void(fptn::common::network::BatchIPPacketPtr packets)>;

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
    // iOS bridge uses this ownership-preserving callback. The single-packet
    // callback remains for non-iOS clients that do not use the Swift bridge.
    OnIPRecvPacketBatchCallback new_ip_pkt_batch_callback;
    // PR6: optional inbound backpressure signal. When set, returns the current
    // count of leased-but-undrained inbound bytes so RunReader can pause before
    // packetFlow's queue grows without bound. Empty for non-iOS clients.
    std::function<std::size_t()> inbound_inflight_bytes;
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
  // PR1C: request an asynchronous stop. Posts teardown onto the strand;
  // does not touch Asio/Beast/SSL objects on the caller's thread.
  // Returns false if a terminal event was already claimed.
  bool RequestStop(DisconnectCode code, StopOrigin origin);
  // Convenience for external callers (wrapper).
  bool Stop(StopOrigin origin = StopOrigin::swift_tunnel_stop);
  // PR1B: typed send result replaces the previous bool return.
  SendResult Send(fptn::common::network::IPPacketPtr packet);
  // Validates and reserves bounded queue capacity before allocating/copying
  // the caller-owned bytes into native packet storage.
  SendResult TrySendPacketBytes(const std::uint8_t* bytes, std::size_t length);
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
  // PR1C: terminal reason diagnostics.
  std::uint32_t GetTerminalReason() const noexcept { return terminal_reason_.load(std::memory_order_acquire); }
  DisconnectCode GetDisconnectCode() const noexcept { return unpackDisconnectCode(GetTerminalReason()); }
  StopOrigin GetStopOrigin() const noexcept { return unpackStopOrigin(GetTerminalReason()); }
  bool IsStopCleanupCompleted() const noexcept { return stop_cleanup_completed_.load(std::memory_order_acquire); }
  std::uint32_t GetActiveOperations() const noexcept { return active_operations_.load(std::memory_order_acquire); }
  // PR1B: outbound queue diagnostics.
  std::uint64_t GetQueuedPackets() const noexcept { return queued_packets_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueuedBytes() const noexcept { return queued_bytes_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueuedBytesPeak() const noexcept { return queued_bytes_peak_.load(std::memory_order_relaxed); }
  std::uint64_t GetQueueFullCount() const noexcept { return queue_full_count_.load(std::memory_order_relaxed); }
  PacketCopyCounters GetPacketCopyCounters() const noexcept;

 protected:
  boost::asio::awaitable<bool> RunInternal();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  // PR1C: watchdog converted from recursive async_wait to tracked coroutine.
  boost::asio::awaitable<void> RunWatchdog();
  boost::asio::awaitable<bool> Connect();
  boost::asio::awaitable<bool> ReceiveIPAssignment();

  boost::asio::awaitable<bool> PerformFakeHandshake2();

  // PR1C: strand-only teardown. Only this method may touch
  // Asio/Beast/SSL objects during shutdown.
  void StopOnExecutor();

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

  // PR1C: operation-tracking barrier. Run() drives the io_context
  // until stop_cleanup_completed_ && active_operations_ == 0.
  std::atomic<bool> run_started_{false};
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> stop_cleanup_completed_{false};
  std::atomic<bool> stop_fallback_pending_{false};
  std::atomic<std::uint32_t> active_operations_{0};

  // PR1C: packed terminal reason (first-writer-wins via CAS).
  // Low 16 bits = DisconnectCode, high 16 bits = StopOrigin.
  // 0 = no terminal event yet.
  std::atomic<std::uint32_t> terminal_reason_{0};

  bool claimTerminalReason(DisconnectCode code, StopOrigin origin) noexcept {
    std::uint32_t expected = 0;
    return terminal_reason_.compare_exchange_strong(
        expected, packTerminalReason(code, origin),
        std::memory_order_acq_rel);
  }

  void trackOperation() noexcept {
    active_operations_.fetch_add(1, std::memory_order_relaxed);
  }

  void completeOperation() noexcept {
    active_operations_.fetch_sub(1, std::memory_order_release);
  }

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
  std::atomic<std::uint64_t> outbound_admission_copy_operations_{0};
  std::atomic<std::uint64_t> outbound_admission_copy_bytes_{0};
  std::atomic<std::uint64_t> outbound_rejected_before_copy_packets_{0};
  std::atomic<std::uint64_t> outbound_rejected_before_copy_bytes_{0};
  std::atomic<std::uint64_t> outbound_copied_but_rejected_packets_{0};
  std::atomic<std::uint64_t> outbound_copied_but_rejected_bytes_{0};

  // PR1B: overflow-safe CAS reservation. Returns the new total on
  // success, nullopt if the byte cap would be exceeded.
  std::optional<std::uint64_t> tryReserveQueuedBytes(
      std::uint64_t packet_size) noexcept;
  void updateQueuedBytesPeak(std::uint64_t new_total) noexcept;
  // Release accounting for a dequeued packet. Must be called before
  // IP-version validation so discarded packets still release bytes.
  void releaseDequeuedPacketAccounting(const IPPacketPtr& packet) noexcept;
  bool tryReserveQueuedPacket() noexcept;
  void releaseQueuedReservation(std::uint64_t packet_size) noexcept;
  SendResult enqueueReserved(IPPacketPtr packet, std::uint64_t packet_size) noexcept;

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
