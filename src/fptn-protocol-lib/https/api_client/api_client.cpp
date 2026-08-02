/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/api_client/api_client.h"

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#include <zlib.h>           // NOLINT(build/include_order)

#include "common/network/utils.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 4702)
#endif

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <camouflage/tls/builder.hpp>

#include "fptn-protocol-lib/https/io_runtime/io_runtime.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/change_cipher_spec.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"

#ifdef _WIN32
#pragma warning(pop)
#endif

namespace {

/*
bool IsPortOpen(const std::string& host, const int port) {
  try {
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    socket.open(boost::asio::ip::tcp::v4());

    const auto native = socket.native_handle();
#ifdef _WIN32
    DWORD timeout_ms = 700;
    ::setsockopt(native, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 700000;
    ::setsockopt(native, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    boost::asio::ip::tcp::endpoint endpoint;
    boost::system::error_code addr_ec;
    const auto addr = boost::asio::ip::make_address(host, addr_ec);
    if (!addr_ec) {
      endpoint = boost::asio::ip::tcp::endpoint(
          addr, static_cast<boost::asio::ip::port_type>(port));
    } else {
      boost::asio::ip::tcp::resolver resolver(ioc);
      const auto results = resolver.resolve(host, std::to_string(port));
      endpoint = *results.begin();
    }

    boost::system::error_code ec;
    socket.connect(endpoint, ec);
    if (socket.is_open()) {
      socket.close();
    }
    return !ec;
  } catch (...) {
    return false;
  }
}
*/

std::string DecompressGzip(const std::string& compressed) {
  constexpr std::size_t kChunkSize = 4096;

  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
  strm.avail_in = static_cast<unsigned int>(compressed.size());

  if (::inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    return {};
  }

  std::string decompressed;
  int ret = 0;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
    strm.avail_out = static_cast<unsigned int>(buffer.size());
    ret = inflate(&strm, Z_NO_FLUSH);

    if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      inflateEnd(&strm);
      return {};
    }
    decompressed.append(buffer.data(), buffer.size() - strm.avail_out);
  } while (ret != Z_STREAM_END);

  inflateEnd(&strm);
  return decompressed;
}

std::string GetHttpBody(
    const boost::beast::http::response<boost::beast::http::dynamic_body>& res) {
  auto body = boost::beast::buffers_to_string(res.body().data());
  if (res[boost::beast::http::field::content_encoding] == "gzip") {
    return DecompressGzip(body);
  }
  return body;
}

using Headers = std::unordered_map<std::string, std::string>;

Headers RealBrowserHeaders() {
  /* Just to ensure that FPTN is as similar to a web browser as possible. */
#ifdef __linux__  // chromium ubuntu arm
  return {{"User-Agent",
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/134.0.0.0 Safari/537.36"},
      {"Accept-Language", "en-US,en;q=0.9"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Sec-Ch-Ua", R"("Not:A-Brand";v="24", "Chromium";v="134")"},
      {"Sec-Ch-Ua-Mobile", "?0"}, {"Sec-Ch-Ua-Platform", R"("Linux")"},
      {"Upgrade-Insecure-Requests", "1"}, {"Sec-Fetch-Site", "cross-site"},
      {"Sec-Fetch-Mode", "navigate"}, {"Sec-Fetch-User", "?1"},
      {"Sec-Fetch-Dest", "document"}, {"Priority", "u=0, i"}};
#elif __APPLE__
  // apple silicon chrome
  return {
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-platform", "\"macOS\""}, {"sec-ch-ua-mobile", "?0"},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "none"}, {"sec-fetch-mode", "no-cors"},
      {"sec-fetch-dest", "empty"}, {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br"},
      {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
      {"priority", "u=4, i"}};
#elif _WIN32
  // chrome windows amd64
  return {
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-mobile", "?0"}, {"sec-ch-ua-platform", "\"Windows\""},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "cross-site"}, {"sec-fetch-mode", "navigate"},
      {"sec-fetch-user", "?1"}, {"sec-fetch-dest", "document"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"}, {"priority", "u=0, i"}};
#else
#error Undefined platform
#endif
}


std::string CleanErrorMessage(const std::string& msg) {
  auto pos = msg.find(" [system:");
  if (pos != std::string::npos) {
    return msg.substr(0, pos);
  }
  pos = msg.find(" at /");
  if (pos != std::string::npos) {
    return msg.substr(0, pos);
  }
  return msg;
}

};  // namespace

namespace fptn::protocol::https {

using tcp_stream_type = boost::beast::tcp_stream;
using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;

ApiClient::ApiClient(
    const std::string& host, int port, CensorshipStrategy censorship_strategy)
    : host_(host),
      port_(port),
      sni_(host),
      censorship_strategy_(censorship_strategy),
      cancellation_(std::make_shared<CancellationState>()) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    CensorshipStrategy censorship_strategy)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      censorship_strategy_(censorship_strategy),
      cancellation_(std::make_shared<CancellationState>()) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    std::string md5_fingerprint,
    CensorshipStrategy censorship_strategy,
    std::string server_name)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      expected_md5_fingerprint_(std::move(md5_fingerprint)),
      censorship_strategy_(censorship_strategy),
      server_name_(std::move(server_name)),
      cancellation_(std::make_shared<CancellationState>()) {}  // NOLINT

std::string ApiClient::ServerLogName() const {
  if (server_name_.empty()) {
    return fmt::format("{}:{}", host_, port_);
  }
  return fmt::format("{} ({}:{})", server_name_, host_, port_);
}

std::string ApiClient::ServerLogHost() const {
  if (server_name_.empty()) {
    return host_;
  }
  return fmt::format("{} ({})", server_name_, host_);
}


namespace {

// Remaining slice of a single overall deadline. Passing the whole timeout to
// every step would make the worst case N * timeout.
std::chrono::steady_clock::duration Remaining(
    std::chrono::steady_clock::time_point deadline) {
  const auto now = std::chrono::steady_clock::now();
  return deadline > now ? (deadline - now)
                        : std::chrono::steady_clock::duration::zero();
}

}  // namespace

// Owns the whole asio stack for one request. Declaration order matters: `ctx`
// must outlive `stream`, which holds a reference to it.
struct ApiClient::Connection {
  boost::asio::ssl::context ctx;
  ssl_stream_type stream;
  SSL* ssl = nullptr;
  std::string server_ip;

  Connection(const boost::asio::any_io_executor& executor,
      SSL_CTX* ssl_ctx,
      obfuscator::IObfuscatorSPtr obfuscator)
      : ctx(ssl_ctx),
        stream(obfuscator_socket_type(
                   tcp_stream_type(executor), std::move(obfuscator)),
            ctx) {}

  boost::asio::ip::tcp::socket& socket() {
    return boost::beast::get_lowest_layer(stream).socket();
  }
};

boost::asio::awaitable<bool> ApiClient::PerformFakeHandshake(
    boost::asio::ip::tcp::socket& socket, Deadline deadline) const {
  try {
    SPDLOG_INFO("Fake TLS handshake started for SNI: {}", sni_);

    const auto client_hello = GenerateHandshakePacket();
    if (client_hello.empty()) {
      SPDLOG_WARN("Failed to generate ClientHello for SNI: {}", sni_);
      co_return false;
    }

    boost::system::error_code ec;
    const std::size_t client_hello_bytes_size =
        co_await boost::asio::async_write(socket,
            boost::asio::buffer(client_hello),
            boost::asio::cancel_after(Remaining(deadline),
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
    if (ec || client_hello_bytes_size != client_hello.size()) {
      SPDLOG_ERROR("Error ClientHello sent: {} of {} bytes",
          client_hello_bytes_size, client_hello.size());
      co_return false;
    }

    const auto server_hello =
        co_await common::network::WaitForServerTlsHelloAsync(
            socket, std::chrono::milliseconds(1500));
    if (!server_hello.has_value()) {
      SPDLOG_ERROR("Failed to receive ServerHello from {}", sni_);
      co_return false;
    }

    common::network::CleanSocket(socket);

    const auto change_cipher_spec =
        fptn::protocol::https::utils::MakeClientChangeCipherSpec();
    const std::size_t change_cipher_spec_size =
        co_await boost::asio::async_write(socket,
            boost::asio::buffer(change_cipher_spec),
            boost::asio::cancel_after(Remaining(deadline),
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
    if (ec || change_cipher_spec_size != change_cipher_spec.size()) {
      SPDLOG_ERROR("Failed to send ChangeCipherSpec to {}: {} of {}", sni_,
          change_cipher_spec_size, change_cipher_spec.size());
      co_return false;
    }

    // Same pacing as the blocking path used, without occupying a thread.
    boost::asio::steady_timer pacer(co_await boost::asio::this_coro::executor);
    pacer.expires_after(std::chrono::milliseconds(150));
    co_await pacer.async_wait(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    SPDLOG_INFO(
        "Fake TLS handshake completed for {}, received {} bytes from server",
        sni_, server_hello.value().size());
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Fake TLS handshake exception for {}: {}", sni_, e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> ApiClient::EstablishAsync(Connection& conn,
    const std::string& log_tag,
    Deadline deadline,
    std::string& error,
    int& respcode) const {
  boost::system::error_code ec;
  const auto executor = co_await boost::asio::this_coro::executor;

  boost::asio::ip::tcp::resolver resolver(executor);
  const auto endpoints = co_await resolver.async_resolve(host_,
      std::to_string(port_),
      boost::asio::cancel_after(Remaining(deadline),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  if (ec) {
    error = CleanErrorMessage(ec.message());
    respcode = 603;
    SPDLOG_ERROR("{} - DNS resolution failed for {}: {}", log_tag,
        ServerLogName(), error);
    co_return false;
  }

  SPDLOG_INFO("{} - Connecting to server: {} [strategy={}]", log_tag,
      ServerLogName(), ToString(censorship_strategy_));

  const auto endpoint = co_await boost::asio::async_connect(conn.socket(),
      endpoints,
      boost::asio::cancel_after(Remaining(deadline),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  if (ec) {
    error = CleanErrorMessage(ec.message());
    respcode = 600;
    SPDLOG_ERROR(
        "{} - Connect failed for {}: {}", log_tag, ServerLogHost(), error);
    co_return false;
  }
  conn.server_ip = endpoint.address().to_string();

  SPDLOG_INFO("{} - Successfully connected to {}", log_tag, ServerLogHost());

  if (IsRealityModeWithFakeHandshake(censorship_strategy_)) {
    if (!co_await PerformFakeHandshake(conn.socket(), deadline)) {
      error = "Fake handshake failed";
      respcode = 600;
      SPDLOG_ERROR(
          "{} - Fake handshake failed for server {}", log_tag, ServerLogHost());
      co_return false;
    }
    // For Reality Mode we use TLS obfuscator after fake handshake.
    // This provides an additional encryption layer for the real connection.
    conn.stream.next_layer().set_obfuscator(
        std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
  }

  utils::SetHandshakeSessionID(conn.stream.native_handle());
  utils::SetHandshakeSni(conn.stream.native_handle(), sni_);
  if (!expected_md5_fingerprint_.empty()) {
    conn.ssl = conn.stream.native_handle();
    utils::AttachCertificateVerificationCallback(
        conn.ssl, [this, &error](const std::string& md5_fingerprint) {
          return onVerifyCertificate(md5_fingerprint, error);
        });
  } else {
    conn.ctx.set_verify_mode(boost::asio::ssl::verify_none);
  }

  co_await conn.stream.async_handshake(boost::asio::ssl::stream_base::client,
      boost::asio::cancel_after(Remaining(deadline),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  if (ec) {
    if (error.empty()) {
      error = CleanErrorMessage(ec.message());
    }
    respcode = 600;
    SPDLOG_ERROR("{} - TLS handshake failed for {}: {}", log_tag,
        ServerLogHost(), error);
    co_return false;
  }

  // Reset obfuscator after TLS handshake.
  conn.stream.next_layer().set_obfuscator(nullptr);

  common::network::CleanSocket(conn.socket());
  common::network::CleanSsl(conn.ssl);

  boost::asio::steady_timer pacer(executor);
  pacer.expires_after(std::chrono::milliseconds(150));
  co_await pacer.async_wait(
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  co_return true;
}

boost::asio::awaitable<Response> ApiClient::AsyncGet(
    const std::string& handle, int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  const Deadline deadline = start_time + std::chrono::seconds(timeout);
  const std::string log_tag = fmt::format("GET [{}]", handle);

  std::string body;
  std::string error;
  int respcode = 400;
  std::string server_ip;

  try {
    obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator = std::make_shared<obfuscator::TlsObfuscator2>();
    }
    Connection conn(co_await boost::asio::this_coro::executor,
        utils::CreateNewSslCtx(), std::move(obfuscator));

    if (co_await EstablishAsync(conn, log_tag, deadline, error, respcode)) {
      server_ip = conn.server_ip;
      boost::system::error_code ec;

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::get, handle, 11};
      req.set(boost::beast::http::field::host, host_);
      for (const auto& [key, value] : RealBrowserHeaders()) {
        req.set(key, value);
      }

      co_await boost::beast::http::async_write(conn.stream, req,
          boost::asio::cancel_after(Remaining(deadline),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
      if (ec) {
        error = CleanErrorMessage(ec.message());
        respcode = 600;
      } else {
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        co_await boost::beast::http::async_read(conn.stream, buffer, res,
            boost::asio::cancel_after(Remaining(deadline),
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
        if (ec) {
          error = CleanErrorMessage(ec.message());
          respcode = 600;
        } else {
          respcode = static_cast<int>(res.result_int());
          body = GetHttpBody(res);
        }
      }

      // Must not be the blocking shutdown(): it waits for the peer's
      // close_notify, which parks a shared I/O thread when the peer never
      // answers. Bounded and asynchronous so a slow peer costs nothing.
      boost::system::error_code shutdown_ec;
      co_await conn.stream.async_shutdown(
          boost::asio::cancel_after(std::chrono::seconds(2),
              boost::asio::redirect_error(
                  boost::asio::use_awaitable, shutdown_ec)));
    } else {
      server_ip = conn.server_ip;
    }

    if (conn.ssl) {
      utils::AttachCertificateVerificationCallbackDelete(conn.ssl);
    }
  } catch (const boost::system::system_error& err) {
    error = CleanErrorMessage(err.what());
    respcode = 600;
    SPDLOG_ERROR("{} - System error for server {} (IP: {}): {}", log_tag,
        ServerLogHost(), server_ip, error);
  } catch (const std::exception& e) {
    error = CleanErrorMessage(e.what());
    respcode = 601;
    SPDLOG_ERROR("{} - Exception for server {} (IP: {}): {}", log_tag,
        ServerLogHost(), server_ip, error);
  }

  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_time);
  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "{} - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Body size: {} bytes",
        log_tag, ServerLogHost(), server_ip, duration.count(), respcode,
        body.size());
  } else {
    SPDLOG_WARN(
        "{} - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Body size: {} bytes",
        log_tag, ServerLogHost(), server_ip, duration.count(), respcode, error,
        body.size());
  }
  co_return Response{body, respcode, error};
}

boost::asio::awaitable<Response> ApiClient::AsyncPost(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  const Deadline deadline = start_time + std::chrono::seconds(timeout);
  const std::string log_tag = fmt::format("POST [{}]", handle);

  std::string body;
  std::string error;
  int respcode = 400;
  std::string server_ip;

  try {
    obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator = std::make_shared<obfuscator::TlsObfuscator2>();
    }
    Connection conn(co_await boost::asio::this_coro::executor,
        utils::CreateNewSslCtx(), std::move(obfuscator));

    if (co_await EstablishAsync(conn, log_tag, deadline, error, respcode)) {
      server_ip = conn.server_ip;
      boost::system::error_code ec;

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::post, handle, 11};
      req.set(boost::beast::http::field::host, host_);
      req.set(boost::beast::http::field::accept, "*/*");
      req.set(boost::beast::http::field::content_type, content_type);
      req.set(boost::beast::http::field::content_length,
          std::to_string(request.size()));
      for (const auto& [key, value] : RealBrowserHeaders()) {
        req.set(key, value);
      }
      req.body() = request;
      req.prepare_payload();

      co_await boost::beast::http::async_write(conn.stream, req,
          boost::asio::cancel_after(Remaining(deadline),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
      if (ec) {
        error = CleanErrorMessage(ec.message());
        respcode = 600;
      } else {
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        co_await boost::beast::http::async_read(conn.stream, buffer, res,
            boost::asio::cancel_after(Remaining(deadline),
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
        if (ec) {
          error = CleanErrorMessage(ec.message());
          respcode = 600;
        } else {
          respcode = static_cast<int>(res.result_int());
          body = GetHttpBody(res);
        }
      }

      // Must not be the blocking shutdown(): it waits for the peer's
      // close_notify, which parks a shared I/O thread when the peer never
      // answers. Bounded and asynchronous so a slow peer costs nothing.
      boost::system::error_code shutdown_ec;
      co_await conn.stream.async_shutdown(
          boost::asio::cancel_after(std::chrono::seconds(2),
              boost::asio::redirect_error(
                  boost::asio::use_awaitable, shutdown_ec)));
    } else {
      server_ip = conn.server_ip;
    }

    if (conn.ssl) {
      utils::AttachCertificateVerificationCallbackDelete(conn.ssl);
    }
  } catch (const boost::system::system_error& err) {
    error = CleanErrorMessage(err.what());
    respcode = 600;
    SPDLOG_ERROR("{} - System error for server {} (IP: {}): {}", log_tag,
        ServerLogHost(), server_ip, error);
  } catch (const std::exception& e) {
    error = CleanErrorMessage(e.what());
    respcode = 601;
    SPDLOG_ERROR("{} - Exception for server {} (IP: {}): {}", log_tag,
        ServerLogHost(), server_ip, error);
  }

  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_time);
  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "{} - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Request: {} bytes, Response: {} bytes",
        log_tag, ServerLogHost(), server_ip, duration.count(), respcode,
        request.size(), body.size());
  } else {
    SPDLOG_WARN(
        "{} - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Request: {} bytes, Response: {} bytes",
        log_tag, ServerLogHost(), server_ip, duration.count(), respcode, error,
        request.size(), body.size());
  }
  co_return Response{body, respcode, error};
}

boost::asio::awaitable<bool> ApiClient::AsyncTestHandshake(int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  const Deadline deadline = start_time + std::chrono::seconds(timeout);
  const std::string log_tag = "TestHandshake";

  std::string error;
  int respcode = 400;
  bool ok = false;
  std::string server_ip;

  try {
    obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator = std::make_shared<obfuscator::TlsObfuscator2>();
    }
    Connection conn(co_await boost::asio::this_coro::executor,
        utils::CreateNewSslCtx(), std::move(obfuscator));

    ok = co_await EstablishAsync(conn, log_tag, deadline, error, respcode);
    server_ip = conn.server_ip;

    if (ok) {
      // Must not be the blocking shutdown(): it waits for the peer's
      // close_notify, which parks a shared I/O thread when the peer never
      // answers. Bounded and asynchronous so a slow peer costs nothing.
      boost::system::error_code shutdown_ec;
      co_await conn.stream.async_shutdown(
          boost::asio::cancel_after(std::chrono::seconds(2),
              boost::asio::redirect_error(
                  boost::asio::use_awaitable, shutdown_ec)));
    }
    if (conn.ssl) {
      utils::AttachCertificateVerificationCallbackDelete(conn.ssl);
    }
  } catch (const std::exception& e) {
    error = CleanErrorMessage(e.what());
    SPDLOG_WARN("Handshake failed for server {} (IP: {}): {}", ServerLogHost(),
        server_ip, error);
    ok = false;
  }

  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_time);
  if (ok) {
    SPDLOG_INFO("Handshake successful for server {} (IP: {}) in {} ms",
        ServerLogHost(), server_ip, duration.count());
  } else {
    SPDLOG_WARN("Handshake failed for server {} (IP: {}) in {} ms - {}",
        ServerLogHost(), server_ip, duration.count(), error);
  }
  co_return ok;
}

void ApiClient::BeginOperation(
    const boost::asio::strand<boost::asio::io_context::executor_type>& strand,
    const std::shared_ptr<boost::asio::cancellation_signal>& signal) const {
  const std::scoped_lock lock(cancellation_->mutex);
  cancellation_->strand = strand;
  cancellation_->signal = signal;
}

void ApiClient::EndOperation() const {
  const std::scoped_lock lock(cancellation_->mutex);
  cancellation_->strand.reset();
  cancellation_->signal.reset();
}

void ApiClient::Cancel() const {
  std::shared_ptr<boost::asio::cancellation_signal> signal;
  std::optional<boost::asio::strand<boost::asio::io_context::executor_type>>
      strand;
  {
    const std::scoped_lock lock(cancellation_->mutex);
    signal = cancellation_->signal;
    strand = cancellation_->strand;
  }
  if (!signal || !strand) {
    return;
  }
  // Emitted on the operation's own strand, so it is serialised with that
  // operation's I/O instead of racing it from another thread.
  boost::asio::post(*strand, [signal] {
    signal->emit(boost::asio::cancellation_type::terminal);
  });
}

// --- Blocking adapters -------------------------------------------------
// Kept for fptn-client and fptn-server, which are synchronous. They spawn the
// coroutine on the shared runtime and wait; no per-request thread is created.

Response ApiClient::Get(const std::string& handle, int timeout) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  auto future = boost::asio::co_spawn(strand, AsyncGet(handle, timeout),
      boost::asio::bind_cancellation_slot(
          signal->slot(), boost::asio::use_future));
  Response response;
  try {
    response = future.get();
  } catch (const std::exception& e) {
    response = Response{"", 601, CleanErrorMessage(e.what())};
  }
  EndOperation();
  return response;
}

Response ApiClient::Post(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  auto future = boost::asio::co_spawn(strand,
      AsyncPost(handle, request, content_type, timeout),
      boost::asio::bind_cancellation_slot(
          signal->slot(), boost::asio::use_future));
  Response response;
  try {
    response = future.get();
  } catch (const std::exception& e) {
    response = Response{"", 601, CleanErrorMessage(e.what())};
  }
  EndOperation();
  return response;
}

bool ApiClient::TestHandshake(int timeout) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  auto future = boost::asio::co_spawn(strand, AsyncTestHandshake(timeout),
      boost::asio::bind_cancellation_slot(
          signal->slot(), boost::asio::use_future));
  bool result = false;
  try {
    result = future.get();
  } catch (const std::exception& e) {
    SPDLOG_WARN("TestHandshake - failed for {}: {}", ServerLogHost(), e.what());
  }
  EndOperation();
  return result;
}

// --- Fire-and-forget adapters ------------------------------------------
// The coroutine is wrapped in a lambda that owns a *copy* of this client, so
// asio keeps it alive for the whole operation. Spawning `AsyncPost(...)`
// directly would bind the coroutine to `this`, which the caller is free to
// destroy the moment these functions return.

void ApiClient::SpawnGet(const std::string& handle,
    int timeout,
    std::function<void(Response)> completion) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  boost::asio::co_spawn(strand,
      [self = *this, handle, timeout]() -> boost::asio::awaitable<Response> {
        co_return co_await self.AsyncGet(handle, timeout);
      },
      boost::asio::bind_cancellation_slot(signal->slot(),
          [self = *this, completion = std::move(completion)](
              std::exception_ptr eptr, Response response) {
            self.EndOperation();
            if (eptr) {
              completion(Response{"", 601, "operation failed"});
              return;
            }
            completion(std::move(response));
          }));
}

void ApiClient::SpawnPost(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout,
    std::function<void(Response)> completion) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  boost::asio::co_spawn(strand,
      [self = *this, handle, request, content_type,
          timeout]() -> boost::asio::awaitable<Response> {
        co_return co_await self.AsyncPost(
            handle, request, content_type, timeout);
      },
      boost::asio::bind_cancellation_slot(signal->slot(),
          [self = *this, completion = std::move(completion)](
              std::exception_ptr eptr, Response response) {
            self.EndOperation();
            if (eptr) {
              completion(Response{"", 601, "operation failed"});
              return;
            }
            completion(std::move(response));
          }));
}

void ApiClient::SpawnTestHandshake(
    int timeout, std::function<void(bool)> completion) const {
  auto strand = boost::asio::make_strand(IoRuntime::Instance().Context());
  auto signal = std::make_shared<boost::asio::cancellation_signal>();
  BeginOperation(strand, signal);

  boost::asio::co_spawn(strand,
      [self = *this, timeout]() -> boost::asio::awaitable<bool> {
        co_return co_await self.AsyncTestHandshake(timeout);
      },
      boost::asio::bind_cancellation_slot(signal->slot(),
          [self = *this, completion = std::move(completion)](
              std::exception_ptr eptr, bool ok) {
            self.EndOperation();
            completion(eptr ? false : ok);
          }));
}

ApiClient ApiClient::Clone() const {
  ApiClient temp_client(
      host_, port_, sni_, expected_md5_fingerprint_, censorship_strategy_);
  return temp_client;
}


bool ApiClient::onVerifyCertificate(
    const std::string& md5_fingerprint, std::string& error) const {
  if (expected_md5_fingerprint_.empty()) {
    return true;
  }
  if (md5_fingerprint == expected_md5_fingerprint_) {
    return true;
  }
  error = "Probably outdated token";
  SPDLOG_ERROR(
      "Certificate verification failed for server {}: {}", ServerLogHost(), error);
  return false;
}

std::vector<std::uint8_t> ApiClient::GenerateHandshakePacket() const {
  auto builder = camouflage::tls::Builder::Create();

  switch (censorship_strategy_) {
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
      return utils::GenerateDecoyTlsHandshake(sni_);
  }

  SPDLOG_INFO("Generating handshake for SNI: {}", sni_);

  const auto session_id = utils::GenerateDecoyTlsSessionId2();
  if (!session_id.has_value()) {
    SPDLOG_WARN("Session ID generation failed for handshake, using fallback");
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  const auto handshake =
      builder.SetSNI(sni_).SetSessionId(session_id.value()).Generate();
  if (!handshake.has_value()) {
    SPDLOG_WARN(
        "Handshake generation failed for SNI: {}, using fallback", sni_);
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  SPDLOG_INFO("Handshake generated: SNI={}, size={} bytes", sni_,
      handshake->handshake_packet_size);
  return std::vector<std::uint8_t>(handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size);
}
}  // namespace fptn::protocol::https
