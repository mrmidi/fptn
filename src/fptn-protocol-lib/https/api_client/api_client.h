/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>

#include "fptn-protocol-lib/https/censorship_strategy.h"

namespace fptn::protocol::https {

struct Response final {
  std::string body;
  int code;
  std::string errmsg;

  Response() : code(600) {}

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  Response(const Response& other)
      : body(other.body), code(other.code), errmsg(other.errmsg) {}

  Response& operator=(const Response& other) {
    if (this != &other) {
      this->~Response();
      new (this) Response(other);
    }
    return *this;
  }

  Response(Response&& other) = default;
  Response& operator=(Response&& other) = default;

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

class ApiClient {
 public:
  ApiClient(const std::string& host,
      int port,
      CensorshipStrategy censorship_strategy);

  ApiClient(std::string host,
      int port,
      std::string sni,
      CensorshipStrategy censorship_strategy);

  ApiClient(std::string host,
      int port,
      std::string sni,
      std::string md5_fingerprint,
      CensorshipStrategy censorship_strategy,
      std::string server_name = "");

  std::string ServerLogName() const;
  std::string ServerLogHost() const;

  // Blocking wrappers. Each spawns its coroutine on the shared IoRuntime and
  // waits for the result; no per-request thread is created.
  Response Get(const std::string& handle, int timeout = 5) const;
  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type = "application/json",
      int timeout = 5) const;
  bool TestHandshake(int timeout = 5) const;

  // Coroutine forms. Callers already running on an io_context should prefer
  // these; the blocking wrappers above are implemented in terms of them.
  boost::asio::awaitable<Response> AsyncGet(
      const std::string& handle, int timeout = 5) const;
  boost::asio::awaitable<Response> AsyncPost(const std::string& handle,
      const std::string& request,
      const std::string& content_type = "application/json",
      int timeout = 5) const;
  boost::asio::awaitable<bool> AsyncTestHandshake(int timeout = 5) const;

  // Fire-and-forget forms for callers that cannot block (the Swift bridge).
  // The coroutine runs on the shared runtime with cancellation registered, and
  // `completion` is invoked on an I/O thread when it finishes.
  //
  // These keep their own copy of the client alive for the duration, so the
  // caller is free to destroy this object as soon as the call returns.
  void SpawnGet(const std::string& handle,
      int timeout,
      std::function<void(Response)> completion) const;
  void SpawnPost(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout,
      std::function<void(Response)> completion) const;
  void SpawnTestHandshake(
      int timeout, std::function<void(bool)> completion) const;

  // Cancels the operation currently in flight, if any. The signal is emitted
  // on the operation's own strand, so it is serialised with that operation's
  // I/O rather than racing it.
  void Cancel() const;

 protected:
  ApiClient Clone() const;

  bool onVerifyCertificate(
      const std::string& md5_fingerprint, std::string& error) const;

  std::vector<std::uint8_t> GenerateHandshakePacket() const;

 private:
  using Deadline = std::chrono::steady_clock::time_point;

  // Forward-declared so the boost::beast stream aliases stay in the .cpp.
  struct Connection;

  // DNS, TCP connect, optional Reality fake handshake, certificate pinning and
  // the TLS handshake. Shared by AsyncGet, AsyncPost and AsyncTestHandshake.
  boost::asio::awaitable<bool> EstablishAsync(Connection& conn,
      const std::string& log_tag,
      Deadline deadline,
      std::string& error,
      int& respcode) const;

  // Reality-mode decoy handshake: ClientHello, wait for ServerHello, then
  // ChangeCipherSpec.
  boost::asio::awaitable<bool> PerformFakeHandshake(
      boost::asio::ip::tcp::socket& socket, Deadline deadline) const;

  // Registers/clears the strand+signal pair that Cancel() targets.
  void BeginOperation(
      const boost::asio::strand<boost::asio::io_context::executor_type>& strand,
      const std::shared_ptr<boost::asio::cancellation_signal>& signal) const;
  void EndOperation() const;

  struct CancellationState {
    std::mutex mutex;
    std::shared_ptr<boost::asio::cancellation_signal> signal;
    std::optional<boost::asio::strand<boost::asio::io_context::executor_type>>
        strand;
  };

  const std::string host_;
  const int port_;
  const std::string sni_;
  const std::string expected_md5_fingerprint_;
  const CensorshipStrategy censorship_strategy_;
  const std::string server_name_;
  std::shared_ptr<CancellationState> cancellation_;
};

using HttpsClientPtr = std::unique_ptr<ApiClient>;

}  // namespace fptn::protocol::https
