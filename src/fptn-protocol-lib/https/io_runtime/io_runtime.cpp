/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/io_runtime/io_runtime.h"

#include <exception>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {
// TLS handshake crypto is CPU work, so a second thread lets concurrent
// server probes overlap instead of serialising.
constexpr int kIoThreads = 2;
}  // namespace

namespace fptn::protocol::https {

IoRuntime& IoRuntime::Instance() {
  // Intentionally leaked. The worker threads outlive static destruction, and
  // tearing them down at exit would race with the destruction of the loggers
  // and BoringSSL state the in-flight coroutines still touch.
  static IoRuntime* instance = new IoRuntime();
  return *instance;
}

IoRuntime::IoRuntime() : work_guard_(boost::asio::make_work_guard(ioc_)) {
  threads_.reserve(kIoThreads);
  for (int i = 0; i < kIoThreads; ++i) {
    threads_.emplace_back([this] {
      try {
        ioc_.run();
      } catch (const std::exception& e) {
        SPDLOG_ERROR("IoRuntime worker stopped: {}", e.what());
      } catch (...) {
        SPDLOG_ERROR("IoRuntime worker stopped: unknown exception");
      }
    });
  }
}

}  // namespace fptn::protocol::https
