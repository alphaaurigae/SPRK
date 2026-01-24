#ifndef CLIENT_RUNTIME_H
#define CLIENT_RUNTIME_H

#include <asio/ssl.hpp>
#include <atomic>
#include <memory>
#include <mutex>

using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>;

namespace runtime_globals {

inline std::mutex &ssl_io_mtx() noexcept {
  static std::mutex obj;
  return obj;
}

inline std::shared_ptr<ssl_socket> &ssl_stream() noexcept {
  static std::shared_ptr<ssl_socket> obj;
  return obj;
}

inline std::shared_ptr<asio::ssl::context> &ssl_ctx() noexcept {
  static std::shared_ptr<asio::ssl::context> obj;
  return obj;
}

inline std::atomic_bool &is_connected() noexcept {
  static std::atomic_bool obj{false};
  return obj;
}

inline std::atomic_bool &should_reconnect() noexcept {
  static std::atomic_bool obj{true};
  return obj;
}

} // namespace runtime_globals

#endif
