#ifndef CLIENT_RUNTIME_H
#define CLIENT_RUNTIME_H

#include <asio/ssl.hpp>
#include <atomic>
#include <memory>
#include <mutex>

using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>;

inline std::mutex                          ssl_io_mtx;
inline std::shared_ptr<ssl_socket>         ssl_stream;
inline std::shared_ptr<asio::ssl::context> ssl_ctx;
inline std::atomic_bool                    is_connected{false};
inline std::atomic_bool                    should_reconnect{true};

#endif