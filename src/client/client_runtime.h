#pragma once

#include <atomic>
#include <mutex>
#include <openssl/ssl.h>

inline std::mutex ssl_io_mtx;
inline SSL* ssl = nullptr;
inline SSL_CTX* ssl_ctx = nullptr;
inline std::atomic_bool is_connected{false};
inline std::atomic_bool should_reconnect{true};
