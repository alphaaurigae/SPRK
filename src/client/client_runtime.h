#ifndef CLIENT_RUNTIME_H
#define CLIENT_RUNTIME_H

#include <atomic>
#include <memory>
#include <mutex>
#include <openssl/ssl.h>

struct AsioSSLContextWrapper;

inline std::mutex                             ssl_io_mtx;
inline SSL                                   *ssl = nullptr;
inline std::shared_ptr<AsioSSLContextWrapper> ssl_ctx;
inline std::atomic_bool                       is_connected{false};
inline std::atomic_bool                       should_reconnect{true};

#endif