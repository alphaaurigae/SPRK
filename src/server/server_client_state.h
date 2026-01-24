#ifndef SERVER_CLIENT_STATE_H
#define SERVER_CLIENT_STATE_H

#include "shared_net_socket_util.h"

#include <asio/ssl.hpp>
#include <memory>
#include <string>

struct AsioSSLContextWrapper;

struct ClientState {
  std::shared_ptr<ssl_socket> stream{};
  std::string session_id{};
  std::string username{};
  std::string fingerprint_hex{};

  explicit ClientState(std::shared_ptr<ssl_socket> s) : stream(std::move(s)) {}
};

#endif