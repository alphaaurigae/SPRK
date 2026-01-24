#ifndef SHARED_NET_SOCKET_UTIL_H
#define SHARED_NET_SOCKET_UTIL_H

#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>
#include <functional>
#include <memory>
#include <system_error>

[[nodiscard]] inline std::shared_ptr<asio::ip::tcp::acceptor>
make_listen_socket_asio(asio::io_context &io, int port, int backlog = 16,
                        bool set_reuse_port = true,
                        std::error_code *out_ec = nullptr) noexcept {
  try {
    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(io);
    acceptor->open(asio::ip::tcp::v4());
    acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
    if (set_reuse_port) {
#ifdef SO_REUSEPORT
      int val = 1;
      ::setsockopt(acceptor->native_handle(), SOL_SOCKET, SO_REUSEPORT, &val,
                   sizeof(val));
#endif
    }
    int fd_flags = ::fcntl(acceptor->native_handle(), F_GETFD);
    if (fd_flags >= 0)
      ::fcntl(acceptor->native_handle(), F_SETFD, fd_flags | FD_CLOEXEC);
    acceptor->bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(),
                                           static_cast<unsigned short>(port)));
    acceptor->listen(backlog);
    if (out_ec)
      *out_ec = std::error_code();
    return acceptor;
  } catch (const std::system_error &e) {
    if (out_ec)
      *out_ec = e.code();
    return nullptr;
  } catch (...) {
    if (out_ec)
      *out_ec = std::make_error_code(std::errc::io_error);
    return nullptr;
  }
}

inline void async_connect_to_host_asio(
    asio::io_context &io, const char *host, int port,
    std::function<void(std::shared_ptr<asio::ip::tcp::socket>, std::error_code)>
        cb) noexcept {
  try {
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io);
    auto sock = std::make_shared<asio::ip::tcp::socket>(io);
    resolver->async_resolve(
        host, std::to_string(port),
        [resolver, sock,
         cb = std::move(cb)](const std::error_code &ec,
                             asio::ip::tcp::resolver::results_type endpoints) {
          if (ec) {
            cb(nullptr, ec);
            return;
          }
          asio::async_connect(
              *sock, endpoints,
              [sock, cb = std::move(cb)](const std::error_code &ec,
                                         const asio::ip::tcp::endpoint &) {
                if (ec) {
                  cb(nullptr, ec);
                  return;
                }
#if defined(__unix__) || defined(__APPLE__)
                using native_t = decltype(sock->native_handle());
                native_t native = sock->native_handle();
                if (native >= 0) {
                  int fd_flags = ::fcntl(static_cast<int>(native), F_GETFD);
                  if (fd_flags >= 0)
                    ::fcntl(static_cast<int>(native), F_SETFD,
                            fd_flags | FD_CLOEXEC);
                }
#endif
                cb(sock, ec);
              });
        });
  } catch (...) {
    cb(nullptr, std::make_error_code(std::errc::io_error));
  }
}

using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>;

inline void async_accept_client(
    std::shared_ptr<asio::ip::tcp::acceptor> acceptor,
    std::shared_ptr<asio::ssl::context> ssl_ctx,
    std::function<void(std::shared_ptr<ssl_socket>, std::error_code)> cb) {
  auto sock = std::make_shared<asio::ip::tcp::socket>(acceptor->get_executor());

  acceptor->async_accept(*sock, [sock, ssl_ctx, cb = std::move(cb),
                                 acceptor](const std::error_code &ec) mutable {
    if (ec) {
      cb(nullptr, ec);
      return;
    }

    auto ssl_stream = std::make_shared<ssl_socket>(std::move(*sock), *ssl_ctx);

    ssl_stream->async_handshake(
        asio::ssl::stream_base::server,
        [ssl_stream, cb = std::move(cb)](const std::error_code &ec) {
          cb(ec ? nullptr : ssl_stream, ec);
        });
  });
}

#endif
