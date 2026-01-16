#ifndef NET_SOCKET_UTIL_H
#define NET_SOCKET_UTIL_H

#include <asio.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <system_error>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>

#ifndef NET_SOCKET_UTIL_DEBUG
# define NET_SOCKET_UTIL_DEBUG 0
#endif

static inline void net_socket_util_debug(const char* msg)
{
#if NET_SOCKET_UTIL_DEBUG
    if (msg) {
        write(STDERR_FILENO, msg, strlen(msg));
        write(STDERR_FILENO, "\n", 1);
    }
#endif
}

[[nodiscard]] inline int make_listen_socket(int port, int backlog = 16) noexcept
{
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    const int one = 1;
    if (::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        const int saved = errno;
        ::close(s);
        errno = saved;
        return -1;
    }
#ifdef SO_REUSEPORT
    ::setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    int flags = ::fcntl(s, F_GETFD);
    if (flags >= 0)
        ::fcntl(s, F_SETFD, flags | FD_CLOEXEC);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int saved = errno;
        ::close(s);
        errno = saved;
        return -1;
    }
    if (::listen(s, backlog) != 0) {
        const int saved = errno;
        ::close(s);
        errno = saved;
        return -1;
    }
    return s;
}

[[nodiscard]] inline int set_socket_nonblocking(int fd) noexcept
{
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    const int fd_flags = ::fcntl(fd, F_GETFD);
    if (fd_flags >= 0)
        ::fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
    return 0;
}

[[nodiscard]] inline int connect_to_host(const char* host, int port) noexcept
{
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    int saved_errno = 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        saved_errno = errno;
        ::close(s);
        errno = saved_errno;
        return -1;
    }
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        saved_errno = errno;
        ::close(s);
        errno = saved_errno;
        return -1;
    }
    return s;
}

[[nodiscard]] inline int connect_to_host_nonblocking(const char* host, int port) noexcept
{
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags >= 0)
        ::fcntl(s, F_SETFL, flags | O_NONBLOCK);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        const int saved = errno;
        ::close(s);
        errno = saved;
        return -1;
    }
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (errno == EINPROGRESS)
            return s;
        const int saved = errno;
        ::close(s);
        errno = saved;
        return -1;
    }
    return s;
}

[[nodiscard]] inline std::shared_ptr<asio::ip::tcp::acceptor>
make_listen_acceptor(asio::io_context& io, int port, int backlog = 16, bool set_reuse_port = true, std::error_code* out_ec = nullptr) noexcept
{
    try {
        auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(io);
        acceptor->open(asio::ip::tcp::v4());
        acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
        if (set_reuse_port) {
#ifdef SO_REUSEPORT
            int val = 1;
            ::setsockopt(acceptor->native_handle(), SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#endif
        }
        int fd_flags = ::fcntl(acceptor->native_handle(), F_GETFD);
        if (fd_flags >= 0)
            ::fcntl(acceptor->native_handle(), F_SETFD, fd_flags | FD_CLOEXEC);
        acceptor->bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), static_cast<unsigned short>(port)));
        acceptor->listen(backlog);
        if (out_ec) *out_ec = std::error_code();
        return acceptor;
    } catch (const std::system_error& e) {
        if (out_ec) *out_ec = e.code();
        return nullptr;
    } catch (...) {
        if (out_ec) *out_ec = std::make_error_code(std::errc::io_error);
        return nullptr;
    }
}

[[nodiscard]] inline int dup_from_asio_socket(const std::shared_ptr<asio::ip::tcp::socket>& sock) noexcept
{
    if (!sock) return -1;
#if defined(__unix__) || defined(__APPLE__)
    using native_t = decltype(sock->native_handle());
    native_t native = sock->native_handle();
    if (native < 0) return -1;
    int dupfd = ::dup(static_cast<int>(native));
    if (dupfd >= 0) {
        int fd_flags = ::fcntl(dupfd, F_GETFD);
        if (fd_flags >= 0)
            ::fcntl(dupfd, F_SETFD, fd_flags | FD_CLOEXEC);
    }
    return dupfd;
#else
    (void)sock;
    return -1;
#endif
}



inline std::shared_ptr<asio::ip::tcp::socket>
connect_to_host_asio(asio::io_context& io, const char* host, int port, std::error_code* out_ec = nullptr) noexcept
{
    try {
        asio::ip::tcp::resolver resolver(io);
        asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, std::to_string(port));
        auto sock = std::make_shared<asio::ip::tcp::socket>(io);
        asio::error_code ec;
        asio::connect(*sock, endpoints, ec);
        if (ec) {
            if (out_ec) *out_ec = ec;
            return nullptr;
        }
#if defined(__unix__) || defined(__APPLE__)
        using native_t = decltype(sock->native_handle());
        native_t native = sock->native_handle();
        if (native >= 0) {
            int fd_flags = ::fcntl(static_cast<int>(native), F_GETFD);
            if (fd_flags >= 0)
                ::fcntl(static_cast<int>(native), F_SETFD, fd_flags | FD_CLOEXEC);
        }
#endif
        if (out_ec) *out_ec = std::error_code();
        return sock;
    } catch (const std::system_error& e) {
        if (out_ec) *out_ec = e.code();
        return nullptr;
    } catch (...) {
        if (out_ec) *out_ec = std::make_error_code(std::errc::io_error);
        return nullptr;
    }
}


inline void async_connect_to_host_asio(asio::io_context& io,
                                                     const char* host, int port,
                                                     std::function<void(std::shared_ptr<asio::ip::tcp::socket>, std::error_code)> cb) noexcept
{
    try {
        auto resolver = std::make_shared<asio::ip::tcp::resolver>(io);
        auto sock = std::make_shared<asio::ip::tcp::socket>(io);
        resolver->async_resolve(host, std::to_string(port),
            [resolver, sock, cb=std::move(cb)](const std::error_code& ec, asio::ip::tcp::resolver::results_type endpoints) {
                if (ec) { cb(nullptr, ec); return; }
                asio::async_connect(*sock, endpoints,
                    [sock, cb=std::move(cb)](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                        if (ec) { cb(nullptr, ec); return; }
#if defined(__unix__) || defined(__APPLE__)
                        using native_t = decltype(sock->native_handle());
                        native_t native = sock->native_handle();
                        if (native >= 0) {
                            int fd_flags = ::fcntl(static_cast<int>(native), F_GETFD);
                            if (fd_flags >= 0)
                                ::fcntl(static_cast<int>(native), F_SETFD, fd_flags | FD_CLOEXEC);
                        }
#endif
                        cb(sock, ec);
                    });
            });
    } catch (...) {
        cb(nullptr, std::make_error_code(std::errc::io_error));
    }
}


#endif
