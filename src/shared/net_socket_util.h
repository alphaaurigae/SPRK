#ifndef NET_SOCKET_UTIL_H
#define NET_SOCKET_UTIL_H

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common_util.h"

[[nodiscard]] inline int make_listen_socket(int port, int backlog = 16) noexcept
{
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;

    constexpr int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
    {
        close(s);
        return -1;
    }

#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    int flags = fcntl(s, F_GETFD);
    if (flags >= 0)
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        close(s);
        return -1;
    }

    if (listen(s, backlog) != 0)
    {
        close(s);
        return -1;
    }

    return s;
}

[[nodiscard]] inline int set_socket_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    const int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags >= 0)
        fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);

    return 0;
}

[[nodiscard]] inline int connect_to_host(const char* host, int port) noexcept
{
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
    {
        close(s);
        return -1;
    }

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        close(s);
        return -1;
    }

    return s;
}

[[nodiscard]] inline bool tls_read_full_frame(SSL* ssl, std::vector<unsigned char>& frame_out)
{
    std::array<unsigned char, 4> header{};
    size_t total = 0;

    while (total < 4)
    {
        const ssize_t r = SSL_read(ssl, header.data() + total, 4 - total);
        if (r <= 0)
        {
            const int err = SSL_get_error(ssl, static_cast<int>(r));
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            return false;
        }
        total += static_cast<size_t>(r);
    }

    const uint32_t payload_len = read_u32_be(header.data());
    if (payload_len > 65536 || payload_len < 2)
        return false;

    frame_out.resize(4 + payload_len);
    std::memcpy(frame_out.data(), header.data(), 4);

    total = 0;
    while (total < payload_len)
    {
        const ssize_t r = SSL_read(ssl, frame_out.data() + 4 + total, payload_len - total);
        if (r <= 0)
        {
            const int err = SSL_get_error(ssl, static_cast<int>(r));
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            return false;
        }
        total += static_cast<size_t>(r);
    }

    return true;
}

[[nodiscard]] inline bool tls_peek_and_read_frame(SSL* ssl, std::vector<unsigned char>& frame_out)
{
    std::array<unsigned char, 4> lenbuf{};
    const ssize_t n = SSL_peek(ssl, lenbuf.data(), lenbuf.size());

    if (n < static_cast<ssize_t>(lenbuf.size()))
    {
        const int err = SSL_get_error(ssl, static_cast<int>(n));
        return (n < 0 && (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE));
    }

    const uint32_t payload_len = read_u32_be(lenbuf.data());
    if (payload_len > 64 * 1024)
        return false;

    frame_out.resize(4 + payload_len);
    const ssize_t got = tls_full_recv(ssl, frame_out.data(), frame_out.size());
    return got > 0;
}

#endif