#ifndef NET_SOCKET_UTIL_H
#define NET_SOCKET_UTIL_H

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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

#endif