#ifndef COMMON_UTIL_H
#define COMMON_UTIL_H
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <span>
#include <ranges>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <iostream>
#include <fstream>

#include <atomic>

#include <ctime>
#include <format>


#include <openssl/ssl.h>
#include <openssl/err.h> 




inline std::atomic_bool debug_mode{false};

inline void dev_print(std::string_view s)
{
    if (debug_mode.load())
        std::cout << s;
}

inline void dev_println(std::string_view s)
{
    if (debug_mode.load())
        std::cout << s << "\n";
}


inline std::string format_hhmmss(uint64_t ms)
{
    const auto t = static_cast<std::time_t>(ms / 1000);
    std::tm    tm{};
    localtime_r(&t, &tm);

    return std::format("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

inline std::vector<unsigned char> read_file_raw(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("cannot open key file");
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

inline std::string to_hex(std::span<const unsigned char> data)
{
    constexpr std::array<char, 16> hex = {'0', '1', '2', '3', '4', '5',
                                          '6', '7', '8', '9', 'a', 'b',
                                          'c', 'd', 'e', 'f'};
    std::string                    s;
    s.reserve(data.size() * 2);
    for (const auto c : data)
    {
        const size_t hi = static_cast<size_t>(c) >> 4;
        const size_t lo = static_cast<size_t>(c) & 0xF;
        s.push_back(hex.at(hi));
        s.push_back(hex.at(lo));
    }
    return s;
}

inline std::string to_hex(const unsigned char *b, size_t n)
{
    return to_hex(std::span<const unsigned char>(b, n));
}

constexpr unsigned char hexval_local(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    throw std::invalid_argument("bad hex");
}

inline std::vector<unsigned char> from_hex(std::string_view hex)
{
    if (hex.size() % 2 != 0U)
        throw std::invalid_argument("hex length");
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const unsigned char hi = hexval_local(hex[i]);
        const unsigned char lo = hexval_local(hex[i + 1]);
        out.push_back((hi << 4) | lo);
    }
    return out;
}

inline uint32_t read_u32_be(std::span<const unsigned char, 4> p) noexcept
{
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint32_t read_u32_be(const unsigned char *p)
{
    return read_u32_be(std::span<const unsigned char, 4>(p, 4));
}

inline void write_u32_be(std::span<unsigned char, 4> p, uint32_t v) noexcept
{
    p[0] = static_cast<unsigned char>((v >> 24) & 0xFFU);
    p[1] = static_cast<unsigned char>((v >> 16) & 0xFFU);
    p[2] = static_cast<unsigned char>((v >> 8) & 0xFFU);
    p[3] = static_cast<unsigned char>(v & 0xFFU);
}

inline void write_u32_be(unsigned char *p, uint32_t v)
{
    write_u32_be(std::span<unsigned char, 4>(p, 4), v);
}

inline ssize_t full_send(int fd, std::span<const unsigned char> data)
{
    size_t sent = 0;
    while (sent < data.size())
    {
        const ssize_t r =
            send(fd, data.subspan(sent).data(), data.size() - sent, 0);
        if (r < 0) [[unlikely]]
        {
            if (errno == EINTR) [[likely]]
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                fd_set wf;
                FD_ZERO(&wf);
                FD_SET(fd, &wf);
                timeval   tv{1, 0};
                const int s = select(fd + 1, nullptr, &wf, nullptr, &tv);
                if (s <= 0)
                    return -1;
                continue;
            }
            return -1;
        }
        sent += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(sent);
}

inline ssize_t full_send(int fd, const unsigned char *buf, size_t len)
{
    return full_send(fd, std::span<const unsigned char>(buf, len));
}

inline ssize_t full_recv(int fd, std::span<unsigned char> buf)
{
    size_t got = 0;
    while (got < buf.size())
    {
        const ssize_t r =
            recv(fd, buf.subspan(got).data(), buf.size() - got, 0);
        if (r < 0) [[unlikely]]
        {
            if (errno == EINTR) [[likely]]
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                fd_set rf;
                FD_ZERO(&rf);
                FD_SET(fd, &rf);
                timeval   tv{1, 0};
                const int s = select(fd + 1, &rf, nullptr, nullptr, &tv);
                if (s <= 0)
                    return -1;
                continue;
            }
            return -1;
        }
        if (r == 0) [[unlikely]]
            return 0;
        got += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(got);
}

inline ssize_t full_recv(int fd, unsigned char *buf, size_t len)
{
    return full_recv(fd, std::span<unsigned char>(buf, len));
}

inline std::string trim(std::string s)
{
    const auto is_space = [](unsigned char c) noexcept {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };

    s.erase(s.begin(),
            std::ranges::find_if(s, [&](unsigned char c) { return !is_space(c); }));

    s.erase(std::ranges::find_if(s | std::views::reverse,
                                 [&](unsigned char c) { return !is_space(c); }).base(),
            s.end());

    return s;
}
#endif