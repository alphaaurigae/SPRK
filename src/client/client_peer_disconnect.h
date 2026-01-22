#ifndef CLIENT_PEER_DISCONNECT_H
#define CLIENT_PEER_DISCONNECT_H

#include "client_peer_manager.h"

#include <mutex>

struct UsernameView
{
    std::string_view v{};
    explicit UsernameView(std::string_view s) noexcept : v(s) {}
};

struct FpHexView
{
    std::string_view v{};
    explicit FpHexView(std::string_view s) noexcept : v(s) {}
};

inline void handle_disconnect(UsernameView username, FpHexView fp_hex)
{
    const std::lock_guard<std::mutex> lk(peers_mtx);

    auto it = peers.find(std::string(fp_hex.v));
    if (it != peers.end())
        peers.erase(it);

    auto itset = fps_by_username.find(std::string(username.v));
    if (itset != fps_by_username.end())
    {
        itset->second.erase(std::string(fp_hex.v));
        if (itset->second.empty())
            fps_by_username.erase(itset);
    }
}

#endif