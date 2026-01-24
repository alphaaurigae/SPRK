#ifndef CLIENT_PEER_DISCONNECT_H
#define CLIENT_PEER_DISCONNECT_H

#include "client_peer_manager.h"
#include "client_runtime.h"

#include <functional>
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
    std::lock_guard<std::mutex> lk{peer_globals::peers_mtx()};

    auto it = peer_globals::peers().find(std::string(fp_hex.v));
    if (it != peer_globals::peers().end())
        peer_globals::peers().erase(it);

    auto itset = peer_globals::fps_by_username().find(std::string(username.v));
    if (itset != peer_globals::fps_by_username().end())
    {
        itset->second.erase(std::string(fp_hex.v));
        if (itset->second.empty())
            peer_globals::fps_by_username().erase(itset);
    }
}

#endif