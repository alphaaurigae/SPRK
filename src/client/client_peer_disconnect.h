#ifndef CLIENT_PEER_DISCONNECT_H
#define CLIENT_PEER_DISCONNECT_H

#include "client_peer_manager.h"

#include <mutex>
#include <string>

inline void handle_disconnect(const std::string &username, const std::string &fp_hex)
{
    const std::lock_guard<std::mutex> lk(peers_mtx);

    auto it = peers.find(fp_hex);
    if (it != peers.end())
        peers.erase(it);

    auto itset = fps_by_username.find(username);
    if (itset != fps_by_username.end())
    {
        itset->second.erase(fp_hex);
        if (itset->second.empty())
            fps_by_username.erase(itset);
    }
}

#endif