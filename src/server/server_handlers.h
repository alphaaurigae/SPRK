#ifndef SERVER_HANDLERS_H
#define SERVER_HANDLERS_H

#include "server_session.h"
#include "shared_net_rekey_util.h"  // For get_current_timestamp_ms()

#include <vector>
#include <string>
#include <ctime>
#include <unordered_map>


static void broadcast_hello_to_peers(const SessionData &sd, int client_fd,
                                     const std::vector<unsigned char> &frame,
                                     const std::vector<ClientState>& clients)
{
    auto ts = get_current_timestamp_ms();
    for (const auto &kv : sd.fd_by_nick)
    {
        std::cerr << "[" << ts << "] [SERVER] Checking broadcast to " << kv.first << " (fd=" << kv.second << ")\\n";  // Debug
        int dst_fd = kv.second;
        if (dst_fd == client_fd) continue;

        auto it = std::find_if(clients.begin(), clients.end(),
                               [dst_fd](const ClientState& cs) { return cs.fd == dst_fd; });
        if (it != clients.end()) {
            tls_full_send(it->ssl, frame.data(), frame.size());
            std::cerr << "[" << ts << "] [SERVER] Broadcast hello from fd=" << client_fd
                      << " to fd=" << dst_fd << "\n";
        }
    }
}


inline bool handle_hello_message(const ClientState& client_state,
                                 const Parsed &p,
                                 const std::vector<unsigned char> &frame,
                                 std::unordered_map<std::string, SessionData> &sessions,
                                 std::unordered_map<int, std::string> &session_by_fd,
                                 std::vector<ClientState>& clients,
                                 std::vector<int> &to_remove)
{
    int client_fd = client_state.fd;
    std::string uname;
    std::string sid;
    std::string error = validate_hello_basics(p, uname, sid);
    std::cerr << "[SERVER] Hello from " << uname << " session=" << sid << " (error: " << error << ")\\n";  // Debug

    if (!error.empty())
    {
        std::cout << "REJECTED: " << error << " for " << uname << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    SessionData &sd = sessions[sid];

    if (!check_username_conflicts(sd, uname, client_fd, to_remove))
    {
        return false;
    }


    cleanup_old_nickname(sd, client_fd, uname);

    // register first so broadcast sees this client
    register_client(sd, client_fd, uname, p, frame);
    std::cerr << "[SERVER] Registered client fd=" << client_fd << " uname=" << uname << "\\n";  // Debug

    // cache hello by fingerprint
    if (!p.identity_pk.empty()) {
        const std::string fhex = compute_fingerprint_hex(p.identity_pk);
        sd.hello_message_by_fingerprint[fhex] = frame;
    }

    session_by_fd[client_fd] = sid;
    
    // Test expects: "connect username session=..."
    std::cout << "connect " << uname << " session=" << sid << "\n";

    auto ts = get_current_timestamp_ms();
    // Debug output
    std::cerr << "[" << ts << "] [SERVER] Broadcasting " << uname << "'s hello to "
              << (sd.fd_by_nick.size() - 1) << " peers\n";

    broadcast_hello_to_peers(sd, client_fd, frame, clients);

    // Send existing hellos to new client (core protocol handshake — keep
    // visible)
    for (const auto &kv : sd.hello_message_by_fingerprint)
    {
        const std::string &existing_fp = kv.first;

        if (existing_fp.empty()) continue;
        auto itn = sd.nick_by_fingerprint.find(existing_fp);
        if (itn != sd.nick_by_fingerprint.end() && itn->second == uname)
            continue;

        const auto &existing_hello = kv.second;

         try
        {
            uint32_t existing_payload_len = read_u32_be(existing_hello.data());
            Parsed p2 = parse_payload(existing_hello.data() + 4, existing_payload_len);
            
            // ALWAYS strip encaps when relaying to new clients
            std::vector<unsigned char> empty_encaps;
            auto stripped = build_hello(p2.username, ALGO_KYBER512, p2.eph_pk,
                                        p2.id_alg, p2.identity_pk, p2.signature,
                                        empty_encaps, p2.session_id);
            tls_full_send(client_state.ssl, stripped.data(), stripped.size());
            
            auto ts2 = get_current_timestamp_ms();
            std::cerr << "[" << ts2 << "] [SERVER] Sent cached hello from " << p2.username
                      << " to " << uname
                      << " (fp=" << compute_fingerprint_hex(p2.identity_pk).substr(0,10) << ")\n";
         }
        catch (...)
        {
            // tls_full_send(client_state.ssl, existing_hello.data(), existing_hello.size());
        }
    }

    return true;
}

inline void handle_chat_message(const ClientState& client_state,
                                const Parsed &p,
                                const std::vector<unsigned char> &frame,
                                const std::unordered_map<int, std::string> &session_by_fd,
                                std::unordered_map<std::string, SessionData> &sessions,
                                const std::vector<ClientState>& clients)
{
    int client_fd = client_state.fd;
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end()) return;

    auto sess_it = sessions.find(sid_it->second);
    if (sess_it == sessions.end()) return;

    SessionData &sd = sess_it->second;

    int dst = -1;

    if (auto it = sd.fd_by_nick.find(p.to); it != sd.fd_by_nick.end())
    {
        dst = it->second;
    }
    else if (p.to.size() >= 4)
    {
        std::string lower = p.to;
        std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        auto it = std::ranges::find_if(sd.fd_by_fingerprint,
                                       [&lower](const auto& kv) {
                                           const std::string& fp = kv.first;
                                           if (fp.size() < lower.size()) return false;
                                           return std::ranges::equal(lower.begin(), lower.end(),
                                                                     fp.begin(), fp.begin() + lower.size(),
                                                                     [](unsigned char a, unsigned char b) {
                                                                         return std::tolower(a) == std::tolower(b);
                                                                     });
                                       });
        if (it != sd.fd_by_fingerprint.end()) dst = it->second;
    }

    if (dst != -1) {
        auto it = std::find_if(clients.begin(), clients.end(),
                               [dst](const ClientState& cs) { return cs.fd == dst; });
        if (it != clients.end()) {
            tls_full_send(it->ssl, frame.data(), frame.size());
        }
    }
}

inline void handle_list_request(const ClientState& client_state,
                                const std::unordered_map<int, std::string>& session_by_fd,
                                std::unordered_map<std::string, SessionData>& sessions,
                                const std::vector<ClientState>& clients)
{
    int client_fd = client_state.fd;
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end()) return;

    const std::string& sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end()) return;

    SessionData& sd = session_it->second;
    std::vector<std::string> users;
    // Only include clients that are actually connected
    for (auto& kv : sd.fd_by_nick) {
        const std::string& nick = kv.first;
        int target_fd = kv.second;
        
        // Check if this client is in the connected clients list
        auto it = std::find_if(clients.begin(), clients.end(),
                               [target_fd](const ClientState& cs) { 
                                   return cs.fd == target_fd; 
                               });
        if (it != clients.end()) {
            users.push_back(nick);
        }
    }
    
    auto resp = build_list_response(users);
    tls_full_send(client_state.ssl, resp.data(), resp.size());
}

inline void handle_pubkey_request(const ClientState& client_state,
                                  const Parsed &p,
                                  const std::unordered_map<int, std::string>& session_by_fd,
                                  std::unordered_map<std::string, SessionData>& sessions,
                                  const std::vector<ClientState>& clients)
{
    int client_fd = client_state.fd;
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end()) return;

    const std::string& sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end()) return;

    SessionData& sd = session_it->second;
    std::string target = trim(p.username);

    std::vector<unsigned char> pk;

    auto itn = sd.fd_by_nick.find(target);
    if (itn != sd.fd_by_nick.end())
    {
        int dstfd = itn->second;
        // Verify this client is still connected
        bool target_connected = false;
        for (const auto& client : clients) {
            if (client.fd == dstfd) {
                target_connected = true;
                break;
            }
        }
        
        if (target_connected) {
            auto itfp = sd.fingerprint_hex_by_fd.find(dstfd);
            if (itfp != sd.fingerprint_hex_by_fd.end())
            {
                auto itpk = sd.identity_pk_by_fingerprint.find(itfp->second);
                if (itpk != sd.identity_pk_by_fingerprint.end())
                    pk = itpk->second;
            }
        } // <-- ADDED THIS CLOSING BRACE
    }
    else
    {
        std::vector<std::string> matches;
        for (auto& kv : sd.identity_pk_by_fingerprint)
        {
            const std::string& hexfp = kv.first;
            if (hexfp.size() >= target.size())
            {
                bool ok = true;
                for (size_t i = 0; i < target.size(); ++i)
                {
                    if (std::tolower((unsigned char)hexfp[i]) != std::tolower((unsigned char)target[i]))
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) matches.push_back(hexfp);
            }
        }
        if (matches.size() == 1)
        {
            // For fingerprint lookup, check if client with this fingerprint is connected
            const std::string& matched_fp = matches[0];
            auto fd_it = sd.fd_by_fingerprint.find(matched_fp);
            if (fd_it != sd.fd_by_fingerprint.end()) {
                int dstfd = fd_it->second;
                
                // Verify this client is still connected
                bool target_connected = false;
                for (const auto& client : clients) {
                    if (client.fd == dstfd) {
                        target_connected = true;
                        break;
                    }
                }
                
                if (target_connected) {
                    pk = sd.identity_pk_by_fingerprint[matched_fp];
                }
            }
        }
    }
    auto resp = build_pubkey_response(target, pk);
    tls_full_send(client_state.ssl, resp.data(), resp.size());
}
#endif