#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sys/select.h>

static int prepare_select(fd_set& rfds, int listen_fd,
                          const std::vector<ClientState>& clients) {
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    int maxfd = listen_fd;

    for (const auto& cs : clients) {
        FD_SET(cs.fd, &rfds);
        if (cs.fd > maxfd) maxfd = cs.fd;
    }

    return maxfd;
}


inline void cleanup_disconnected_client(
    int client_fd,
    std::vector<ClientState>& clients,
    std::unordered_map<int, std::string>& session_by_fd,
    std::unordered_map<std::string, SessionData>& sessions)
{
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end()) {
        auto it = std::find_if(clients.begin(), clients.end(),
                               [client_fd](const ClientState& cs) { return cs.fd == client_fd; });
        if (it != clients.end()) clients.erase(it);
        return;
    }

    std::string sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end()) {
        session_by_fd.erase(client_fd);
        auto it = std::find_if(clients.begin(), clients.end(),
                               [client_fd](const ClientState& cs) { return cs.fd == client_fd; });
        if (it != clients.end()) clients.erase(it);
        return;
    }

    SessionData& sd = session_it->second;

    std::string nick;
    auto nit = sd.nick_by_fd.find(client_fd);
    if (nit != sd.nick_by_fd.end())
        nick = nit->second;

    std::string fp_hex;
    auto iit = sd.fingerprint_hex_by_fd.find(client_fd);
    if (iit != sd.fingerprint_hex_by_fd.end())
        fp_hex = iit->second;

    // ADD LOGGING HERE (replace the old simple "disconnect" line)
    auto ts = get_current_timestamp_ms();
    if (!nick.empty()) {
        std::cout << "[" << ts << "] DISCONNECT " << nick 
                  << " session=" << sid
                  << (fp_hex.empty() ? "" : " fingerprint=" + fp_hex.substr(0, 10))
                  << "\n";
    } else {
        std::cout << "[" << ts << "] DISCONNECT fd=" << client_fd 
                  << " session=" << sid << "\n";
    }

    if (!fp_hex.empty()) {
        sd.fd_by_fingerprint.erase(fp_hex);
        sd.nick_by_fingerprint.erase(fp_hex);
        sd.eph_by_fingerprint.erase(fp_hex);
        sd.identity_pk_by_fingerprint.erase(fp_hex);
        sd.hello_message_by_fingerprint.erase(fp_hex);
        sd.fingerprint_hex_by_fd.erase(client_fd);
    }

    if (!nick.empty()) {
        sd.fd_by_nick.erase(nick);
        sd.nick_by_fd.erase(client_fd);
    }

    session_by_fd.erase(client_fd);

    auto it = std::find_if(clients.begin(), clients.end(),
                           [client_fd](const ClientState& cs) { return cs.fd == client_fd; });
    if (it != clients.end()) {
        // REMOVE this old logging line since we added better logging above
        // std::cout << "disconnect " << nick << " session=" << sid << "\n";
        clients.erase(it);
    }
}

static void process_client_events(const fd_set& rfds,
                                  std::vector<ClientState>& clients,
                                  std::unordered_map<std::string, SessionData>& sessions,
                                  std::unordered_map<int, std::string>& session_by_fd,
                                  std::vector<int>& to_remove)
{
    for (auto& client : clients) {
        if (!FD_ISSET(client.fd, &rfds)) continue;
        
        if (!SSL_is_init_finished(client.ssl)) {
            int ret = SSL_accept(client.ssl);
            if (ret <= 0) {
                int err = SSL_get_error(client.ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    to_remove.push_back(client.fd);
                }
            }
            continue;
        }
        
        std::vector<unsigned char> frame;
        if (!tls_peek_and_read_frame(client.ssl, frame)) {
            int err = SSL_get_error(client.ssl, 0);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                to_remove.push_back(client.fd);
            }
            continue;
        }
        
        uint32_t payload_len = read_u32_be(frame.data());
        try {
            Parsed p = parse_payload(frame.data() + 4, payload_len);
            switch (p.type) {
                case MsgType::MSG_HELLO:
                    handle_hello_message(client, p, frame, sessions, session_by_fd, clients, to_remove);
                    break;
                case MsgType::MSG_CHAT:
                    handle_chat_message(client, p, frame, session_by_fd, sessions, clients);
                    break;
                case MSG_LIST_REQUEST:
                    handle_list_request(client, session_by_fd, sessions, clients);
                    break;
                case MSG_PUBKEY_REQUEST:
                    handle_pubkey_request(client, p, session_by_fd, sessions, clients);
                    break;
                default:
                    break;
            }
        } catch (const std::exception& e) {
            std::cerr << "server parse exception: " << e.what() << "\n";
            to_remove.push_back(client.fd);
        } catch (...) {
            std::cerr << "server parse exception: unknown\n";
            to_remove.push_back(client.fd);
        }
    }
}
#endif
