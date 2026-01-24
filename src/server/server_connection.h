#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

#include "server_client_state.h"
#include "server_handlers.h"
#include "server_session.h"
#include "shared_net_common_protocol.h"
#include "shared_net_rekey_util.h"
#include "shared_net_tls_frame_io.h"

#include <asio/ssl.hpp>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

inline void cleanup_disconnected_client(
    std::shared_ptr<ClientState> client,
    std::unordered_map<std::string, SessionData> &sessions) {
  if (client->session_id.empty())
    return;

  auto session_it = sessions.find(client->session_id);
  if (session_it == sessions.end())

    return;

  SessionData &sd = session_it->second;

  auto ts = get_current_timestamp_ms();
  if (!client->username.empty()) {
    std::cout << "[" << ts << "] DISCONNECT " << client->username
              << " session=" << client->session_id
              << (client->fingerprint_hex.empty()
                      ? ""
                      : " fingerprint=" + client->fingerprint_hex.substr(0, 10))
              << "\n";
  } else {
    std::cout << "[" << ts << "] DISCONNECT session=" << client->session_id
              << "\n";
  }

  if (!client->fingerprint_hex.empty()) {
    sd.clients_by_fingerprint.erase(client->fingerprint_hex);
    sd.nick_by_fingerprint.erase(client->fingerprint_hex);
    sd.eph_by_fingerprint.erase(client->fingerprint_hex);
    sd.identity_pk_by_fingerprint.erase(client->fingerprint_hex);
    sd.hello_message_by_fingerprint.erase(client->fingerprint_hex);
  }

  if (!client->username.empty()) {
    sd.clients_by_nick.erase(client->username);
  }
}

inline void
start_client_session(std::shared_ptr<ClientState> client,
                     std::unordered_map<std::string, SessionData> &sessions) {
  std::cerr << "[" << get_current_timestamp_ms()
            << "] start_client_session: registering read chain for client\n";
  chain_read_frames(client->stream, [client, &sessions](
                                        const std::error_code &ec,
                                        std::vector<unsigned char> &frame) {
    std::cerr << "[" << get_current_timestamp_ms()
              << "] chain_read_frames callback: ec="
              << (ec ? ec.message() : "ok") << " frame_len=" << frame.size()
              << "\n";

    if (ec) {
      std::cerr << "[" << get_current_timestamp_ms()
                << "] read error - cleaning up client\n";
      cleanup_disconnected_client(client, sessions);
      return;
    }

    if (frame.size() < 4) {
      std::cerr << "[" << get_current_timestamp_ms()
                << "] frame too small (<4) - cleaning up client\n";
      cleanup_disconnected_client(client, sessions);
      return;
    }

    uint32_t payload_len = read_u32_be(frame.data());
    if (payload_len + 4 != frame.size()) {
      std::cerr << "[" << get_current_timestamp_ms()
                << "] warning: payload_len mismatch; payload_len="
                << payload_len << " frame_total=" << frame.size() << "\n";
    }

    try {
      Parsed p = parse_payload(frame.data() + 4, payload_len);
      std::cerr << "[" << get_current_timestamp_ms()
                << "] parsed message type=" << static_cast<int>(p.type)
                << " from='" << p.username << "' session_id='" << p.session_id
                << "'\n";

      switch (p.type) {
      case MsgType::MSG_HELLO:
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] dispatch: MSG_HELLO\n";
        handle_hello_message(client, ParsedView(p), FrameView(frame), sessions);
        break;
      case MsgType::MSG_CHAT:
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] dispatch: MSG_CHAT to=" << p.to << "\n";
        handle_chat_message(client, ParsedView(p), FrameView(frame), sessions);
        break;
      case MSG_LIST_REQUEST:
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] dispatch: MSG_LIST_REQUEST\n";
        handle_list_request(client, sessions);
        break;
      case MSG_PUBKEY_REQUEST:
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] dispatch: MSG_PUBKEY_REQUEST username=" << p.username
                  << "\n";
        handle_pubkey_request(client, p, sessions);
        break;
      default:
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] unknown message type: " << static_cast<int>(p.type)
                  << "\n";
        break;
      }
    } catch (const std::exception &e) {
      std::cerr << "[" << get_current_timestamp_ms()
                << "] parse_payload threw: " << e.what() << "\n";
    } catch (...) {
      std::cerr << "[" << get_current_timestamp_ms()
                << "] parse_payload unknown exception\n";
    }
  });
}
#endif
