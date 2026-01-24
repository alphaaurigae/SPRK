#ifndef SERVER_HANDLERS_H
#define SERVER_HANDLERS_H

#include "server_client_state.h"
#include "server_session.h"
#include "shared_net_common_protocol.h"
#include "shared_net_rekey_util.h"
#include "shared_net_tls_frame_io.h"

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

struct ParsedView {
  const Parsed *v{};
  explicit ParsedView(const Parsed &p) noexcept : v(&p) {}
};

struct FrameView {
  const std::vector<unsigned char> *v{};
  explicit FrameView(const std::vector<unsigned char> &f) noexcept : v(&f) {}
};

static void broadcast_hello_to_peers(
    const SessionData &sd, std::shared_ptr<ClientState> sender,
    const std::vector<unsigned char> &frame,
    const std::unordered_map<std::string, SessionData> &sessions) {
  auto ts = get_current_timestamp_ms();
  std::cerr << "[" << ts
            << "] broadcast_hello_to_peers: peers=" << sd.clients_by_nick.size()
            << " sender=" << (sender ? sender->username : "(null)")
            << " total_sessions=" << sessions.size() << "\n";

  for (const auto &kv : sd.clients_by_nick) {
    if (!sender || kv.second.get() == sender.get())
      continue;

    auto frame_copy = std::make_shared<const std::vector<unsigned char>>(frame);
    async_write_frame(
        kv.second->stream, frame_copy,
        [ts, sender_name = sender ? sender->username : "(null)",
         target_name = kv.first](const std::error_code &ec, std::size_t) {
          if (ec)
            std::cerr << "[" << ts << "] [SERVER] Broadcast hello -> "
                      << target_name << " FAILED: " << ec.message() << "\n";
          else
            std::cerr << "[" << ts << "] [SERVER] Broadcast hello from "
                      << sender_name << " to " << target_name << "\n";
        });
  }
}

inline void
handle_hello_message(std::shared_ptr<ClientState> client, ParsedView p,
                     FrameView frame,
                     std::unordered_map<std::string, SessionData> &sessions) {
  const Parsed &pp = *p.v;
  const std::vector<unsigned char> &ff = *frame.v;

  std::cerr << "[" << get_current_timestamp_ms()
            << "] handle_hello_message: username='" << pp.username
            << "' session_id='" << pp.session_id
            << "' eph_pk_len=" << pp.eph_pk.size() << "\n";

  auto basics = HelloBasicsOut::make(HelloBasicsOut::SessionId(pp.session_id),
                                     HelloBasicsOut::UserName(pp.username));

  std::string error = validate_hello_basics(pp, basics);

  std::string &sid = basics.sid;
  std::string &uname = basics.uname;

  if (!error.empty()) {
    std::cerr << "[" << get_current_timestamp_ms() << "] REJECTED: " << error
              << " for " << uname << "\n";
    return;
  }

  SessionData &sd = sessions[sid];

  if (!check_username_conflicts(sd, uname, client))
    return;

  client->session_id = sid;
  client->username = uname;
  client->fingerprint_hex =
      pp.identity_pk.empty() ? "" : compute_fingerprint_hex(pp.identity_pk);

  cleanup_old_nickname(sd, client, uname);

  auto data = ClientRegistrationData::make(
      ClientRegistrationData::Uname(uname), ClientRegistrationData::Frame(ff),
      ClientRegistrationData::ParsedMsg(pp));

  register_client(sd, client, data);

  if (!pp.identity_pk.empty())
    sd.hello_message_by_fingerprint[client->fingerprint_hex] = ff;

  std::cerr << "[" << get_current_timestamp_ms() << "] connect " << uname
            << " session=" << sid << "\n";

  auto ts = get_current_timestamp_ms();
  std::cerr << "[" << ts << "] [SERVER] Broadcasting " << uname
            << "'s hello to " << (sd.clients_by_nick.size() - 1) << " peers\n";

  broadcast_hello_to_peers(sd, client, ff, sessions);

  for (const auto &kv : sd.hello_message_by_fingerprint) {
    const std::string &existing_fp = kv.first;
    if (existing_fp.empty())
      continue;

    auto itn = sd.nick_by_fingerprint.find(existing_fp);
    if (itn != sd.nick_by_fingerprint.end() && itn->second == uname)
      continue;

    const auto &existing_hello = kv.second;
    uint32_t existing_payload_len = read_u32_be(existing_hello.data());
    Parsed p2 = parse_payload(existing_hello.data() + 4, existing_payload_len);

    std::vector<unsigned char> empty_encaps;
    auto stripped =
        build_hello(p2.username, ALGO_KYBER512, p2.eph_pk, p2.id_alg,
                    p2.identity_pk, p2.signature, empty_encaps, p2.session_id);

    auto frame_copy =
        std::make_shared<const std::vector<unsigned char>>(stripped);
    async_write_frame(client->stream, frame_copy,
                      [ts, p2_uname = p2.username, uname,
                       p2_fp = compute_fingerprint_hex(p2.identity_pk)](
                          const std::error_code &ec, std::size_t) {
                        if (ec) {
                          std::cerr
                              << "[" << ts
                              << "] [SERVER] Failed to send cached hello from "
                              << p2_uname << " to " << uname
                              << " (fp=" << p2_fp.substr(0, 10)
                              << "): " << ec.message() << "\n";
                        } else {
                          std::cerr << "[" << ts
                                    << "] [SERVER] Sent cached hello from "
                                    << p2_uname << " to " << uname
                                    << " (fp=" << p2_fp.substr(0, 10) << ")\n";
                        }
                      });
  }
}

inline void
handle_chat_message(std::shared_ptr<ClientState> client, ParsedView p,
                    FrameView frame,
                    std::unordered_map<std::string, SessionData> &sessions) {
  const Parsed &pp = *p.v;

  std::cerr << "[" << get_current_timestamp_ms()
            << "] handle_chat_message: from='" << pp.from << "' to='" << pp.to
            << "' seq=" << pp.seq << "\n";

  if (client->session_id.empty())
    return;

  auto sess_it = sessions.find(client->session_id);
  if (sess_it == sessions.end())
    return;

  SessionData &sd = sess_it->second;
  std::shared_ptr<ClientState> dst;

  if (auto it = sd.clients_by_nick.find(pp.to); it != sd.clients_by_nick.end())
    dst = it->second;
  else if (pp.to.size() >= 4) {
    std::string lower = pp.to;
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });

    auto it = std::ranges::find_if(
        sd.clients_by_fingerprint, [&lower](const auto &kv) {
          const std::string &fp = kv.first;
          if (fp.size() < lower.size())
            return false;
          return std::ranges::equal(lower.begin(), lower.end(), fp.begin(),
                                    fp.begin() + lower.size(),
                                    [](unsigned char a, unsigned char b) {
                                      return std::tolower(a) == std::tolower(b);
                                    });
        });
    if (it != sd.clients_by_fingerprint.end())
      dst = it->second;
  }

  if (dst) {
    auto frame_copy =
        std::make_shared<const std::vector<unsigned char>>(*frame.v);
    async_write_frame(
        dst->stream, frame_copy, [](const std::error_code &ec, std::size_t) {
          if (ec)
            std::cerr << "[" << get_current_timestamp_ms()
                      << "] handle_chat_message: async_write_frame failed: "
                      << ec.message() << "\n";
        });
  }
}

inline void
handle_list_request(std::shared_ptr<ClientState> client,
                    std::unordered_map<std::string, SessionData> &sessions) {
  if (client->session_id.empty())
    return;
  auto session_it = sessions.find(client->session_id);
  if (session_it == sessions.end())
    return;

  SessionData &sd = session_it->second;
  std::vector<std::string> users;
  for (const auto &kv : sd.clients_by_nick)
    users.push_back(kv.first);

  auto resp = build_list_response(users);
  auto resp_copy = std::make_shared<const std::vector<unsigned char>>(resp);
  async_write_frame(
      client->stream, resp_copy, [](const std::error_code &ec, std::size_t) {
        if (ec)
          std::cerr << "[" << get_current_timestamp_ms()
                    << "] handle_list_request: async_write_frame failed: "
                    << ec.message() << "\n";
        else
          std::cerr << "[" << get_current_timestamp_ms()
                    << "] handle_list_request: response sent\n";
      });
}

inline void
handle_pubkey_request(std::shared_ptr<ClientState> client, const Parsed &p,
                      std::unordered_map<std::string, SessionData> &sessions) {
  const auto validate_preconditions = [&]() noexcept -> bool {
    return client && client->stream && !client->session_id.empty();
  };

  const auto find_session = [&]() noexcept -> SessionData * {
    const auto it = sessions.find(client->session_id);
    return (it != sessions.end()) ? &it->second : nullptr;
  };

  const auto sanitize_target =
      [&](std::string_view raw) noexcept -> std::optional<std::string> {
    const std::string cleaned = trim(std::string(raw));
    const bool valid = !cleaned.empty() && cleaned.size() <= MAX_USERNAME &&
                       is_valid_username(cleaned);
    return valid ? std::optional(cleaned) : std::nullopt;
  };

  const auto lookup_by_nickname =
      [](SessionData &sd,
         std::string_view nick) noexcept -> std::vector<unsigned char> {
    const auto it = sd.clients_by_nick.find(std::string(nick));
    const bool has_client = (it != sd.clients_by_nick.end());
    const bool has_fp = has_client && !it->second->fingerprint_hex.empty();
    const bool valid_fp =
        has_fp && is_valid_hex_token(it->second->fingerprint_hex);

    if (!valid_fp) [[unlikely]]
      return {};

    const auto pk_it =
        sd.identity_pk_by_fingerprint.find(it->second->fingerprint_hex);
    return (pk_it != sd.identity_pk_by_fingerprint.end())
               ? pk_it->second
               : std::vector<unsigned char>{};
  };

  const auto lookup_by_fingerprint_prefix =
      [](SessionData &sd,
         std::string_view prefix) noexcept -> std::vector<unsigned char> {
    if (!is_valid_hex_token(std::string(prefix))) [[unlikely]]
      return {};

    constexpr auto case_insensitive_match = [](char a, char b) noexcept {
      return std::tolower(static_cast<unsigned char>(a)) ==
             std::tolower(static_cast<unsigned char>(b));
    };

    const auto matches_prefix = [&](const auto &kv) noexcept {
      const auto &hexfp = kv.first;
      return hexfp.size() >= prefix.size() &&
             hexfp.size() >= MIN_FP_PREFIX_HEX &&
             std::ranges::equal(prefix, hexfp | std::views::take(prefix.size()),
                                case_insensitive_match);
    };

    std::vector<std::pair<std::string, std::vector<unsigned char>>> matches;
    matches.reserve(2);

    for (const auto &[hexfp, pk] : sd.identity_pk_by_fingerprint) {
      if (matches_prefix(std::pair{hexfp, pk})) {
        matches.emplace_back(hexfp, pk);
        if (matches.size() >= 2)
          break;
      }
    }

    return (matches.size() == 1) ? matches[0].second
                                 : std::vector<unsigned char>{};
  };

  const auto send_response =
      [&](std::string_view username,
          const std::vector<unsigned char> &pk) noexcept {
        const auto resp = build_pubkey_response(std::string(username), pk);
        auto resp_copy =
            std::make_shared<const std::vector<unsigned char>>(std::move(resp));

        async_write_frame(client->stream, resp_copy,
                          [](const std::error_code &ec, std::size_t) noexcept {
                            if (ec) [[unlikely]]
                              std::cerr
                                  << "[" << get_current_timestamp_ms()
                                  << "] handle_pubkey_request: write failed: "
                                  << ec.message() << "\n";
                          });
      };

  if (!validate_preconditions()) [[unlikely]]
    return;

  SessionData *const sd = find_session();
  if (sd == nullptr) [[unlikely]]
    return;

  const auto target_opt = sanitize_target(p.username);
  if (!target_opt) [[unlikely]]
    return;

  const std::string &target = *target_opt;

  const auto pk_by_nick = lookup_by_nickname(*sd, target);
  const auto &pk = !pk_by_nick.empty()
                       ? pk_by_nick
                       : lookup_by_fingerprint_prefix(*sd, target);

  send_response(target, pk);
}
#endif
