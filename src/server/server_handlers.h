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

struct ParsedView
{
    const Parsed *v{};
    explicit ParsedView(const Parsed &p) noexcept : v(&p) {}
};

struct FrameView
{
    const std::vector<unsigned char> *v{};
    explicit FrameView(const std::vector<unsigned char> &f) noexcept : v(&f) {}
};

static void broadcast_hello_to_peers(
    const SessionData &sd, std::shared_ptr<ClientState> sender,
    const std::vector<unsigned char>                   &frame,
    const std::unordered_map<std::string, SessionData> &sessions)
{
    auto ts = get_current_timestamp_ms();
    std::cerr << "[" << ts << "] broadcast_hello_to_peers: peers="
              << sd.clients_by_nick.size()
              << " sender=" << (sender ? sender->username : "(null)")
              << " total_sessions=" << sessions.size() << "\n";

    for (const auto &kv : sd.clients_by_nick)
    {
        if (!sender || kv.second.get() == sender.get())
            continue;

        auto frame_copy =
            std::make_shared<const std::vector<unsigned char>>(frame);
        async_write_frame(
            kv.second->stream, frame_copy,
            [ts, sender_name = sender ? sender->username : "(null)",
             target_name = kv.first](const std::error_code &ec, std::size_t)
            {
                if (ec)
                    std::cerr << "[" << ts << "] [SERVER] Broadcast hello -> "
                              << target_name << " FAILED: " << ec.message()
                              << "\n";
                else
                    std::cerr << "[" << ts << "] [SERVER] Broadcast hello from "
                              << sender_name << " to " << target_name << "\n";
            });
    }
}

inline void
handle_hello_message(std::shared_ptr<ClientState> client, ParsedView p,
                     FrameView                                     frame,
                     std::unordered_map<std::string, SessionData> &sessions)
{
    const Parsed                     &pp = *p.v;
    const std::vector<unsigned char> &ff = *frame.v;

    std::cerr << "[" << get_current_timestamp_ms()
              << "] handle_hello_message: username='" << pp.username
              << "' session_id='" << pp.session_id
              << "' eph_pk_len=" << pp.eph_pk.size() << "\n";

    auto basics = HelloBasicsOut::make(HelloBasicsOut::SessionId(pp.session_id),
                                       HelloBasicsOut::UserName(pp.username));

    std::string error = validate_hello_basics(pp, basics);

    std::string &sid   = basics.sid;
    std::string &uname = basics.uname;

    if (!error.empty())
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] REJECTED: " << error << " for " << uname << "\n";
        return;
    }

    SessionData &sd = sessions[sid];

    if (!check_username_conflicts(sd, uname, client))
        return;

    client->session_id = sid;
    client->username   = uname;
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
              << "'s hello to " << (sd.clients_by_nick.size() - 1)
              << " peers\n";

    broadcast_hello_to_peers(sd, client, ff, sessions);

    for (const auto &kv : sd.hello_message_by_fingerprint)
    {
        const std::string &existing_fp = kv.first;
        if (existing_fp.empty())
            continue;

        auto itn = sd.nick_by_fingerprint.find(existing_fp);
        if (itn != sd.nick_by_fingerprint.end() && itn->second == uname)
            continue;

        const auto &existing_hello       = kv.second;
        uint32_t    existing_payload_len = read_u32_be(existing_hello.data());
        Parsed      p2 =
            parse_payload(existing_hello.data() + 4, existing_payload_len);

        std::vector<unsigned char> empty_encaps;
        auto stripped = build_hello(p2.username, ALGO_KYBER512, p2.eph_pk,
                                    p2.id_alg, p2.identity_pk, p2.signature,
                                    empty_encaps, p2.session_id);

        auto frame_copy =
            std::make_shared<const std::vector<unsigned char>>(stripped);
        async_write_frame(
            client->stream, frame_copy,
            [ts, p2_uname = p2.username, uname,
             p2_fp = compute_fingerprint_hex(p2.identity_pk)](
                const std::error_code &ec, std::size_t)
            {
                if (ec)
                {
                    std::cerr << "[" << ts
                              << "] [SERVER] Failed to send cached hello from "
                              << p2_uname << " to " << uname
                              << " (fp=" << p2_fp.substr(0, 10)
                              << "): " << ec.message() << "\n";
                }
                else
                {
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
                    FrameView                                     frame,
                    std::unordered_map<std::string, SessionData> &sessions)
{
    const Parsed &pp = *p.v;

    std::cerr << "[" << get_current_timestamp_ms()
              << "] handle_chat_message: from='" << pp.from << "' to='" << pp.to
              << "' seq=" << pp.seq << "\n";

    if (client->session_id.empty())
        return;

    auto sess_it = sessions.find(client->session_id);
    if (sess_it == sessions.end())
        return;

    SessionData                 &sd = sess_it->second;
    std::shared_ptr<ClientState> dst;

    if (auto it = sd.clients_by_nick.find(pp.to);
        it != sd.clients_by_nick.end())
        dst = it->second;
    else if (pp.to.size() >= 4)
    {
        std::string lower = pp.to;
        std::ranges::transform(lower, lower.begin(), [](unsigned char c)
                               { return static_cast<char>(std::tolower(c)); });

        auto it = std::ranges::find_if(
            sd.clients_by_fingerprint,
            [&lower](const auto &kv)
            {
                const std::string &fp = kv.first;
                if (fp.size() < lower.size())
                    return false;
                return std::ranges::equal(
                    lower.begin(), lower.end(), fp.begin(),
                    fp.begin() + lower.size(),
                    [](unsigned char a, unsigned char b)
                    { return std::tolower(a) == std::tolower(b); });
            });
        if (it != sd.clients_by_fingerprint.end())
            dst = it->second;
    }

    if (dst)
    {
        auto frame_copy =
            std::make_shared<const std::vector<unsigned char>>(*frame.v);
        async_write_frame(
            dst->stream, frame_copy,
            [](const std::error_code &ec, std::size_t)
            {
                if (ec)
                    std::cerr
                        << "[" << get_current_timestamp_ms()
                        << "] handle_chat_message: async_write_frame failed: "
                        << ec.message() << "\n";
            });
    }
}

inline void
handle_list_request(std::shared_ptr<ClientState>                  client,
                    std::unordered_map<std::string, SessionData> &sessions)
{
    if (client->session_id.empty())
        return;
    auto session_it = sessions.find(client->session_id);
    if (session_it == sessions.end())
        return;

    SessionData             &sd = session_it->second;
    std::vector<std::string> users;
    for (const auto &kv : sd.clients_by_nick)
        users.push_back(kv.first);

    auto resp      = build_list_response(users);
    auto resp_copy = std::make_shared<const std::vector<unsigned char>>(resp);
    async_write_frame(
        client->stream, resp_copy,
        [](const std::error_code &ec, std::size_t)
        {
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
                      std::unordered_map<std::string, SessionData> &sessions)
{
    if (client->session_id.empty())
        return;
    auto session_it = sessions.find(client->session_id);
    if (session_it == sessions.end())
        return;

    SessionData               &sd     = session_it->second;
    std::string                target = trim(p.username);
    std::vector<unsigned char> pk;

    auto itn = sd.clients_by_nick.find(target);
    if (itn != sd.clients_by_nick.end() &&
        !itn->second->fingerprint_hex.empty())
    {
        auto itpk =
            sd.identity_pk_by_fingerprint.find(itn->second->fingerprint_hex);
        if (itpk != sd.identity_pk_by_fingerprint.end())
            pk = itpk->second;
    }
    else
    {
        std::vector<std::string> matches;
        for (auto &kv : sd.identity_pk_by_fingerprint)
        {
            const std::string &hexfp = kv.first;
            if (hexfp.size() >= target.size())
            {
                bool ok = true;
                for (size_t i = 0; i < target.size(); ++i)
                {
                    if (std::tolower((unsigned char)hexfp[i]) !=
                        std::tolower((unsigned char)target[i]))
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    matches.push_back(hexfp);
            }
        }
        if (matches.size() == 1)
        {
            const std::string matched_fp = matches[0];
            auto itpk = sd.identity_pk_by_fingerprint.find(matched_fp);
            if (itpk != sd.identity_pk_by_fingerprint.end())
                pk = itpk->second;
        }
    }

    auto resp      = build_pubkey_response(target, pk);
    auto resp_copy = std::make_shared<const std::vector<unsigned char>>(resp);
    async_write_frame(
        client->stream, resp_copy,
        [](const std::error_code &ec, std::size_t)
        {
            if (ec)
                std::cerr
                    << "[" << get_current_timestamp_ms()
                    << "] handle_pubkey_request: async_write_frame failed: "
                    << ec.message() << "\n";
            else
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] handle_pubkey_request: response sent\n";
        });
}

#endif
