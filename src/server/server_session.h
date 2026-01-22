#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include "server_client_state.h"
#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_username_util.h"

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

struct SessionData
{
    std::unordered_map<std::string, std::shared_ptr<ClientState>>
        clients_by_nick;
    std::unordered_map<std::string, std::shared_ptr<ClientState>>
                                                 clients_by_fingerprint;
    std::unordered_map<std::string, std::string> nick_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        eph_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        identity_pk_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        hello_message_by_fingerprint;
};

// Returns empty string on success, error message on failure
static std::string validate_hello_basics(const Parsed &p, std::string &sid,
                                         std::string &uname)
{
    uname = trim(p.username);
    sid   = trim(p.session_id);

    std::cerr << "[" << get_current_timestamp_ms()
              << "] validate_hello_basics: username='" << uname
              << "' session_id_len=" << sid.size()
              << " id_alg=" << static_cast<int>(p.id_alg)
              << " eph_pk_len=" << p.eph_pk.size()
              << " signature_len=" << p.signature.size() << "\n";

    if (sid.empty())
    {
        sid = std::string(reinterpret_cast<const char *>(p.eph_pk.data()),
                          p.eph_pk.size());
        std::cerr
            << "[" << get_current_timestamp_ms()
            << "] validate_hello_basics: generated session id from eph_pk, len="
            << p.eph_pk.size() << "\n";
    }

    if (p.id_alg == 0 || p.identity_pk.empty() || p.signature.empty())
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] validate_hello_basics: missing identity or signature\n";
        return "missing identity or signature";
    }

    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    bool sig_ok =
        (p.id_alg == ALGO_MLDSA87) &&
        pqsig_verify(SIG_ALG_NAME, p.identity_pk, sig_data, p.signature);

    if (!sig_ok)
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] validate_hello_basics: signature verification failed\n";
        return "invalid signature";
    }

    std::cerr << "[" << get_current_timestamp_ms()
              << "] validate_hello_basics: ok\n";
    return {}; // empty string = success
}

static void cleanup_old_nickname(SessionData                 &sd,
                                 std::shared_ptr<ClientState> client,
                                 const std::string           &new_uname)
{
    if (client->username.empty() || client->username == new_uname)
        return;

    const std::string oldnick = client->username;
    sd.clients_by_nick.erase(oldnick);

    if (!client->fingerprint_hex.empty())
    {
        const std::string oldfp = client->fingerprint_hex;
        sd.clients_by_fingerprint.erase(oldfp);
        sd.nick_by_fingerprint.erase(oldfp);
        sd.eph_by_fingerprint.erase(oldfp);
        sd.identity_pk_by_fingerprint.erase(oldfp);
        sd.hello_message_by_fingerprint.erase(oldfp);
    }
}

static bool check_username_conflicts(SessionData &sd, const std::string &uname,
                                     std::shared_ptr<ClientState> client)
{
    auto it_existing = sd.clients_by_nick.find(uname);

    // Exact match with different fd → reject
    if (it_existing != sd.clients_by_nick.end() &&
        it_existing->second != client)
    {
        std::cout << "REJECTED: username already in use " << uname << "\n";

        return false;
    }

    // Similar username, but not the same client re-connecting
    if (has_similar_username(uname, sd.clients_by_nick, 85) &&
        (it_existing == sd.clients_by_nick.end() ||
         it_existing->second != client))
    {
        std::cout << "REJECTED: username too similar to existing user " << uname
                  << "\n";
        return false;
    }

    return true; // username is acceptable
}

static void register_client(SessionData                      &sd,
                            std::shared_ptr<ClientState>      client,
                            const std::string                &uname,
                            const std::vector<unsigned char> &frame,
                            const Parsed                     &p)
{
    std::cerr << "[" << get_current_timestamp_ms()
              << "] register_client: uname='" << uname
              << "' fp_present=" << (!p.identity_pk.empty())
              << " frame_len=" << frame.size() << "\n";

    // Compute fingerprint if identity key present
    std::string fp_hex =
        p.identity_pk.empty() ? "" : compute_fingerprint_hex(p.identity_pk);

    // Always register nickname
    sd.clients_by_nick[uname] = client;

    // Register identity/fingerprint data if present
    if (!fp_hex.empty())
    {
        sd.clients_by_fingerprint[fp_hex]       = client;
        sd.nick_by_fingerprint[fp_hex]          = uname;
        sd.eph_by_fingerprint[fp_hex]           = p.eph_pk;
        sd.identity_pk_by_fingerprint[fp_hex]   = p.identity_pk;
        sd.hello_message_by_fingerprint[fp_hex] = frame;
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] register_client: registered fingerprint="
                  << fp_hex.substr(0, 10) << "\n";
    }
    else
    {
        sd.hello_message_by_fingerprint[""] = frame;
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] register_client: registered anonymous hello\n";
    }
}
#endif