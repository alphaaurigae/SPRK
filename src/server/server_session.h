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

struct HelloBasicsOut
{
  public:
    std::string sid{};
    std::string uname{};

    struct SessionId
    {
        std::string_view v{};
        explicit SessionId(std::string_view s) noexcept : v(s) {}
    };

    struct UserName
    {
        std::string_view v{};
        explicit UserName(std::string_view s) noexcept : v(s) {}
    };

    static HelloBasicsOut make(SessionId s, UserName u)
    {
        return HelloBasicsOut(s, u);
    }

    HelloBasicsOut() = delete;

  private:
    explicit HelloBasicsOut(SessionId s, UserName u) : sid(s.v), uname(u.v) {}
};
static std::string validate_hello_basics(const Parsed &p, HelloBasicsOut &out)
{
    out.uname = trim(p.username);
    out.sid   = trim(p.session_id);

    std::cerr << "[" << get_current_timestamp_ms()
              << "] validate_hello_basics: username='" << out.uname
              << "' session_id_len=" << out.sid.size()
              << " id_alg=" << static_cast<int>(p.id_alg)
              << " eph_pk_len=" << p.eph_pk.size()
              << " signature_len=" << p.signature.size() << "\n";

    if (out.sid.empty())
    {
        out.sid = std::string(reinterpret_cast<const char *>(p.eph_pk.data()),
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

    bool sig_ok{false};
    sig_ok = (p.id_alg == ALGO_MLDSA87) &&
             pqsig_verify(SIG_ALG_NAME, p.identity_pk, sig_data, p.signature);

    if (!sig_ok)
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] validate_hello_basics: signature verification failed\n";
        return "invalid signature";
    }

    std::cerr << "[" << get_current_timestamp_ms()
              << "] validate_hello_basics: ok\n";
    return {};
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

    return true;
}

struct ClientRegistrationData
{
  public:
    std::string                uname{};
    std::vector<unsigned char> frame{};
    Parsed                     p{};

    struct Uname
    {
        std::string_view v{};
        explicit Uname(std::string_view s) noexcept : v(s) {}
    };

    struct Frame
    {
        const std::vector<unsigned char> *v{};
        explicit Frame(const std::vector<unsigned char> &f) noexcept : v(&f) {}
    };

    struct ParsedMsg
    {
        const Parsed *v{};
        explicit ParsedMsg(const Parsed &p_) noexcept : v(&p_) {}
    };

    static ClientRegistrationData make(Uname u, Frame f, ParsedMsg p_)
    {
        return ClientRegistrationData(u, f, p_);
    }

    ClientRegistrationData() = delete;

  private:
    explicit ClientRegistrationData(Uname u, Frame f, ParsedMsg p_)
        : uname(u.v), frame(*f.v), p(*p_.v)
    {
    }
};

static void register_client(SessionData                  &sd,
                            std::shared_ptr<ClientState>  client,
                            const ClientRegistrationData &data)
{
    const auto &uname = data.uname;
    const auto &frame = data.frame;
    const auto &p     = data.p;

    const auto now = get_current_timestamp_ms();

    std::cerr << "[" << now << "] register_client: uname='" << uname
              << "' fp_present=" << (!p.identity_pk.empty())
              << " frame_len=" << frame.size() << "\n";

    const bool has_pk = !p.identity_pk.empty();

    secure_vector dummy_pk(SHA256_LEN);
    if (!has_pk)
        RAND_bytes(dummy_pk.data(), static_cast<int>(dummy_pk.size()));

    const auto &pk = has_pk ? p.identity_pk : dummy_pk;

    const std::string fp_hex = compute_fingerprint_hex(pk);

    const bool valid_fp = has_pk & is_valid_hex_token(fp_hex);

    if (!valid_fp)
        throw std::runtime_error("invalid or missing identity");

    sd.clients_by_nick.insert_or_assign(uname, client);
    sd.clients_by_fingerprint.insert_or_assign(fp_hex, client);
    sd.nick_by_fingerprint.insert_or_assign(fp_hex, uname);
    sd.eph_by_fingerprint.insert_or_assign(fp_hex, p.eph_pk);
    sd.identity_pk_by_fingerprint.insert_or_assign(fp_hex, p.identity_pk);
    sd.hello_message_by_fingerprint.insert_or_assign(fp_hex, frame);

    std::cerr << "[" << now << "] register_client: registered fp="
              << fp_hex.substr(0, MIN_FP_PREFIX_HEX) << "\n";
}
#endif