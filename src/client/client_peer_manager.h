#ifndef CLIENT_PEER_MANAGER_H
#define CLIENT_PEER_MANAGER_H

#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_rekey_util.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct PeerParsed;

struct PeerInfo
{
    std::string   username{};
    std::string   bound_session_id{};
    secure_vector eph_pk{};
    secure_vector identity_pk{};
    std::string   peer_fp_hex{};
    SessionKey    sk{};
    uint32_t      recv_seq                = 0;
    uint32_t      send_seq                = 0;
    uint64_t      last_recv_time          = 0;
    uint64_t      last_send_time          = 0;
    uint32_t      rate_limit_counter      = 0;
    uint64_t      rate_limit_window_start = 0;
    bool          ready                   = false;
    bool          sent_hello              = false;
    bool          identity_verified       = false;
};

struct MsU
{
    uint64_t v{};
    explicit MsU(uint64_t x) noexcept : v(x) {}
};

struct PeerNameStr
{
    std::string_view v{};
    explicit PeerNameStr(std::string_view s) noexcept : v(s) {}
};

struct PeerFpHexStr
{
    std::string_view v{};
    explicit PeerFpHexStr(std::string_view s) noexcept : v(s) {}
};

static constexpr uint32_t REKEY_INTERVAL       = 1024;
static constexpr size_t   MAX_PEERS            = 256;
static constexpr uint32_t RATE_LIMIT_MSGS      = 100;
static constexpr uint64_t RATE_LIMIT_WINDOW_MS = 1000;

inline std::unordered_map<std::string, PeerInfo> peers;
inline std::unordered_map<std::string, std::unordered_set<std::string>>
                     fps_by_username;
inline std::mutex    peers_mtx;
inline std::string   my_username;
inline std::string   session_id;
inline secure_vector my_eph_pk;
inline secure_vector my_eph_sk;

inline secure_vector my_identity_pk;
inline secure_vector my_identity_sk;
inline std::string   my_fp_hex;

static bool check_rate_limit(PeerInfo &pi) noexcept
{
    RateLimitState state{pi.rate_limit_counter, pi.rate_limit_window_start};
    const bool     allowed =
        check_rate_limit(state, get_current_timestamp_ms(), RATE_LIMIT_MSGS,
                         RATE_LIMIT_WINDOW_MS);
    pi.rate_limit_counter      = state.counter;
    pi.rate_limit_window_start = state.window_start_ms;
    return allowed;
}

void update_peer_info(PeerInfo &pi, PeerNameStr peer_name,
                      PeerFpHexStr                     peer_fp_hex,
                      std::unordered_set<std::string> &fps_set)
{
    pi.username = std::string(peer_name.v);
    if (!peer_fp_hex.v.empty())
    {
        fps_set.insert(std::string(peer_fp_hex.v));
        pi.peer_fp_hex = std::string(peer_fp_hex.v);
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] update_peer_info: set peer '"
                  << std::string(peer_name.v) << "' fp="
                  << std::string(peer_fp_hex.v)
                         .substr(0, std::min<size_t>(peer_fp_hex.v.size(), 12))
                  << "\n";
    }
    else
    {
        const std::string peer_key = "uname:" + std::string(peer_name.v);
        fps_set.insert(peer_key);
        pi.peer_fp_hex = peer_key;
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] update_peer_info: set peer '"
                  << std::string(peer_name.v) << "' uname-key=" << peer_key
                  << "\n";
    }
}

bool detect_key_changes(const PeerInfo &pi, const Parsed &p, bool &pk_changed,
                        bool &has_new_encaps)
{
    const bool had_eph_pk = !pi.eph_pk.empty();
    pk_changed     = had_eph_pk && (pi.eph_pk.size() != p.eph_pk.size() ||
                                !std::equal(pi.eph_pk.begin(), pi.eph_pk.end(),
                                                p.eph_pk.begin()));
    has_new_encaps = !p.encaps.empty() && had_eph_pk && !pi.ready;
    return !had_eph_pk || pk_changed || has_new_encaps;
}

void handle_rekey(PeerInfo &pi, PeerNameStr peer_name, MsU ms)
{
    pi.recv_seq   = 0;
    pi.send_seq   = 0;
    pi.ready      = false;
    pi.sent_hello = false;
    pi.sk.key.clear();
    pi.identity_verified = false;
    std::cout << "[" << ms.v << "] peer " << std::string(peer_name.v)
              << " rekeyed\n";
}

void update_keys_and_log_connect(PeerInfo &pi, const Parsed &p,
                                 PeerNameStr peer_name, MsU ms)
{
    pi.eph_pk      = secure_vector(p.eph_pk.begin(), p.eph_pk.end());
    pi.identity_pk = secure_vector(p.identity_pk.begin(), p.identity_pk.end());

    const std::string ts      = format_hhmmss(ms.v);
    std::string       shortpk = "(no pk)";
    if (!p.identity_pk.empty())
    {
        const std::string hexpk =
            to_hex(p.identity_pk.data(), p.identity_pk.size());
        shortpk = (hexpk.size() > 20) ? hexpk.substr(0, 10) + "..." +
                                            hexpk.substr(hexpk.size() - 10)
                                      : hexpk;
    }
    std::cout << "[" << ts << "] connect " << std::string(peer_name.v)
              << " pubkey=" << shortpk << "\n";
}

#endif
