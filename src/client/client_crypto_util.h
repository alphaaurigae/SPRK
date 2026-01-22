#ifndef CLIENT_CRYPTO_UTIL_H
#define CLIENT_CRYPTO_UTIL_H

#include "client_peer_manager.h"
#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_rekey_util.h"
#include "shared_net_tls_frame_io.h"

#include <cstdint>
#include <iostream>
#include <mutex>

#include <string>

#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

struct PeerInfo;
/*
// Forward declarations for globals from client_peer_manager.h
extern std::unordered_map<std::string, PeerInfo> peers;
extern std::mutex                                peers_mtx;
extern secure_vector                             my_eph_pk;
extern secure_vector                             my_eph_sk;
extern secure_vector                             my_identity_pk;
extern secure_vector                             my_identity_sk;
extern std::string                               my_username;
extern std::string                               my_fp_hex;
extern std::string                               session_id;
extern std::mutex                                ssl_io_mtx;
extern std::shared_ptr<ssl_socket>               ssl_stream;
*/
static void rotate_ephemeral_if_needed(const std::string &peer_fp)
{
    const std::lock_guard<std::mutex> lk(peers_mtx);
    const auto                        it = peers.find(peer_fp);
    if (it == peers.end() || !should_rekey(it->second.send_seq, REKEY_INTERVAL))
        return;

    const auto                 ms       = get_current_timestamp_ms();
    auto                       eph_pair = pqkem_keypair(KEM_ALG_NAME);
    secure_vector              new_pk   = eph_pair.first;
    secure_vector              new_sk   = eph_pair.second;
    std::vector<unsigned char> sig_data;
    sig_data.reserve(new_pk.size() + session_id.size());
    sig_data.insert(sig_data.end(), new_pk.begin(), new_pk.end());
    sig_data.insert(sig_data.end(), session_id.begin(), session_id.end());
    const std::vector<unsigned char> signature_vec =
        pqsig_sign(SIG_ALG_NAME,
                   std::vector<unsigned char>(my_identity_sk.begin(),
                                              my_identity_sk.end()),
                   sig_data);
    const std::vector<unsigned char> identity_pk_vec(my_identity_pk.begin(),
                                                     my_identity_pk.end());
    const std::vector<unsigned char> empty_encaps;
    const auto                       hello_frame = build_hello(
        my_username, ALGO_KEM_ALG_NAME,
        std::vector<unsigned char>(new_pk.begin(), new_pk.end()), ALGO_MLDSA87,
        identity_pk_vec, signature_vec, empty_encaps, session_id);
    auto frame_ptr = std::make_shared<std::vector<unsigned char>>(hello_frame);
    {
        const std::lock_guard<std::mutex> lk(peers_mtx);
        if (!ssl_stream)
            return;
        async_write_frame(ssl_stream, frame_ptr,
                          [frame_ptr](const std::error_code &, std::size_t) {});

        my_eph_pk     = new_pk;
        my_eph_sk     = new_sk;
        const auto it = peers.find(peer_fp);
        if (it != peers.end())
        {
            auto &pi    = it->second;
            pi.send_seq = 0;
            pi.ready    = false;
        }
    }
    dev_println("[" + std::to_string(ms) +
                "] rotated ephemeral key for peer_fp " + peer_fp);
}

// AAD Context Construction

struct KeyContextParams
{
  public:
    std::string my_fp{};
    std::string peer_fp{};
    std::string session_id{};

    struct MyFP
    {
        std::string_view v{};
        explicit MyFP(std::string_view s) noexcept : v(s) {}
    };
    struct PeerFP
    {
        std::string_view v{};
        explicit PeerFP(std::string_view s) noexcept : v(s) {}
    };
    struct SessionID
    {
        std::string_view v{};
        explicit SessionID(std::string_view s) noexcept : v(s) {}
    };

    static KeyContextParams make(MyFP my, PeerFP peer, SessionID sid)
    {
        return KeyContextParams(my.v, peer.v, sid.v);
    }

    KeyContextParams() = delete;

  private:
    explicit KeyContextParams(std::string_view my, std::string_view peer,
                              std::string_view sid)
        : my_fp(my), peer_fp(peer), session_id(sid)
    {
    }
};

static std::string build_key_context_for_peer(const KeyContextParams &ctx)
{
    if (ctx.my_fp.empty() || ctx.peer_fp.empty() || ctx.session_id.empty())
    {
        throw std::runtime_error("invalid key context parameters");
    }

    std::string a = ctx.my_fp;
    std::string b = ctx.peer_fp;
    if (a > b)
        std::swap(a, b);
    return a + "|" + b + "|" + ctx.session_id;
}

// Strong-typedef style small wrappers to avoid "easily-swappable-parameters"
struct PeerNameView
{
    std::string_view v{};
    explicit PeerNameView(std::string_view s) noexcept : v(s) {}
};

struct PeerKeyView
{
    std::string_view v{};
    explicit PeerKeyView(std::string_view s) noexcept : v(s) {}
};

struct KeyContextView
{
    std::string_view v{};
    explicit KeyContextView(std::string_view s) noexcept : v(s) {}
};

struct MsU
{
    uint64_t v{};
    explicit MsU(uint64_t x) noexcept : v(x) {}
};

struct MsS
{
    int64_t v{};
    explicit MsS(int64_t x) noexcept : v(x) {}
};

static bool try_handle_decaps_and_set_ready(PeerInfo &pi, const Parsed &p,
                                            PeerNameView   peer_name,
                                            KeyContextView key_context, MsS ms)
{
    try
    {
        const secure_vector shared =
            pqkem_decaps(KEM_ALG_NAME, p.encaps, my_eph_sk);
        pi.sk =
            derive_shared_key_from_secret(shared, std::string(key_context.v));
        std::cerr << "[KEY] Derived for " << std::string(peer_name.v)
                  << " key=" << to_hex(pi.sk.key).substr(0, 32)
                  << " context=" << std::string(key_context.v) << " (encaps)\n";
        dev_println("[" + std::to_string(ms.v) + "] DEBUG decaps: my=" +
                    my_username + " peer=" + std::string(peer_name.v) +
                    " context=" + std::string(key_context.v) +
                    " keysize=" + std::to_string(pi.sk.key.size()));
        pi.ready             = true;
        pi.identity_verified = true;
        return true;
    }
    catch (const std::exception &e)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: decapsulation failed for " +
                    std::string(peer_name.v) + " error=" + e.what());
        return false;
    }
}

static bool try_handle_initiator_encaps(PeerInfo &pi, const Parsed &p,
                                        PeerNameView   peer_name,
                                        KeyContextView key_context, MsS ms)
{
    try
    {
        // Recompute locally (safe and simple – no need to pass extra param)
        std::string peer_fp_hex =
            fingerprint_to_hex(fingerprint_sha256(std::vector<unsigned char>(
                pi.identity_pk.begin(), pi.identity_pk.end())));
        bool initiator = my_fp_hex < peer_fp_hex;

        dev_println(">>> INITIATOR SENDING ENCAPS! my=" + my_username +
                    " peer=" + std::string(peer_name.v) +
                    " initiator=" + std::to_string(initiator) +
                    " already_sent=" + std::to_string(pi.sent_hello));

        // Fixed: proper function call syntax (no stray ... and no extra comma)
        const auto enc_pair = pqkem_encaps(
            KEM_ALG_NAME,
            std::vector<unsigned char>(pi.eph_pk.begin(), pi.eph_pk.end()));

        const std::vector<unsigned char> encaps_ct = enc_pair.first;
        const secure_vector              shared    = enc_pair.second;

        pi.sk =
            derive_shared_key_from_secret(shared, std::string(key_context.v));
        std::cerr << "[KEY] Derived for " << std::string(peer_name.v)
                  << " key=" << to_hex(pi.sk.key).substr(0, 32)
                  << " context=" << std::string(key_context.v) << " (encaps)\n";

        dev_println("[" + std::to_string(ms.v) + "] DEBUG encaps: my=" +
                    my_username + " peer=" + std::string(peer_name.v) +
                    " context=" + std::string(key_context.v) +
                    " keysize=" + std::to_string(pi.sk.key.size()));

        pi.ready             = true;
        pi.identity_verified = true;

        std::vector<unsigned char> sig_data2;
        sig_data2.reserve(my_eph_pk.size() + p.session_id.size());
        sig_data2.insert(sig_data2.end(), my_eph_pk.begin(), my_eph_pk.end());
        sig_data2.insert(sig_data2.end(), p.session_id.begin(),
                         p.session_id.end());

        const std::vector<unsigned char> signature_vec =
            pqsig_sign(SIG_ALG_NAME,
                       std::vector<unsigned char>(my_identity_sk.begin(),
                                                  my_identity_sk.end()),
                       sig_data2);

        const std::vector<unsigned char> identity_pk_vec(my_identity_pk.begin(),
                                                         my_identity_pk.end());
        const auto                       reply = build_hello(
            my_username, ALGO_KEM_ALG_NAME,
            std::vector<unsigned char>(my_eph_pk.begin(), my_eph_pk.end()),
            ALGO_MLDSA87, identity_pk_vec, signature_vec, encaps_ct,
            p.session_id);

        auto frame_ptr = std::make_shared<std::vector<unsigned char>>(reply);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (!ssl_stream)
                return false;
            async_write_frame(
                ssl_stream, frame_ptr,
                [frame_ptr](const std::error_code &, std::size_t) {});
        }
        pi.sent_hello = true;
        return true;
    }
    catch (const std::exception &e)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: encapsulation failed for reply to " +
                    std::string(peer_name.v) + " error=" + e.what());
        return false;
    }
}

bool validate_username(MsU ms, PeerNameView peer_name)
{
    if (!is_valid_username(peer_name.v))
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: invalid username format");
        return false;
    }
    if (std::string(peer_name.v) == my_username)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: self-connection attempt");
        return false;
    }
    // Prevent Self-Session Exploits
    if (std::string(peer_name.v) == my_username)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: self-messaging blocked");
        return false;
    }
    return true;
}

// --- Fixed helper functions (compatible with original handle_hello) ---
bool check_peer_limits(MsU ms, PeerKeyView peer_key)
{
    if (peers.size() >= MAX_PEERS &&
        peers.find(std::string(peer_key.v)) == peers.end())
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: max peers limit reached");
    }
    return !(peers.size() >= MAX_PEERS &&
             peers.find(std::string(peer_key.v)) == peers.end());
}

inline bool check_hello_signature_core(const Parsed &p)
{
    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    return (p.id_alg == ALGO_MLDSA87)
               ? pqsig_verify(SIG_ALG_NAME, p.identity_pk, sig_data,
                              p.signature)
               : false;
}

struct TimestampMs
{
    int64_t value;
};

inline bool check_hello_signature(const Parsed &p, TimestampMs ms,
                                  const std::string &peer_name)
{
    bool sig_ok = check_hello_signature_core(p);
    if (!sig_ok)
        dev_println("[" + std::to_string(ms.value) +
                    "] REJECTED: invalid signature from " + peer_name);
    return sig_ok;
}

bool check_rate_and_signature(PeerInfo &pi, const Parsed &p, MsU ms,
                              PeerNameView peer_name)
{
    if (!check_rate_limit(pi))
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: rate limit exceeded for " +
                    std::string(peer_name.v));
        return false;
    }
    if (!check_hello_signature(p, TimestampMs{static_cast<int64_t>(ms.v)},
                               std::string(peer_name.v)))
    {
        return false;
    }
    return true;
}

struct ExpectedLengths
{
    size_t pk_len;
    size_t ct_len;
};

bool get_expected_lengths(ExpectedLengths &lengths, uint64_t ms)
{
#ifdef USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG_NAME);
    if (kem == nullptr)
    {
        dev_println("[" + std::to_string(ms) + "] REJECTED: kem init failed");
        return false;
    }
    lengths.pk_len = kem->length_public_key;
    lengths.ct_len = kem->length_ciphertext;
    OQS_KEM_free(kem);
#else
    lengths.pk_len = 0;
    lengths.ct_len = 0;
#endif
    return true;
}

bool validate_eph_pk_length(const Parsed &p, MsU ms, PeerNameView peer_name,
                            size_t expected_pk_len)
{
    if (p.eph_pk.size() != expected_pk_len)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: bad eph_pk length from " +
                    std::string(peer_name.v));
    }
    return p.eph_pk.size() == expected_pk_len;
}

bool handle_encaps_present(PeerInfo &pi, const Parsed &p, MsU ms,
                           PeerNameView peer_name, KeyContextView key_context,
                           size_t expected_ct_len)
{

    if (p.encaps.size() != expected_ct_len)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: bad encaps length from " +
                    std::string(peer_name.v));
        return false;
    }
    return try_handle_decaps_and_set_ready(pi, p, peer_name, key_context,
                                           MsS{static_cast<int64_t>(ms.v)});
}

bool handle_initiator_no_encaps(PeerInfo &pi, const Parsed &p, MsU ms,
                                PeerNameView   peer_name,
                                KeyContextView key_context,
                                size_t         expected_pk_len)
{

    if (pi.eph_pk.size() != expected_pk_len)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] INFO: missing peer eph_pk for " +
                    std::string(peer_name.v) + ", awaiting encaps");
        return false;
    }
    return try_handle_initiator_encaps(pi, p, peer_name, key_context,
                                       MsS{static_cast<int64_t>(ms.v)});
}

void log_awaiting_encaps(MsU ms, PeerNameView peer_name)
{
    std::cout << "[" << ms.v << "] INFO: awaiting encaps from "
              << std::string(peer_name.v) << "\n";
}
void log_ready_if_new(const PeerInfo &pi, uint64_t ms, bool was_ready,
                      const std::string &peer_name)
{
    if (!was_ready && pi.ready)
    {
        std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
    }
}

#endif