#ifndef CLIENT_CRYPTO_UTIL_H
#define CLIENT_CRYPTO_UTIL_H

#include "client_peer_manager.h"
#include "client_runtime.h"
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

static void rotate_ephemeral_if_needed(const std::string &peer_fp)
{
    const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
    const auto                        it = peer_globals::peers().find(peer_fp);
    if (it == peer_globals::peers().end() ||
        !should_rekey(it->second.send_seq, REKEY_INTERVAL))
        return;

    const auto    ms       = get_current_timestamp_ms();
    auto          eph_pair = pqkem_keypair(KEM_ALG_NAME);
    secure_vector new_pk   = eph_pair.first;
    secure_vector new_sk   = eph_pair.second;

    std::vector<unsigned char> sig_data;
    sig_data.reserve(new_pk.size() + peer_globals::session_id().size());
    sig_data.insert(sig_data.end(), new_pk.begin(), new_pk.end());
    sig_data.insert(sig_data.end(), peer_globals::session_id().begin(),
                    peer_globals::session_id().end());

    const std::vector<unsigned char> signature_vec = pqsig_sign(
        SIG_ALG_NAME,
        std::vector<unsigned char>(peer_globals::my_identity_sk().begin(),
                                   peer_globals::my_identity_sk().end()),
        sig_data);

    const std::vector<unsigned char> identity_pk_vec(
        peer_globals::my_identity_pk().begin(),
        peer_globals::my_identity_pk().end());

    const auto hello_frame =
        build_hello(peer_globals::my_username(), ALGO_KEM_ALG_NAME,
                    std::vector<unsigned char>(new_pk.begin(), new_pk.end()),
                    ALGO_MLDSA87, identity_pk_vec, signature_vec,
                    std::vector<unsigned char>{}, peer_globals::session_id());

    auto frame_ptr = std::make_shared<std::vector<unsigned char>>(hello_frame);
    {
        const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
        if (!runtime_globals::ssl_stream())
            return;
        async_write_frame(runtime_globals::ssl_stream(), frame_ptr,
                          [frame_ptr](const std::error_code &, std::size_t) {});

        peer_globals::my_eph_pk() = new_pk;
        peer_globals::my_eph_sk() = new_sk;
        const auto it             = peer_globals::peers().find(peer_fp);
        if (it != peer_globals::peers().end())
        {
            auto &pi    = it->second;
            pi.send_seq = 0;
            pi.ready    = false;
        }
    }
    dev_println("[" + std::to_string(ms) +
                "] rotated ephemeral key for peer_fp " + peer_fp);
}

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

    struct MyFPIn
    {
        std::string_view v{};
        explicit MyFPIn(std::string_view s) noexcept : v(s) {}
    };
    struct PeerFPIn
    {
        std::string_view v{};
        explicit PeerFPIn(std::string_view s) noexcept : v(s) {}
    };
    struct SessionIDIn
    {
        std::string_view v{};
        explicit SessionIDIn(std::string_view s) noexcept : v(s) {}
    };
    static KeyContextParams make(MyFP my, PeerFP peer, SessionID sid)
    {
        return KeyContextParams(MyFPIn{my.v}, PeerFPIn{peer.v},
                                SessionIDIn{sid.v});
    }

    KeyContextParams() = delete;

  private:
    explicit KeyContextParams(MyFPIn my, PeerFPIn peer, SessionIDIn sid)
        : my_fp(my.v), peer_fp(peer.v), session_id(sid.v)
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

struct MsS
{
    int64_t v{};
    explicit MsS(int64_t x) noexcept : v(x) {}
};

struct ExpectedPkLen
{
    size_t v{};
    explicit ExpectedPkLen(size_t x) noexcept : v(x) {}
};

struct ExpectedCtLen
{
    size_t v{};
    explicit ExpectedCtLen(size_t x) noexcept : v(x) {}
};

static bool try_handle_decaps_and_set_ready(PeerInfo &pi, const Parsed &p,
                                            PeerNameView   peer_name,
                                            KeyContextView key_context, MsS ms)
{
    try
    {
        const secure_vector shared =
            pqkem_decaps(KEM_ALG_NAME, p.encaps, peer_globals::my_eph_sk());
        pi.sk =
            derive_shared_key_from_secret(shared, std::string(key_context.v));
        std::cerr << "[KEY] Derived for " << std::string(peer_name.v)
                  << " key=" << to_hex(pi.sk.key).substr(0, 32)
                  << " context=" << std::string(key_context.v) << " (encaps)\n";
        dev_println("[" + std::to_string(ms.v) +
                    "] DEBUG decaps: my=" + peer_globals::my_username() +
                    " peer=" + std::string(peer_name.v) +
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
        std::string peer_fp_hex =
            fingerprint_to_hex(fingerprint_sha256(std::vector<unsigned char>(
                pi.identity_pk.begin(), pi.identity_pk.end())));
        bool initiator = peer_globals::my_fp_hex() < peer_fp_hex;

        dev_println(
            ">>> INITIATOR SENDING ENCAPS! my=" + peer_globals::my_username() +
            " peer=" + std::string(peer_name.v) +
            " initiator=" + std::to_string(initiator) +
            " already_sent=" + std::to_string(pi.sent_hello));

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

        dev_println("[" + std::to_string(ms.v) +
                    "] DEBUG encaps: my=" + peer_globals::my_username() +
                    " peer=" + std::string(peer_name.v) +
                    " context=" + std::string(key_context.v) +
                    " keysize=" + std::to_string(pi.sk.key.size()));

        pi.ready             = true;
        pi.identity_verified = true;

        std::vector<unsigned char> sig_data2;
        sig_data2.reserve(peer_globals::my_eph_pk().size() +
                          p.session_id.size());
        sig_data2.insert(sig_data2.end(), peer_globals::my_eph_pk().begin(),
                         peer_globals::my_eph_pk().end());
        sig_data2.insert(sig_data2.end(), p.session_id.begin(),
                         p.session_id.end());

        const std::vector<unsigned char> signature_vec = pqsig_sign(
            SIG_ALG_NAME,
            std::vector<unsigned char>(peer_globals::my_identity_sk().begin(),
                                       peer_globals::my_identity_sk().end()),
            sig_data2);

        const std::vector<unsigned char> identity_pk_vec(
            peer_globals::my_identity_pk().begin(),
            peer_globals::my_identity_pk().end());
        const auto reply = build_hello(
            peer_globals::my_username(), ALGO_KEM_ALG_NAME,
            std::vector<unsigned char>(peer_globals::my_eph_pk().begin(),
                                       peer_globals::my_eph_pk().end()),
            ALGO_MLDSA87, identity_pk_vec, signature_vec, encaps_ct,
            p.session_id);

        auto frame_ptr = std::make_shared<std::vector<unsigned char>>(reply);
        {
            std::lock_guard<std::mutex> lk(runtime_globals::ssl_io_mtx());
            if (!runtime_globals::ssl_stream())
                return false;
            async_write_frame(
                runtime_globals::ssl_stream(), frame_ptr,
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

bool validate_username(PeerNameView peer_name, MsU ms)
{
    if (!is_valid_username(peer_name.v))
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: invalid username format");
        return false;
    }
    if (std::string(peer_name.v) == peer_globals::my_username())
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: self-connection attempt");
        return false;
    }
    if (std::string(peer_name.v) == peer_globals::my_username())
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: self-messaging blocked");
        return false;
    }
    return true;
}

bool check_peer_limits(PeerKeyView peer_key, MsU ms)
{
    if (peer_globals::peers().size() >= MAX_PEERS &&
        peer_globals::peers().find(std::string(peer_key.v)) ==
            peer_globals::peers().end())
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: max peer_globals::peers() limit reached");
    }
    return !(peer_globals::peers().size() >= MAX_PEERS &&
             peer_globals::peers().find(std::string(peer_key.v)) ==
                 peer_globals::peers().end());
}

inline bool check_hello_signature_core(const Parsed &p)
{
    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    if (p.id_alg != ALGO_MLDSA87)
        return false;

    bool ok = false;
    ok      = pqsig_verify(
        SIG_ALG_NAME, p.identity_pk, sig_data,
        std::vector<unsigned char>(p.signature.begin(), p.signature.end()));
    if (!ok)
    {
        std::cerr << "[DEBUG] check_hello_signature_core: signature "
                     "verification failed"
                  << " peer_session_len=" << p.session_id.size()
                  << " local_session_len=" << peer_globals::session_id().size()
                  << " peer_identity_key="
                  << compute_fingerprint_hex(p.identity_pk) << "\n";
    }
    return ok;
}

struct TimestampMs
{
    int64_t value;
};

inline bool check_hello_signature(const Parsed &p, TimestampMs ms,
                                  const std::string &peer_name)
{
    bool sig_ok{};
    sig_ok = check_hello_signature_core(p);
    if (!sig_ok)
        dev_println("[" + std::to_string(ms.value) +
                    "] REJECTED: invalid signature from " + peer_name);
    return sig_ok;
}

bool check_rate_and_signature(PeerInfo &pi, const Parsed &p,
                              PeerNameView peer_name, MsU ms)
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

bool validate_eph_pk_length(const Parsed &p, PeerNameView peer_name,
                            ExpectedPkLen expected_pk_len, MsU ms)
{
    if (p.eph_pk.size() != expected_pk_len.v)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: bad eph_pk length from " +
                    std::string(peer_name.v));
    }
    return p.eph_pk.size() == expected_pk_len.v;
}

bool handle_encaps_present(PeerInfo &pi, const Parsed &p,
                           PeerNameView peer_name, KeyContextView key_context,
                           ExpectedCtLen expected_ct_len, MsU ms)
{

    if (p.encaps.size() != expected_ct_len.v)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: bad encaps length from " +
                    std::string(peer_name.v));
        return false;
    }
    return try_handle_decaps_and_set_ready(pi, p, peer_name, key_context,
                                           MsS{static_cast<int64_t>(ms.v)});
}

bool handle_initiator_no_encaps(PeerInfo &pi, const Parsed &p,
                                PeerNameView   peer_name,
                                KeyContextView key_context,
                                ExpectedPkLen expected_pk_len, MsU ms)
{

    if (pi.eph_pk.size() != expected_pk_len.v)
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] INFO: missing peer eph_pk for " +
                    std::string(peer_name.v) + ", awaiting encaps");
        return false;
    }
    return try_handle_initiator_encaps(pi, p, peer_name, key_context,
                                       MsS{static_cast<int64_t>(ms.v)});
}

void log_awaiting_encaps(PeerNameView peer_name, MsU ms)
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
