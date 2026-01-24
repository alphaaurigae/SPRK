#ifndef CLIENT_MESSAGE_UTIL_H
#define CLIENT_MESSAGE_UTIL_H

#include "client_crypto_util.h"
#include "client_peer_disconnect.h"
#include "client_peer_manager.h"
#include "client_runtime.h"
#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_key_util.h"
#include "shared_net_message_util.h"
#include "shared_net_rekey_util.h"
#include "shared_net_tls_frame_io.h"

#include <algorithm>
#include <array>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <cstdint>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

struct RecipientFP;


bool        validate_eph_pk_length(const Parsed &p, PeerNameView peer_name,
                                   ExpectedPkLen expected_pk_len, MsU ms);
bool        handle_encaps_present(PeerInfo &pi, const Parsed &p,
                                  PeerNameView peer_name, KeyContextView key_context,
                                  ExpectedCtLen expected_ct_len, MsU ms);
bool        try_handle_initiator_encaps(PeerInfo &pi, const Parsed &p,
                                        PeerNameView   peer_name,
                                        KeyContextView key_context, MsS ms);
std::string build_key_context_for_peer(const std::string &my_fp,
                                       const std::string &peer_fp_hex_ref,
                                       const std::string &session_id_val);
void        rotate_ephemeral_if_needed(const std::string &peer_fp);

inline std::string get_fingerprint_for_user(const std::string &username)

{

    const auto itset = peer_globals::fps_by_username().find(username);
    if (itset != peer_globals::fps_by_username().end() &&
        !itset->second.empty())

    {
        return *itset->second.begin();
    }
    return "(no fp)";
}

inline void process_list_response(const Parsed &p)
{

    const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
    std::cerr << "[" << get_current_timestamp_ms()
              << "] process_list_response: users_count=" << p.users.size()
              << "\n";
    std::cout << "users:\n";

    for (const auto &u : p.users)
    {
        std::string fp_display =
            (u == peer_globals::my_username() &&
             !peer_globals::my_identity_pk().empty())
                ? fingerprint_to_hex(
                      fingerprint_sha256(std::vector<unsigned char>(
                          peer_globals::my_identity_pk().begin(),
                          peer_globals::my_identity_pk().end())))
                : get_fingerprint_for_user(u);

        std::cout << u << " [" << fp_display << "]\n";
    }
}

inline void process_pubkey_response(const Parsed &p)
{

    const std::string hexpk =
        p.identity_pk.empty()
            ? std::string("(no pk)")
            : to_hex(p.identity_pk.data(), p.identity_pk.size());

    std::cerr << "[" << get_current_timestamp_ms()
              << "] process_pubkey_response: username='" << p.username
              << "' pk_len=" << p.identity_pk.size() << "\n";
    if (!p.identity_pk.empty())
    {
        try
        {
            const std::string fhex = compute_fingerprint_hex(p.identity_pk);

            const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
            auto                             &pi = peer_globals::peers()[fhex];
            pi.identity_pk =
                secure_vector(p.identity_pk.begin(), p.identity_pk.end());
            if (!p.username.empty())
            {
                pi.username = p.username;
                peer_globals::fps_by_username()[p.username].insert(fhex);
            }
        }

        catch (const std::exception &)
        {
            dev_println("fingerprint error: fingerprint computation failed");
        }
    }
    std::cout << "pubkey " << p.username << " " << hexpk << "\n";
}

struct PeerFpHexOut
{
    std::string *v{};
    explicit PeerFpHexOut(std::string &ref) noexcept : v{&ref} {}
};

struct PeerNameIn
{
    std::string_view v{};
    explicit PeerNameIn(std::string_view s) noexcept : v(s) {}
};

inline std::optional<std::string>
validate_and_compute_peer_key(const Parsed &p, PeerFpHexOut peer_fp_hex,
                              PeerNameIn peer_name, MsU ms)
{
    const auto key_opt = compute_peer_key(p, *peer_fp_hex.v);
    if (!key_opt.has_value())
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: hello without identity_pk from " +
                    std::string(peer_name.v));
        return std::nullopt;
    }
    return key_opt;
}

struct PeerKeyIn
{
    std::string_view v{};
    explicit PeerKeyIn(std::string_view s) noexcept : v(s) {}
};

struct PeerFpHexIn
{
    std::string_view v{};
    explicit PeerFpHexIn(std::string_view s) noexcept : v(s) {}
};

struct FpsSetRef
{
    std::unordered_set<std::string> *v{};
    explicit FpsSetRef(std::unordered_set<std::string> &ref) noexcept : v{&ref}
    {
    }
};

inline bool update_peer_state(PeerInfo &pi, const Parsed &p,
                              PeerNameIn peer_name, PeerKeyIn peer_key,
                              PeerFpHexIn peer_fp_hex, FpsSetRef fps_set,
                              MsU ms)
{
    update_peer_info(pi, PeerNameStr{peer_name.v}, PeerFpHexStr{peer_fp_hex.v},
                     *fps_set.v);

    if (!check_peer_limits(PeerKeyView{peer_key.v}, ms))
        return false;
    if (!check_rate_and_signature(pi, p, PeerNameView{peer_name.v}, ms))
        return false;

    bool pk_changed         = false;
    bool has_new_encaps     = false;
    bool needs_key_handling = false;
    needs_key_handling = detect_key_changes(pi, p, pk_changed, has_new_encaps);
    if (pk_changed)
        handle_rekey(pi, PeerNameStr{peer_name.v}, ms);
    if (!needs_key_handling && pi.ready)
        return false;

    update_keys_and_log_connect(pi, p, PeerNameStr{peer_name.v}, ms);
    return true;
}

struct SessionIdIn
{
    std::string_view v{};
    explicit SessionIdIn(std::string_view s) noexcept : v(s) {}
};

inline std::string build_key_context_for_session(PeerFpHexIn peer_fp_hex,
                                                 SessionIdIn session_id)
{
    return build_key_context_for_peer(KeyContextParams::make(
        KeyContextParams::MyFP{peer_globals::my_fp_hex()},
        KeyContextParams::PeerFP{peer_fp_hex.v},
        KeyContextParams::SessionID{session_id.v}));
}

namespace detail
{
struct KeyContextIn
{
    std::string_view v{};
    explicit KeyContextIn(std::string_view s) noexcept : v(s) {}
};

inline void maybe_send_list_request(const Parsed &p)
{
    if (!p.encaps.empty())
    {
        const std::vector<unsigned char> req{PROTO_VERSION, MSG_LIST_REQUEST};
        const auto                       frame = build_frame(req);
        auto frame_ptr = std::make_shared<std::vector<unsigned char>>(frame);
        std::lock_guard<std::mutex> lk(runtime_globals::ssl_io_mtx());
        if (runtime_globals::ssl_stream())
            async_write_frame(
                runtime_globals::ssl_stream(), frame_ptr,
                [frame_ptr](const std::error_code &, std::size_t) {});
    }
}

struct WasReadyFlag
{
    bool v{};
    explicit WasReadyFlag(bool x) noexcept : v(x) {}
};

inline void handle_ready_state(const Parsed &p, PeerNameIn peer_name,
                               PeerInfo &pi, WasReadyFlag was_ready, MsU ms)
{
    if (!was_ready.v && pi.ready)
    {
        std::cout << "[" << ms.v << "] peer " << std::string(peer_name.v)
                  << " ready\n";
        maybe_send_list_request(p);
    }
}

struct InitiatorFlag
{
    bool v{};
    explicit InitiatorFlag(bool x) noexcept : v(x) {}
};

inline bool process_peer_encaps(const Parsed &p, PeerNameIn peer_name,
                                PeerInfo &pi, KeyContextIn key_context,
                                const ExpectedLengths &expected,
                                InitiatorFlag initiator, MsU ms)
{
    const bool was_ready = pi.ready;

    if (!p.encaps.empty() || (initiator.v && !pi.sent_hello))
    {
        bool handled = false;
        handled =
            initiator.v
                ? try_handle_initiator_encaps(pi, p, PeerNameView{peer_name.v},
                                              KeyContextView{key_context.v},
                                              MsS{static_cast<int64_t>(ms.v)})
                : handle_encaps_present(pi, p, PeerNameView{peer_name.v},
                                        KeyContextView{key_context.v},
                                        ExpectedCtLen{expected.ct_len}, ms);

        if (handled)
            handle_ready_state(p, peer_name, pi, WasReadyFlag{was_ready}, ms);

        return handled;
    }

    return false;
}
}

inline void handle_hello(const Parsed &p)
{
    const std::string peer_name = trim(p.username);
    const uint64_t    ms        = get_current_timestamp_ms();

    std::cerr << "[" << ms << "] handle_hello: from='" << peer_name
              << "' eph_pk_len=" << p.eph_pk.size()
              << " encaps_len=" << p.encaps.size() << "\n";

    if (!validate_username(PeerNameView{peer_name}, MsU{ms}))
        return;

    const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());

    std::string peer_fp_hex;
    const auto  peer_key_opt = validate_and_compute_peer_key(
        p, PeerFpHexOut{peer_fp_hex}, PeerNameIn{peer_name}, MsU{ms});
    if (!peer_key_opt.has_value())
        return;
    const std::string peer_key = peer_key_opt.value();

    auto &pi      = peer_globals::peers()[peer_key];
    auto &fps_set = peer_globals::fps_by_username()[peer_name];

    if (!update_peer_state(pi, p, PeerNameIn{peer_name}, PeerKeyIn{peer_key},
                           PeerFpHexIn{peer_fp_hex}, FpsSetRef{fps_set},
                           MsU{ms}))
        return;

    ExpectedLengths expected{};
    if (!get_expected_lengths(expected, ms))
        return;

    if (!validate_eph_pk_length(p, PeerNameView{peer_name},
                                ExpectedPkLen{expected.pk_len}, MsU{ms}))
        return;

    const std::string key_context = build_key_context_for_session(
        PeerFpHexIn{peer_fp_hex}, SessionIdIn{p.session_id});

    const bool i_am_initiator =
        !peer_fp_hex.empty() && (peer_globals::my_fp_hex() < peer_fp_hex);

    if (!detail::process_peer_encaps(
            p, PeerNameIn{peer_name}, pi, detail::KeyContextIn{key_context},
            expected, detail::InitiatorFlag{i_am_initiator}, MsU{ms}))
    {
        if (!i_am_initiator)
        {
            if (pi.ready)
                dev_println("[" + std::to_string(ms) +
                            "] responder confirmed ready for " + peer_name);
            else
                log_awaiting_encaps(PeerNameView{peer_name}, MsU{ms});
        }
        else
            log_awaiting_encaps(PeerNameView{peer_name}, MsU{ms});
    }
}

struct PeerFromIn
{
    std::string_view v{};
    explicit PeerFromIn(std::string_view s) noexcept : v(s) {}
};

inline std::optional<PeerInfo *> validate_peer(const Parsed &p,
                                               PeerFromIn peer_from, MsU ms)
{
    if (!validate_username(PeerNameView{peer_from.v}, ms)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: invalid sender username");
        return std::nullopt;
    }

    if (p.identity_pk.empty()) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: chat without sender fingerprint");
        return std::nullopt;
    }

    const auto peer_key = to_hex(p.identity_pk.data(), p.identity_pk.size());
    auto       it       = peer_globals::peers().find(peer_key);
    if (it == peer_globals::peers().end()) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: peer not found for key " + peer_key);
        return std::nullopt;
    }

    PeerInfo &pi = it->second;

    if (!pi.ready) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) + "] REJECTED: peer " +
                    std::string(peer_from.v) + " not ready");
        return std::nullopt;
    }

    if (!check_rate_limit(pi)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: rate limit exceeded for " +
                    std::string(peer_from.v));
        return std::nullopt;
    }

    return &pi;
}

inline std::string compute_sender_fp_hex(const PeerInfo &pi)
{
    if (pi.identity_pk.empty())
        return {};
    const auto fp = fingerprint_sha256(std::vector<unsigned char>(
        pi.identity_pk.begin(), pi.identity_pk.end()));
    return fingerprint_to_hex(fp);
}

struct SenderFpHexIn
{
    std::string_view v{};
    explicit SenderFpHexIn(std::string_view s) noexcept : v(s) {}
};

struct SeqU64
{
    uint64_t v{};
    explicit SeqU64(uint64_t x) noexcept : v(x) {}
};

inline std::vector<unsigned char> build_aad_seq(SenderFpHexIn sender_fp_hex,
                                                SeqU64        seq)
{
    const std::string aad_s =
        AADBuilder{peer_globals::my_fp_hex(), std::string(sender_fp_hex.v)}
            .build_for_seq(seq.v);
    return std::vector<unsigned char>(aad_s.begin(), aad_s.end());
}

inline bool handle_sequence(PeerInfo &pi, SeqU64 seq, MsU ms,
                            PeerFromIn peer_from)
{
    if (is_replay_attack(seq.v, pi.recv_seq)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: replay attack from " +
                    std::string(peer_from.v) + " seq=" + std::to_string(seq.v) +
                    " < " + std::to_string(pi.recv_seq));
        return false;
    }

    if (!is_sequence_gap_valid(seq.v, pi.recv_seq, DEFAULT_MAX_SEQ_GAP,
                               DEFAULT_SEQ_JITTER_BUFFER)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: seq gap too large from " +
                    std::string(peer_from.v) + " got=" + std::to_string(seq.v) +
                    " expected=" + std::to_string(pi.recv_seq));
        return false;
    }

    bool jitter_detected = false;
    jitter_detected      = is_sequence_in_jitter_range(seq.v, pi.recv_seq,
                                                       DEFAULT_SEQ_JITTER_BUFFER);

    if (jitter_detected) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] WARNING: jitter detected from " +
                    std::string(peer_from.v) + " got=" + std::to_string(seq.v) +
                    " expected=" + std::to_string(pi.recv_seq));
        pi.recv_seq = seq.v;
    }
    else if (seq.v != pi.recv_seq) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms.v) +
                    "] REJECTED: seq mismatch from " +
                    std::string(peer_from.v) + " got=" + std::to_string(seq.v) +
                    " expected=" + std::to_string(pi.recv_seq));
        return false;
    }

    return true;
}

inline void handle_chat(const Parsed &p)
{
    const std::string peer_from = trim(p.from);
    const uint64_t    ms        = get_current_timestamp_ms();

    std::cerr << "[" << ms << "] handle_chat: from=" << peer_from
              << " seq=" << p.seq << " ct_len=" << p.ciphertext.size() << "\n";

    auto pi_opt = validate_peer(p, PeerFromIn{peer_from}, MsU{ms});
    if (!pi_opt)
        return;
    PeerInfo *pi = *pi_opt;

    if (is_message_timeout_exceeded(pi->last_recv_time, ms,
                                    DEFAULT_MESSAGE_TIMEOUT_MS)) [[unlikely]]
        dev_println("[" + std::to_string(ms) +
                    "] WARNING: large time gap from " + peer_from);

    if (!handle_sequence(*pi, SeqU64{p.seq}, MsU{ms}, PeerFromIn{peer_from}))
        [[unlikely]]
        return;

    try
    {
        const std::string sender_fp_hex = compute_sender_fp_hex(*pi);
        const auto        aad =
            build_aad_seq(SenderFpHexIn{sender_fp_hex}, SeqU64{p.seq});

        const auto pt = aead_decrypt(pi->sk.key, p.ciphertext, aad, p.nonce);
        if (pt.empty()) [[unlikely]]
        {
            dev_println("[" + std::to_string(ms) +
                        "] handle_chat: aead_decrypt returned empty for " +
                        peer_from);
            return;
        }
        if (pt.size() > 65535) [[unlikely]]
        {
            dev_println("[" + std::to_string(ms) +
                        "] REJECTED: invalid plaintext size from " + peer_from);
            return;
        }

        const std::string msg(pt.begin(), pt.end());
        const std::string ts = format_hhmmss(ms);

        if (peer_from == peer_globals::my_username()) [[unlikely]]
        {
            std::cout << "[" << ts << "] [sent] " << msg << "\n";
        }
        else
        {
            const std::string shortfp =
                sender_fp_hex.empty()
                    ? "(no fp)"
                    : sender_fp_hex.substr(
                          0, std::min<size_t>(10, sender_fp_hex.size()));
            std::cout << "[" << ts << "] [" << peer_from << " " << shortfp
                      << "] " << msg << "\n";
            std::cout.flush();
        }

        pi->recv_seq++;
        pi->last_recv_time = ms;
    }
    catch (const std::exception &)
    {
        std::cerr << "[" << ms << "] decrypt failed from=" << peer_from
                  << " seq=" << p.seq << "\n";
        return;
    }
}

inline std::vector<std::string> find_matching_peers(const std::string &token)
{
    std::vector<std::string> matches;
    for (const auto &kv : peer_globals::peers())
    {
        if (kv.first.size() >= token.size() &&
            std::equal(token.begin(), token.end(), kv.first.begin(),
                       [](char a, char b) noexcept
                       {
                           return std::tolower(static_cast<unsigned char>(a)) ==
                                  std::tolower(static_cast<unsigned char>(b));
                       }))
        {
            matches.push_back(kv.first);
        }
    }
    return matches;
}

inline std::vector<std::string>
resolve_fingerprint_recipients(const std::vector<std::string> &recipients)
{
    std::vector<std::string>          resolved;
    const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());

    for (const auto &token : recipients)
    {
        if (!is_valid_hex_token(token))
        {
            std::cout
                << "REJECTED: recipient must be hex fingerprint prefix (got: "
                << token << ")\n";
            continue;
        }

        const auto matches = find_matching_peers(token);

        if (matches.size() == 1)
        {
            const auto &fp = matches[0];
            if (fp.starts_with("uname:"))
            {
                std::cout << "REJECTED: cannot send to non-verified peer "
                          << token << "\n";
                continue;
            }
            resolved.push_back(matches[0]);
        }
        else if (matches.empty())
        {
            std::cout << "REJECTED: unknown fingerprint prefix " << token
                      << "\n";
        }
        else
        {
            std::cout << "REJECTED: ambiguous fingerprint prefix " << token
                      << "\n";
        }
    }
    return resolved;
}

inline std::vector<std::string>
get_ready_recipients(const std::vector<std::string> &resolved)
{
    std::vector<std::string>          ready;
    const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
    for (const auto &r : resolved)
    {
        const auto it = peer_globals::peers().find(r);
        if (it != peer_globals::peers().end() && it->second.ready)
        {
            ready.push_back(r);
        }
    }
    return ready;
}

inline bool send_message_to_peer(const std::string &msg,
                                 const RecipientFP &recipient_fp)
{
    rotate_ephemeral_if_needed(recipient_fp.value);

    const auto ctx = prepare_message_context(
        recipient_fp.value, peer_globals::my_fp_hex(), peer_globals::peers(),
        peer_globals::peers_mtx());
    if (!ctx.valid)
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] send_message_to_peer: context invalid for target="
                  << recipient_fp.value << "\n";
        return true;
    }

    const secure_vector nonce =
        derive_nonce_from_session(ctx.session_key, ctx.seq);

    const auto ct = aead_encrypt_with_nonce(
        ctx.session_key,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char *>(msg.data()), msg.size()),
        std::span<const unsigned char>(ctx.aad.data(), ctx.aad.size()), nonce);

    const auto frame =
        build_chat(ctx.target_username, peer_globals::my_username(),
                   compute_fingerprint_array(peer_globals::my_identity_pk()),
                   ctx.seq, nonce, ct);
    auto frame_ptr = std::make_shared<std::vector<unsigned char>>(frame);
    {
        std::lock_guard<std::mutex> lk(runtime_globals::ssl_io_mtx());
        if (!runtime_globals::ssl_stream())
        {
            runtime_globals::is_connected() = false;
            handle_disconnect(UsernameView{ctx.target_username},
                              FpHexView{recipient_fp.value});
            return false;
        }
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] send_message_to_peer: async_write_frame to "
                  << ctx.target_username << " seq=" << ctx.seq
                  << " frame_len=" << frame.size() << "\n";
        async_write_frame(
            runtime_globals::ssl_stream(), frame_ptr,
            [frame_ptr, target = ctx.target_username,
             fp = recipient_fp.value](const std::error_code &ec, std::size_t)
            {
                if (ec)
                {
                    std::cerr << "[" << get_current_timestamp_ms()
                              << "] send_message_to_peer: async_write_frame ec="
                              << ec.message() << " target=" << target << "\n";
                    runtime_globals::is_connected() = false;
                    handle_disconnect(UsernameView{target}, FpHexView{fp});
                }
                else
                {
                    std::cerr << "[" << get_current_timestamp_ms()
                              << "] send_message_to_peer: write completed to "
                              << target << "\n";
                }
            });
    }

    {
        const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
        auto &pi = peer_globals::peers()[recipient_fp.value];
        pi.send_seq++;
        pi.last_send_time = get_current_timestamp_ms();
    }

    const std::string ts = format_hhmmss(get_current_timestamp_ms());
    std::cout << "[" << ts << "] [" << ctx.target_username << " " << ctx.shortfp
              << "] \"" << msg << "\"\n";

    return true;
}

#endif
