#ifndef CLIENT_MESSAGE_UTIL_H
#define CLIENT_MESSAGE_UTIL_H

#include "client_crypto_util.h"
#include "client_peer_disconnect.h"
#include "client_peer_manager.h"
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
#include <string>
#include <unordered_set>
#include <vector>

struct RecipientFP;

extern std::mutex                  ssl_io_mtx;
extern std::shared_ptr<ssl_socket> ssl_stream;
extern std::atomic_bool            is_connected;

bool validate_username(PeerNameView peer_name, MsU ms);
bool check_peer_limits(PeerKeyView peer_key, MsU ms);
bool check_rate_and_signature(PeerInfo &pi, const Parsed &p,
                              PeerNameView peer_name, MsU ms);
struct ExpectedLengths;

bool        validate_eph_pk_length(const Parsed &p, PeerNameView peer_name,
                                   ExpectedPkLen expected_pk_len, MsU ms);
bool        handle_encaps_present(PeerInfo &pi, const Parsed &p,
                                  PeerNameView peer_name, KeyContextView key_context,
                                  ExpectedCtLen expected_ct_len, MsU ms);
bool        try_handle_initiator_encaps(PeerInfo &pi, const Parsed &p,
                                        PeerNameView   peer_name,
                                        KeyContextView key_context, MsS ms);
void        log_awaiting_encaps(PeerNameView peer_name, MsU ms);
std::string build_key_context_for_peer(const std::string &my_fp,
                                       const std::string &peer_fp_hex_ref,
                                       const std::string &session_id_val);
void        rotate_ephemeral_if_needed(const std::string &peer_fp);

inline std::string get_fingerprint_for_user(const std::string &username)

{

    const auto itset = fps_by_username.find(username);
    if (itset != fps_by_username.end() && !itset->second.empty())

    {
        return *itset->second.begin();
    }
    return "(no fp)";
}

inline void process_list_response(const Parsed &p)
{

    const std::lock_guard<std::mutex> lk(peers_mtx);
    std::cerr << "[" << get_current_timestamp_ms()
              << "] process_list_response: users_count=" << p.users.size()
              << "\n";
    std::cout << "users:\n";

    for (const auto &u : p.users)
    {
        std::string fp_display =
            (u == my_username && !my_identity_pk.empty())
                ? fingerprint_to_hex(
                      fingerprint_sha256(std::vector<unsigned char>(
                          my_identity_pk.begin(), my_identity_pk.end())))
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

            const std::lock_guard<std::mutex> lk(peers_mtx);
            auto                             &pi = peers[fhex];
            pi.identity_pk =
                secure_vector(p.identity_pk.begin(), p.identity_pk.end());
            if (!p.username.empty())
            {
                pi.username = p.username;
                fps_by_username[p.username].insert(fhex);
            }
        }
        catch (const std::exception &e)
        {
            dev_println("fingerprint error: " + std::string(e.what()));
        }
    }
    std::cout << "pubkey " << p.username << " " << hexpk << "\n";
}

inline void handle_hello(const Parsed &p)
{
    const std::string peer_name = trim(p.username);
    std::cerr << "[" << get_current_timestamp_ms() << "] handle_hello: from='"
              << peer_name << "' eph_pk_len=" << p.eph_pk.size()
              << " encaps_len=" << p.encaps.size() << "\n";

    const auto ms = get_current_timestamp_ms();
    if (!validate_username(PeerNameView{peer_name}, MsU{ms}))
        return;

    const std::lock_guard<std::mutex> lk(peers_mtx);
    std::string                       peer_fp_hex;
    const auto peer_key_opt = compute_peer_key(p, peer_fp_hex);
    if (!peer_key_opt.has_value())
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: hello without identity_pk from " + peer_name);
        return;
    }
    const std::string peer_key = peer_key_opt.value();
    std::cerr << "[" << ms << "] handle_hello: computed peer_key prefix="
              << (peer_key.size() ? peer_key.substr(0, std::min<size_t>(
                                                           peer_key.size(), 16))
                                  : "(empty)")
              << "\n";

    auto &pi      = peers[peer_key];
    auto &fps_set = fps_by_username[peer_name];
    update_peer_info(pi, PeerNameStr{peer_name}, PeerFpHexStr{peer_fp_hex},
                     fps_set);

    if (!check_peer_limits(PeerKeyView{peer_key}, MsU{ms}))
        return;
    if (!check_rate_and_signature(pi, p, PeerNameView{peer_name}, MsU{ms}))
        return;

    bool       pk_changed     = false;
    bool       has_new_encaps = false;
    const bool needs_key_handling =
        detect_key_changes(pi, p, pk_changed, has_new_encaps);

    if (pk_changed)
        handle_rekey(pi, PeerNameStr{peer_name}, MsU{ms});

    if (!needs_key_handling && pi.ready)
        return;

    update_keys_and_log_connect(pi, p, PeerNameStr{peer_name}, MsU{ms});

    ExpectedLengths expected{};
    if (!get_expected_lengths(expected, ms))
        return;

    if (!validate_eph_pk_length(p, PeerNameView{peer_name},
                                ExpectedPkLen{expected.pk_len}, MsU{ms}))
        return;

    const std::string key_context = build_key_context_for_peer(
        KeyContextParams::make(KeyContextParams::MyFP{my_fp_hex},
                               KeyContextParams::PeerFP{peer_fp_hex},
                               KeyContextParams::SessionID{p.session_id}));

    const bool was_ready = pi.ready;
    const bool i_am_initiator =
        !peer_fp_hex.empty() && (my_fp_hex < peer_fp_hex);

    if (!p.encaps.empty())
    {

        if (handle_encaps_present(pi, p, PeerNameView{peer_name},
                                  KeyContextView{key_context},
                                  ExpectedCtLen{expected.ct_len}, MsU{ms}))
        {
            if (!was_ready && pi.ready)
            {
                std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
                const std::vector<unsigned char> req{PROTO_VERSION,
                                                     MSG_LIST_REQUEST};
                const auto                       frame = build_frame(req);
                auto                             frame_ptr =
                    std::make_shared<std::vector<unsigned char>>(frame);
                std::lock_guard<std::mutex> lk2(ssl_io_mtx);
                if (ssl_stream)
                {
                    async_write_frame(
                        ssl_stream, frame_ptr,
                        [frame_ptr](const std::error_code &, std::size_t) {});
                }
            }
        }
    }

    else if (i_am_initiator && !pi.sent_hello)
    {
        if (try_handle_initiator_encaps(pi, p, PeerNameView{peer_name},
                                        KeyContextView{key_context},
                                        MsS{static_cast<int64_t>(ms)}))
        {
            if (!was_ready && pi.ready)
            {
                std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
            }
        }
    }

    else if (!i_am_initiator)
    {
        if (!p.encaps.empty())
        {
            if (handle_encaps_present(pi, p, PeerNameView{peer_name},
                                      KeyContextView{key_context},
                                      ExpectedCtLen{expected.ct_len}, MsU{ms}))
            {
                if (!was_ready && pi.ready)
                {
                    std::cout << "[" << ms << "] peer " << peer_name
                              << " ready\n";
                    const std::vector<unsigned char> req{PROTO_VERSION,
                                                         MSG_LIST_REQUEST};
                    const auto                       frame = build_frame(req);
                    auto                             frame_ptr =
                        std::make_shared<std::vector<unsigned char>>(frame);
                    std::lock_guard<std::mutex> lk2(ssl_io_mtx);
                    if (ssl_stream)
                    {
                        async_write_frame(ssl_stream, frame_ptr,
                                          [frame_ptr](const std::error_code &,
                                                      std::size_t) {});
                    }
                }
            }
        }
        else if (pi.ready)
        {
            dev_println("[" + std::to_string(ms) +
                        "] responder confirmed ready for " + peer_name);
        }
        else
        {
            log_awaiting_encaps(PeerNameView{peer_name}, MsU{ms});
        }
    }
    else
    {
        log_awaiting_encaps(PeerNameView{peer_name}, MsU{ms});
    }
}

inline void handle_chat(const Parsed &p)
{
    const std::string peer_from = trim(p.from);
    const auto        ms        = get_current_timestamp_ms();

    std::cerr << "[" << ms << "] handle_chat: from=" << peer_from
              << " seq=" << p.seq << " ct_len=" << p.ciphertext.size() << "\n";
    if (!validate_username(PeerNameView{peer_from}, MsU{ms})) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: invalid sender username");
        return;
    }

    if (p.identity_pk.empty()) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: chat without sender fingerprint");
        return;
    }

    const std::string peer_key =
        to_hex(p.identity_pk.data(), p.identity_pk.size());

    const auto it = peers.find(peer_key);
    if (it == peers.end()) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: peer not found for key " + peer_key);
        return;
    }

    PeerInfo &pi = it->second;

    if (!pi.ready) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) + "] REJECTED: peer " + peer_from +
                    " not ready");
        return;
    }

    if (!check_rate_limit(pi)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: rate limit exceeded for " + peer_from);
        return;
    }

    if (is_message_timeout_exceeded(pi.last_recv_time, ms,
                                    DEFAULT_MESSAGE_TIMEOUT_MS)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] WARNING: large time gap from " + peer_from);
    }

    if (is_replay_attack(p.seq, pi.recv_seq)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: replay attack from " + peer_from +
                    " seq=" + std::to_string(p.seq) + " < " +
                    std::to_string(pi.recv_seq));
        return;
    }

    if (!is_sequence_gap_valid(p.seq, pi.recv_seq, DEFAULT_MAX_SEQ_GAP,
                               DEFAULT_SEQ_JITTER_BUFFER)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: seq gap too large from " + peer_from +
                    " got=" + std::to_string(p.seq) +
                    " expected=" + std::to_string(pi.recv_seq));
        return;
    }

    const bool jitter_detected = is_sequence_in_jitter_range(
        p.seq, pi.recv_seq, DEFAULT_SEQ_JITTER_BUFFER);
    const bool seq_mismatch = p.seq != pi.recv_seq;

    if (jitter_detected) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] WARNING: jitter detected from " + peer_from +
                    " got=" + std::to_string(p.seq) +
                    " expected=" + std::to_string(pi.recv_seq));

        pi.recv_seq = p.seq;
    }
    else if (seq_mismatch) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: seq mismatch from=" + peer_from +
                    " got=" + std::to_string(p.seq) +
                    " expected=" + std::to_string(pi.recv_seq));
        return;
    }

    try
    {
        std::string sender_fp_hex;
        if (!pi.identity_pk.empty())
        {
            const auto fp = fingerprint_sha256(std::vector<unsigned char>(
                pi.identity_pk.begin(), pi.identity_pk.end()));
            sender_fp_hex = fingerprint_to_hex(fp);
        }

        const std::string aad_s =
            AADBuilder{my_fp_hex, sender_fp_hex}.build_for_seq(p.seq);

        std::vector<unsigned char> aad(aad_s.begin(), aad_s.end());

        std::cerr << "[CLIENT] Decrypting from " << peer_from
                  << " AAD=" << aad_s << "\n";

        const auto pt = aead_decrypt(pi.sk.key, p.ciphertext, aad, p.nonce);
        if (pt.empty())
            std::cerr << "[" << ms
                      << "] handle_chat: aead_decrypt returned empty\n";
        if (pt.empty() || pt.size() > 65535) [[unlikely]]
        {
            dev_println("[" + std::to_string(ms) +
                        "] REJECTED: invalid plaintext size from " + peer_from);
            return;
        }

        const std::string msg(pt.begin(), pt.end());
        const std::string ts = format_hhmmss(ms);

        if (peer_from == my_username) [[unlikely]]
        {
            std::cout << "[" << ts << "] [sent] " << msg << "\n";
        }
        else [[likely]]
        {
            const std::string shortfp = [&sender_fp_hex]() -> std::string
            {
                if (sender_fp_hex.empty())
                    return "(no fp)";
                if (sender_fp_hex.size() > 10)
                    return sender_fp_hex.substr(0, 10);
                return sender_fp_hex;
            }();

            std::cout << "[" << ts << "] [" << peer_from << " " << shortfp
                      << "] " << msg << "\n";
            std::cout.flush();
        }

        pi.recv_seq++;
        pi.last_recv_time = ms;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << ms << "] decrypt failed from=" << peer_from
                  << " seq=" << p.seq << " error=" << e.what() << "\n";
    }
}

inline std::vector<std::string> find_matching_peers(const std::string &token)
{
    std::vector<std::string> matches;
    for (const auto &kv : peers)
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
    const std::lock_guard<std::mutex> lk(peers_mtx);

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
    const std::lock_guard<std::mutex> lk(peers_mtx);
    for (const auto &r : resolved)
    {
        const auto it = peers.find(r);
        if (it != peers.end() && it->second.ready)
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

    const auto ctx = prepare_message_context(recipient_fp.value, my_fp_hex,
                                             peers, peers_mtx);
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

    const auto frame     = build_chat(ctx.target_username, my_username,
                                      compute_fingerprint_array(my_identity_pk),
                                      ctx.seq, nonce, ct);
    auto       frame_ptr = std::make_shared<std::vector<unsigned char>>(frame);
    {
        std::lock_guard<std::mutex> lk(ssl_io_mtx);
        if (!ssl_stream)
        {
            is_connected = false;
            handle_disconnect(UsernameView{ctx.target_username},
                              FpHexView{recipient_fp.value});
            return false;
        }
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] send_message_to_peer: async_write_frame to "
                  << ctx.target_username << " seq=" << ctx.seq
                  << " frame_len=" << frame.size() << "\n";
        async_write_frame(
            ssl_stream, frame_ptr,
            [frame_ptr, target = ctx.target_username,
             fp = recipient_fp.value](const std::error_code &ec, std::size_t)
            {
                if (ec)
                {
                    std::cerr << "[" << get_current_timestamp_ms()
                              << "] send_message_to_peer: async_write_frame ec="
                              << ec.message() << " target=" << target << "\n";
                    is_connected = false;
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
        const std::lock_guard<std::mutex> lk(peers_mtx);
        auto                             &pi = peers[recipient_fp.value];
        pi.send_seq++;
        pi.last_send_time = get_current_timestamp_ms();
    }

    const std::string ts = format_hhmmss(get_current_timestamp_ms());
    std::cout << "[" << ts << "] [" << ctx.target_username << " " << ctx.shortfp
              << "] \"" << msg << "\"\n";

    return true;
}

#endif