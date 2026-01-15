#pragma once

#include "common_crypto.h"
#include "net_common_protocol.h"
#include "common_util.h"
#include "net_tls_context.h"
#include "net_socket_util.h"
#include "net_tls_frame_io.h"
#include "net_username_util.h"
#include "net_rekey_util.h"
#include "net_message_util.h"
#include "net_key_util.h"
#include "peer_manager.h"
#include "client_runtime.h"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h> 
#include <csignal>



inline bool init_oqs_provider()

{
    static OSSL_PROVIDER *oqsprov = nullptr;
    if (!oqsprov)
    {
        oqsprov = OSSL_PROVIDER_load(nullptr, "oqsprovider");
        if (!oqsprov)
        {
            std::cerr << "Failed to load oqsprovider\n";
            ERR_print_errors_fp(stderr);
            return false;
        }
    }
    return true;
}

struct KeyPath { std::string value; };
struct AlgorithmName { std::string value; };

static void rotate_ephemeral_if_needed([[maybe_unused]] int sock, const std::string &peer_fp)
{
    bool do_rotate = false;
    {
        const std::lock_guard<std::mutex> lk(peers_mtx);
        const auto                        it = peers.find(peer_fp);
        if (it != peers.end() && should_rekey(it->second.send_seq, REKEY_INTERVAL))

        {
            do_rotate = true;
        }
    }
    if (!do_rotate)
        return;

    const auto ms = get_current_timestamp_ms();

    auto          eph_pair = pqkem_keypair("Kyber512");
    secure_vector new_pk   = eph_pair.first;
    secure_vector new_sk   = eph_pair.second;

    std::vector<unsigned char> sig_data;
    sig_data.reserve(new_pk.size() + session_id.size());
    sig_data.insert(sig_data.end(), new_pk.begin(), new_pk.end());
    sig_data.insert(sig_data.end(), session_id.begin(), session_id.end());

    const std::vector<unsigned char> signature_vec =
        pqsig_sign("ML-DSA-87",
                   std::vector<unsigned char>(my_identity_sk.begin(),
                                              my_identity_sk.end()),
                   sig_data);

    const std::vector<unsigned char> identity_pk_vec(my_identity_pk.begin(),
                                                     my_identity_pk.end());
    const std::vector<unsigned char> empty_encaps;
    const auto                       hello_frame = build_hello(
        my_username, ALGO_KYBER512,
        std::vector<unsigned char>(new_pk.begin(), new_pk.end()), ALGO_MLDSA87,
        identity_pk_vec, signature_vec, empty_encaps, session_id);

    tls_full_send(ssl, hello_frame.data(), hello_frame.size());

    {
        const std::lock_guard<std::mutex> lk(peers_mtx);
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

static bool check_hello_signature(const Parsed &p, const std::string &peer_name, int64_t ms)
{
    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    const bool sig_ok =
        (p.id_alg == ALGO_MLDSA87)
            ? pqsig_verify("ML-DSA-87", p.identity_pk, sig_data, p.signature)
            : false;
    if (!sig_ok)
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: invalid signature from " + peer_name);
    return sig_ok;
}

static std::string build_key_context_for_peer(const std::string &peer_fp_hex_ref, const std::string &peer_name)
{
    return !my_fp_hex.empty() && !peer_fp_hex_ref.empty()
        ? build_key_derivation_context(my_fp_hex, peer_fp_hex_ref)
        : build_username_context(my_username, peer_name);
}

static bool try_handle_decaps_and_set_ready(PeerInfo &pi, const Parsed &p,
                                            const std::string &key_context,
                                            const std::string &peer_name,
                                            int64_t            ms)
{
    try
    {
        const secure_vector shared =
            pqkem_decaps("Kyber512", p.encaps, my_eph_sk);
        pi.sk = derive_shared_key_from_secret(shared, key_context);
        dev_println("[" + std::to_string(ms) +
                    "] DEBUG decaps: my=" + my_username + " peer=" + peer_name +
                    " context=" + key_context +
                    " keysize=" + std::to_string(pi.sk.key.size()));
        pi.ready             = true;
        pi.identity_verified = true;
        return true;
    }
    catch (const std::exception &e)
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: decapsulation failed for " + peer_name +
                    " error=" + e.what());
        return false;
    }
}

static bool try_handle_initiator_encaps(PeerInfo &pi, const Parsed &p, const std::string &key_context, [[maybe_unused]] int sock, const std::string &peer_name, int64_t ms) {
    try {
        // Recompute locally (safe and simple – no need to pass extra param)
        std::string peer_fp_hex = fingerprint_to_hex(
            fingerprint_sha256(std::vector<unsigned char>(
                pi.identity_pk.begin(), pi.identity_pk.end())));

        bool initiator = my_fp_hex < peer_fp_hex;

        dev_println(">>> INITIATOR SENDING ENCAPS! my=" + my_username + " peer=" + peer_name 
                    + " initiator=" + std::to_string(initiator) 
                    + " already_sent=" + std::to_string(pi.sent_hello));

        // Fixed: proper function call syntax (no stray ... and no extra comma)
        const auto enc_pair = pqkem_encaps(
            "Kyber512",
            std::vector<unsigned char>(pi.eph_pk.begin(), pi.eph_pk.end()));

        const std::vector<unsigned char> encaps_ct = enc_pair.first;
        const secure_vector shared = enc_pair.second;

        pi.sk = derive_shared_key_from_secret(shared, key_context);
        dev_println("[" + std::to_string(ms) +
                    "] DEBUG encaps: my=" + my_username + " peer=" + peer_name +
                    " context=" + key_context +
                    " keysize=" + std::to_string(pi.sk.key.size()));

        pi.ready             = true;
        pi.identity_verified = true;

        std::vector<unsigned char> sig_data2;
        sig_data2.reserve(my_eph_pk.size() + p.session_id.size());
        sig_data2.insert(sig_data2.end(), my_eph_pk.begin(), my_eph_pk.end());
        sig_data2.insert(sig_data2.end(), p.session_id.begin(),
                         p.session_id.end());

        const std::vector<unsigned char> signature_vec =
            pqsig_sign("ML-DSA-87",
                       std::vector<unsigned char>(my_identity_sk.begin(),
                                                  my_identity_sk.end()),
                       sig_data2);

        const std::vector<unsigned char> identity_pk_vec(my_identity_pk.begin(),
                                                         my_identity_pk.end());
        const auto                       reply = build_hello(
            my_username, ALGO_KYBER512,
            std::vector<unsigned char>(my_eph_pk.begin(), my_eph_pk.end()),
            ALGO_MLDSA87, identity_pk_vec, signature_vec, encaps_ct,
            p.session_id);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            tls_full_send(ssl, reply.data(), reply.size());
        }
        pi.sent_hello = true;
        return true;
    }
    catch (const std::exception &e)
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: encapsulation failed for reply to " +
                    peer_name + " error=" + e.what());
        return false;
    }
}


bool validate_username(const std::string &peer_name, uint64_t ms)
{
    if (!is_valid_username(peer_name))
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: invalid username format");
        return false;
    }
    if (peer_name == my_username)
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: self-connection attempt");
        return false;
    }
    return true;
}

// --- Fixed helper functions (compatible with original handle_hello) ---
bool check_peer_limits(const std::string &peer_key, uint64_t ms)
{
    if (peers.size() >= MAX_PEERS && peers.find(peer_key) == peers.end())
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: max peers limit reached");
        return false;
    }
    return true;
}

bool check_rate_and_signature(PeerInfo &pi, const Parsed &p, const std::string &peer_name, uint64_t ms)
{
    if (!check_rate_limit(pi))
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: rate limit exceeded for " + peer_name);
        return false;
    }
    if (!check_hello_signature(p, peer_name, static_cast<int64_t>(ms)))
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
    OQS_KEM *kem = OQS_KEM_new("Kyber512");
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

bool validate_eph_pk_length(const Parsed &p, size_t expected_pk_len, const std::string &peer_name, uint64_t ms)
{
    if (p.eph_pk.size() != expected_pk_len)
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: bad eph_pk length from " + peer_name);
        return false;
    }
    return true;
}


bool handle_encaps_present(PeerInfo &pi, const Parsed &p,
                           size_t             expected_ct_len,
                           const std::string &key_context,
                           const std::string &peer_name, uint64_t ms)
{
    if (p.encaps.size() != expected_ct_len)
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: bad encaps length from " + peer_name);
        return false;
    }
    return try_handle_decaps_and_set_ready(pi, p, key_context, peer_name,
                                           static_cast<int64_t>(ms));
}

bool handle_initiator_no_encaps(PeerInfo &pi, const Parsed &p,
                                size_t             expected_pk_len,
                                const std::string &key_context, int sock,
                                const std::string &peer_name, uint64_t ms)
{
    if (pi.eph_pk.size() != expected_pk_len)
    {
        dev_println("[" + std::to_string(ms) +
                    "] INFO: missing peer eph_pk for " + peer_name +
                    ", awaiting encaps");
        return false;
    }
    return try_handle_initiator_encaps(pi, p, key_context, sock, peer_name,
                                       static_cast<int64_t>(ms));
}


void log_awaiting_encaps(const std::string &peer_name, uint64_t ms)
{
    std::cout << "[" << ms << "] INFO: awaiting encaps from " << peer_name
              << "\n";
}

void log_ready_if_new(const PeerInfo &pi, const std::string &peer_name,
                      uint64_t ms, bool was_ready)
{
    if (!was_ready && pi.ready)
    {
        std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
    }
}