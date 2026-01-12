#include "crypto.h"
#include "protocol.h"
#include "util.h"
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

struct PeerInfo
{
    std::string   username;
    secure_vector eph_pk;
    secure_vector identity_pk;
    std::string   peer_fp_hex;
    SessionKey    sk;
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

static constexpr uint32_t REKEY_INTERVAL         = 1024;
static constexpr uint32_t MAX_SEQ_GAP            = 100;
static constexpr uint64_t MESSAGE_TIMEOUT_MS     = 60000;
static constexpr size_t   MAX_PEERS              = 256;
static constexpr size_t   MAX_USERNAME_LEN       = 64;
static constexpr uint32_t RATE_LIMIT_MSGS        = 100;
static constexpr uint64_t RATE_LIMIT_WINDOW_MS   = 1000;
static constexpr uint32_t SEQ_JITTER_BUFFER      = 3;
static constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
static constexpr uint64_t INITIAL_BACKOFF_MS     = 1000;
static constexpr uint64_t MAX_BACKOFF_MS         = 60000;
static constexpr size_t   MIN_FP_PREFIX_HEX      = 16;
static constexpr size_t   SESSION_ID_LENGTH      = 60;

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
namespace
{
inline std::unordered_map<std::string, PeerInfo> peers;
inline std::unordered_map<std::string, std::unordered_set<std::string>>
                        fps_by_username;
inline std::mutex       peers_mtx;
inline std::string      my_username;
inline std::string      session_id;
inline secure_vector    my_eph_pk;
inline secure_vector    my_eph_sk;
inline secure_vector    my_identity_pk;
inline secure_vector    my_identity_sk;
inline std::string      my_fp_hex;
inline bool             debug_mode = false;
inline std::atomic_bool should_reconnect{true};
inline std::atomic_bool is_connected{false};
} // namespace
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

inline SSL_CTX* ssl_ctx = nullptr;
inline SSL* ssl = nullptr;
inline std::mutex ssl_io_mtx;



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

inline void dev_print(std::string_view s)
{
    if (debug_mode)
        std::cout << s;
}

inline void dev_println(std::string_view s)
{
    if (debug_mode)
        std::cout << s << "\n";
}

inline uint64_t now_ms() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

inline std::string format_hhmmss(uint64_t ms)
{
    const auto t = static_cast<std::time_t>(ms / 1000);
    std::tm    tm{};
    localtime_r(&t, &tm);

    return std::format("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

inline std::string trim(std::string s)
{
    const auto is_space = [](unsigned char c) noexcept -> bool
    { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c)
                                    { return !is_space(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [&](unsigned char c) { return !is_space(c); })
                .base(),
            s.end());
    return s;
}

inline bool is_valid_username(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= MAX_USERNAME_LEN &&
           std::all_of(
               name.begin(), name.end(), [](unsigned char c) noexcept
               { return (std::isalnum(c) != 0) || c == '_' || c == '-'; });
}
static SSL_CTX* init_tls_client_context(const std::string& client_cert_path,
                                        const std::string& client_key_path)
{
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    SSL_CTX* ctx = SSL_CTX_new_ex(nullptr, nullptr, TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256");

    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519") != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // User-supplied TLS client certificate + key
    if (SSL_CTX_use_certificate_file(ctx, client_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, client_key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load user-supplied client cert/key:\n"
                  << "  cert: " << client_cert_path << "\n"
                  << "  key:  " << client_key_path << "\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Hardcoded trusted CA bundle for server verification
    if (SSL_CTX_load_verify_locations(ctx, "sample/sample_test_cert/ca.crt", nullptr) <= 0) {
        std::cerr << "Failed to load trusted CA bundle for server verification\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    std::cout << "Client TLS ready (user-supplied):\n"
              << "  Cert: " << client_cert_path << "\n"
              << "  Key:  " << client_key_path << "\n"
              << "  Using trusted CA bundle for server\n"
              << "  Hybrid KEM: X25519MLKEM768\n";
    return ctx;
}
inline bool is_valid_session_id(std::string_view sid) noexcept
{
    if (sid.size() != SESSION_ID_LENGTH)
        return false;
    constexpr std::string_view base58_chars =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return std::all_of(
        sid.begin(), sid.end(), [&](char c) noexcept
        { return base58_chars.find(c) != std::string_view::npos; });
}

inline std::string generate_session_id()
{
    constexpr std::string_view base58_chars =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    constexpr size_t       CHARSET          = base58_chars.size();
    constexpr unsigned int REJECT_THRESHOLD = 256U / CHARSET * CHARSET;
    std::string            sid;
    sid.reserve(SESSION_ID_LENGTH);
    unsigned char b = 0;
    for (size_t i = 0; i < SESSION_ID_LENGTH; ++i)
    {
        while (true)
        {
            if (RAND_bytes(&b, 1) != 1)
                throw std::runtime_error("RAND_bytes failed");
            if (static_cast<unsigned int>(b) < REJECT_THRESHOLD)
            {
                sid += base58_chars[static_cast<unsigned int>(b) % CHARSET];
                break;
            }
        }
    }
    return sid;
}

struct PQKeypair
{
    secure_vector              sk;
    std::vector<unsigned char> pk;
};

inline std::vector<unsigned char> read_file_raw(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("cannot open key file");
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

struct KeyPath
{
    std::string value;
};
struct AlgorithmName
{
    std::string value;
};

struct SessionId
{
    std::string value;
};

struct PeerName
{
    std::string value;
};

inline PQKeypair derive_ephemeral_for_peer(const secure_vector &identity_sk,
                                           const SessionId     &session_id,
                                           const PeerName      &peer)
{
#ifdef USE_LIBOQS
    std::vector<unsigned char> salt(session_id.value.begin(),
                                    session_id.value.end());
    salt.insert(salt.end(), peer.value.begin(), peer.value.end());

    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (kem == nullptr)
        throw std::runtime_error("pqkem new failed");

    const secure_vector derived_key =
        hkdf(identity_sk, salt, kem->length_secret_key);
    OQS_KEM_free(kem);

    auto pqkp = pqkem_keypair_from_seed("Kyber512", derived_key);

    PQKeypair ret;
    ret.pk.assign(pqkp.first.begin(), pqkp.first.end());
    ret.sk = secure_vector(pqkp.second.begin(), pqkp.second.end());
    return ret;
#else
    throw std::runtime_error("liboqs not enabled at build");
#endif
}

int connect_to(const std::string &host, int port)
{
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        close(s);
        return -1;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
        close(s);
        return -1;
    }

    return s;
}

static bool check_rate_limit(PeerInfo &pi) noexcept
{
    const uint64_t now = now_ms();
    if (now - pi.rate_limit_window_start > RATE_LIMIT_WINDOW_MS)
    {
        pi.rate_limit_counter      = 0;
        pi.rate_limit_window_start = now;
    }
    return ++pi.rate_limit_counter <= RATE_LIMIT_MSGS;
}

static void rotate_ephemeral_if_needed([[maybe_unused]] int sock, const std::string &peer_fp)
{
    bool do_rotate = false;
    {
        const std::lock_guard<std::mutex> lk(peers_mtx);
        const auto                        it = peers.find(peer_fp);
        if (it != peers.end() && it->second.send_seq >= REKEY_INTERVAL)
        {
            do_rotate = true;
        }
    }
    if (!do_rotate)
        return;

    const auto ms = now_ms();

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

static bool check_hello_signature(const Parsed &p, const std::string &peer_name,
                                  int64_t ms)
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

static std::string
build_key_context_for_peer(const std::string &peer_fp_hex_ref,
                           const std::string &peer_name)
{
    if (!my_fp_hex.empty() && !peer_fp_hex_ref.empty())
        return (my_fp_hex < peer_fp_hex_ref)
                   ? (my_fp_hex + "|" + peer_fp_hex_ref)
                   : (peer_fp_hex_ref + "|" + my_fp_hex);

    return (my_username < peer_name) ? (my_username + "|" + peer_name)
                                     : (peer_name + "|" + my_username);
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

static bool try_handle_initiator_encaps(PeerInfo &pi, const Parsed &p,
                                        const std::string &key_context,
                                        [[maybe_unused]] int sock, const std::string &peer_name,
                                        int64_t ms) {
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

std::string compute_peer_key(const Parsed &p, std::string &peer_fp_hex)
{
    if (!p.identity_pk.empty())
    {
        const auto fp = fingerprint_sha256(p.identity_pk);
        peer_fp_hex   = fingerprint_to_hex(fp);
        return peer_fp_hex;
    }
    return "uname:" + trim(p.username);
}

void update_peer_info(PeerInfo &pi, const std::string &peer_name,
                      const std::string               &peer_fp_hex,
                      std::unordered_set<std::string> &fps_set)
{
    pi.username = peer_name;
    if (!peer_fp_hex.empty())
    {
        fps_set.insert(peer_fp_hex);
        pi.peer_fp_hex = peer_fp_hex;
    }
    else
    {
        const std::string peer_key = "uname:" + peer_name;
        fps_set.insert(peer_key);
        pi.peer_fp_hex = peer_key;
    }
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

bool check_rate_and_signature(PeerInfo &pi, const Parsed &p,
                              const std::string &peer_name, uint64_t ms)
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

void handle_rekey(PeerInfo &pi, const std::string &peer_name, uint64_t ms)
{
    pi.recv_seq   = 0;
    pi.send_seq   = 0;
    pi.ready      = false;
    pi.sent_hello = false;
    pi.sk.key.clear();
    pi.identity_verified = false;
    std::cout << "[" << ms << "] peer " << peer_name << " rekeyed\n";
}

void update_keys_and_log_connect(PeerInfo &pi, const Parsed &p,
                                 const std::string &peer_name, uint64_t ms)
{
    pi.eph_pk      = secure_vector(p.eph_pk.begin(), p.eph_pk.end());
    pi.identity_pk = secure_vector(p.identity_pk.begin(), p.identity_pk.end());

    const std::string ts      = format_hhmmss(ms);
    std::string       shortpk = "(no pk)";
    if (!p.identity_pk.empty())
    {
        const std::string hexpk =
            to_hex(p.identity_pk.data(), p.identity_pk.size());
        shortpk = (hexpk.size() > 20) ? hexpk.substr(0, 10) + "..." +
                                            hexpk.substr(hexpk.size() - 10)
                                      : hexpk;
    }
    std::cout << "[" << ts << "] connect " << peer_name << " pubkey=" << shortpk
              << "\n";
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

bool validate_eph_pk_length(const Parsed &p, size_t expected_pk_len,
                            const std::string &peer_name, uint64_t ms)
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

void handle_hello(const Parsed &p, int sock)
{
    const std::string peer_name = trim(p.username);
    const auto ms = now_ms();
    if (!validate_username(peer_name, ms)) return;
    
    const std::lock_guard<std::mutex> lk(peers_mtx);
    std::string peer_fp_hex;
    const std::string peer_key = compute_peer_key(p, peer_fp_hex);
    auto &pi = peers[peer_key];
    auto &fps_set = fps_by_username[peer_name];
    update_peer_info(pi, peer_name, peer_fp_hex, fps_set);
    
    if (!check_peer_limits(peer_key, ms)) return;
    if (!check_rate_and_signature(pi, p, peer_name, ms)) return;
    
    bool pk_changed = false;
    bool has_new_encaps = false;
    const bool needs_key_handling = detect_key_changes(pi, p, pk_changed, has_new_encaps);
    
    if (pk_changed) handle_rekey(pi, peer_name, ms);
    
    if (!needs_key_handling && pi.ready) return;
    
    update_keys_and_log_connect(pi, p, peer_name, ms);
    
    ExpectedLengths expected{};
    if (!get_expected_lengths(expected, ms)) return;
    if (!validate_eph_pk_length(p, expected.pk_len, peer_name, ms)) return;
    
    const std::string key_context = build_key_context_for_peer(peer_fp_hex, peer_name);
    const bool was_ready = pi.ready;
    const bool i_am_initiator = !peer_fp_hex.empty() && (my_fp_hex < peer_fp_hex);
    
    if (!p.encaps.empty()) {
        if (handle_encaps_present(pi, p, expected.ct_len, key_context, peer_name, ms)) {
            if (!was_ready && pi.ready) {
                std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
                const std::vector<unsigned char> req{PROTO_VERSION, MSG_LIST_REQUEST};
                const auto frame = build_frame(req);
                std::lock_guard<std::mutex> lk(ssl_io_mtx);
                tls_full_send(ssl, frame.data(), frame.size());
            }
        }
    } else if (i_am_initiator && !pi.sent_hello) {
        if (try_handle_initiator_encaps(pi, p, key_context, sock, peer_name, ms)) {
            if (!was_ready && pi.ready) {
                std::cout << "[" << ms << "] peer " << peer_name << " ready\n";
            }
        }
    } else if (!i_am_initiator && p.encaps.empty() && pi.ready) {
        dev_println("[" + std::to_string(ms) + "] responder confirmed ready for " + peer_name);
    } else {
        log_awaiting_encaps(peer_name, ms);
    }
}

void handle_chat(const Parsed &p)
{
    const std::string peer_from = trim(p.from);
    const auto        ms        = now_ms();

    if (!is_valid_username(peer_from)) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: invalid sender username");
        return;
    }

    std::string peer_key;
    if (!p.identity_pk.empty()) [[likely]]
    {
        peer_key = to_hex(p.identity_pk.data(), p.identity_pk.size());
    }
    else [[unlikely]]
    {
        dev_println(
            "[" + std::to_string(ms) +
            "] REJECTED: peer must be identified by fingerprint, not username");
        return;
    }

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

    if (pi.last_recv_time > 0 && (ms - pi.last_recv_time) > MESSAGE_TIMEOUT_MS)
        [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] WARNING: large time gap from " + peer_from);
    }

    if (p.seq < pi.recv_seq) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: replay attack from " + peer_from +
                    " seq=" + std::to_string(p.seq) + " < " +
                    std::to_string(pi.recv_seq));
        return;
    }

    if (p.seq - pi.recv_seq > MAX_SEQ_GAP + SEQ_JITTER_BUFFER) [[unlikely]]
    {
        dev_println("[" + std::to_string(ms) +
                    "] REJECTED: seq gap too large from " + peer_from +
                    " got=" + std::to_string(p.seq) +
                    " expected=" + std::to_string(pi.recv_seq));
        return;
    }

    const bool jitter_detected =
        p.seq > pi.recv_seq && p.seq - pi.recv_seq <= SEQ_JITTER_BUFFER;
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
            pi.peer_fp_hex + "|" + my_fp_hex + "|" + std::to_string(p.seq);
        std::vector<unsigned char> aad(aad_s.begin(), aad_s.end());

        const auto pt = aead_decrypt(pi.sk.key, p.ciphertext, aad, p.nonce);
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
        }

        pi.recv_seq++;
        pi.last_recv_time = ms;
    }
    catch (const std::exception &e)
    {
        std::cout << "[" << ms << "] decrypt failed from=" << peer_from
                  << " seq=" << p.seq << " error=" << e.what() << "\n";
    }
}

// === Helper functions (placed BEFORE reader_thread in the .cpp file) ===

inline std::string get_fingerprint_for_user(const std::string &username)
{
    const auto itset = fps_by_username.find(username);
    if (itset != fps_by_username.end() && !itset->second.empty())
    {
        for (const auto &fp_candidate : itset->second)
        {
            const auto pit = peers.find(fp_candidate);
            if (pit != peers.end() && !pit->second.identity_pk.empty())
            {
                const auto fp_arr = fingerprint_sha256(
                    std::vector<unsigned char>(pit->second.identity_pk.begin(),
                                               pit->second.identity_pk.end()));
                return fingerprint_to_hex(fp_arr);
            }
        }
    }
    return "(no fp)";
}

inline void process_list_response(const Parsed &p)
{
    const std::lock_guard<std::mutex> lk(peers_mtx);
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

    if (!p.identity_pk.empty())
    {
        try
        {
            const auto        fp_arr = fingerprint_sha256(p.identity_pk);
            const std::string fhex   = fingerprint_to_hex(fp_arr);

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

inline bool tls_read_frame(SSL* ssl, std::vector<unsigned char>& frame_out)
{
    unsigned char header[4];
    size_t total = 0;

    while (total < 4) {
        ssize_t r = SSL_read(ssl, header + total, 4 - total);
        if (r <= 0) {
            int err = SSL_get_error(ssl, static_cast<int>(r));
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                dev_println("[" + std::to_string(now_ms()) + "] peer closed connection cleanly");
                return false;
            }
            dev_println("[" + std::to_string(now_ms()) + "] header read failed, err=" + std::to_string(err));
            return false;
        }
        total += static_cast<size_t>(r);
    }

    uint32_t payload_len = read_u32_be(header);
    if (payload_len > 65536 || payload_len < 2) {
        dev_println("[" + std::to_string(now_ms()) + "] invalid payload len: " + std::to_string(payload_len));
        return false;
    }

    frame_out.resize(4 + payload_len);
    std::memcpy(frame_out.data(), header, 4);

    total = 0;
    while (total < payload_len) {
        ssize_t r = SSL_read(ssl, frame_out.data() + 4 + total, payload_len - total);
        if (r <= 0) {
            int err = SSL_get_error(ssl, static_cast<int>(r));
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                dev_println("[" + std::to_string(now_ms()) + "] peer closed connection during payload");
                return false;
            }
            dev_println("[" + std::to_string(now_ms()) + "] payload read failed, err=" + std::to_string(err));
            return false;
        }
        total += static_cast<size_t>(r);
    }

    dev_println("[" + std::to_string(now_ms()) + "] received frame, size=" + std::to_string(frame_out.size()));
    return true;
}


void reader_thread(int sock, SSL *ssl)
{
    while (should_reconnect && is_connected)
    {
        if (!ssl || !SSL_is_init_finished(ssl)) {
            dev_println("[" + std::to_string(now_ms()) + "] SSL not ready in reader thread");
            is_connected = false;
            break;
        }
        
        std::vector<unsigned char> frame;
        if (!tls_read_frame(ssl, frame)) {
            is_connected = false;
            break;
        }

        try
        {
            std::span<const unsigned char> frame_span(frame);
            const Parsed p = parse_payload(frame_span.subspan(4).data(), frame_span.size() - 4);

            if (p.type == MSG_HELLO) handle_hello(p, sock);
            else if (p.type == MSG_CHAT) handle_chat(p);
            else if (p.type == MSG_LIST_RESPONSE) process_list_response(p);
            else if (p.type == MSG_PUBKEY_RESPONSE) process_pubkey_response(p);
        }
        catch (const std::exception &e)
        {
            std::cout << "parse error: " << e.what() << "\n";
        }
    }
}

inline bool is_valid_hex_token(const std::string &token) noexcept
{
    return token.size() >= MIN_FP_PREFIX_HEX &&
           std::all_of(token.begin(), token.end(), [](unsigned char c) noexcept
                       { return std::isxdigit(c) != 0; });
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
            std::cout << "REJECTED: recipient must be a hex fingerprint "
                      << token << "\n";
            continue;
        }

        const auto matches = find_matching_peers(token);

        if (matches.size() == 1)
        {
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

struct MessageContext
{
    std::vector<unsigned char> aad;
    uint32_t                   seq = 0;
    secure_vector              session_key;
    std::string                shortfp         = "(no fp)";
    std::string                target_username = "(unknown)";
    bool                       valid           = false;
};

inline MessageContext prepare_message_context(const std::string &recipient_key)
{
    MessageContext ctx;

    const std::lock_guard<std::mutex> lk(peers_mtx);
    const auto                        it = peers.find(recipient_key);
    if (it == peers.end())
        return ctx;

    const auto &pi      = it->second;
    ctx.seq             = pi.send_seq;
    ctx.session_key     = pi.sk.key;
    ctx.target_username = pi.username;

    if (!pi.identity_pk.empty())
    {
        const auto        fp    = fingerprint_sha256(std::vector<unsigned char>(
            pi.identity_pk.begin(), pi.identity_pk.end()));
        const std::string hexfp = fingerprint_to_hex(fp);
        ctx.shortfp = (hexfp.size() > 10) ? hexfp.substr(0, 10) : hexfp;
    }

    const std::string aad_s =
        my_fp_hex + "|" + pi.peer_fp_hex + "|" + std::to_string(ctx.seq);
    ctx.aad.assign(aad_s.begin(), aad_s.end());
    ctx.valid = true;
    return ctx;
}

// Returns true if the line was a command that was fully handled
inline bool handle_client_command(const std::string &line, 
                                  [[maybe_unused]] int sock, SSL *ssl)
{
    if (line == "help")
    {
        std::cout << "q                         quit\n"
                     "list | list users         list connected users\n"
                     "pubk <username>           fetch user public key\n"
                     "<fp[,fp...]> <message>    send message to peer(s)\n";
        return true;
    }

    if (line == "q")
    {
        should_reconnect = false;
        is_connected     = false;
        return true;
    }

    if (line == "list" || line == "list users" || line == "list user")
    {
        const std::vector<unsigned char> p{PROTO_VERSION, MSG_LIST_REQUEST};
        const auto                       f = build_frame(p);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (tls_full_send(ssl, f.data(), f.size()) <= 0)
            {
                is_connected = false;
            }
        }
        {
        }
        return true;
    }

    if (line.starts_with("pubk "))
    {
        const std::string who = trim(line.substr(5));
        if (!is_valid_username(who))
        {
            std::cout << "invalid username\n";
            return true;
        }
        const auto req = build_pubkey_request(who);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (tls_full_send(ssl, req.data(), req.size()) <= 0)
            {
                is_connected = false;
            }
        }
        return true;
    }

    return false;
}

// Recipient parsing
inline std::vector<std::string> parse_recipient_list(const std::string &input)
{
    std::vector<std::string> recipients;
    size_t                   start = 0;
    while (true)
    {
        const auto comma = input.find(',', start);
        if (comma == std::string::npos)
        {
            const std::string r = trim(input.substr(start));
            if (!r.empty())
                recipients.push_back(r);
            break;
        }
        const std::string r = trim(input.substr(start, comma - start));
        if (!r.empty())
            recipients.push_back(r);
        start = comma + 1;
    }
    return recipients;
}

// Strong type to prevent swapping msg and recipient_fp
struct RecipientFP
{
    std::string value;
    explicit RecipientFP(std::string fp) : value(std::move(fp)) {}
    [[nodiscard]] const std::string &str() const & { return value; }
    [[nodiscard]] std::string      &&str()      &&{ return std::move(value); }
};

// Lazy, thread-safe, immutable my fingerprint — no globals, no flags
inline const std::array<unsigned char, 32> &get_my_fingerprint_array()
{
    static const std::array<unsigned char, 32> my_fp = []()
    {
        std::array<unsigned char, 32> arr{};
        const auto fp = fingerprint_sha256(std::vector<unsigned char>(
            my_identity_pk.begin(), my_identity_pk.end()));
        std::copy(fp.begin(), fp.end(), arr.begin());
        return arr;
    }();
    return my_fp;
}

// "Flawless Victory!"
inline bool send_message_to_peer(int sock, const std::string &msg,
                                 const RecipientFP &recipient_fp, SSL *ssl)

{
    rotate_ephemeral_if_needed(sock, recipient_fp.value);

    const auto ctx = prepare_message_context(recipient_fp.value);
    if (!ctx.valid)
    {
        return true;
    }

    const secure_vector nonce =
        derive_nonce_from_session(ctx.session_key, ctx.seq);

    const auto ct = aead_encrypt_with_nonce(
        ctx.session_key, std::vector<unsigned char>(msg.begin(), msg.end()),
        ctx.aad, nonce);

    const auto frame =
        build_chat(ctx.target_username, my_username, get_my_fingerprint_array(),
                   ctx.seq, nonce, ct);

    {
        std::lock_guard<std::mutex> lk(ssl_io_mtx);
        if (tls_full_send(ssl, frame.data(), frame.size()) <= 0)
        {
            is_connected = false;
            return false;
        }
    }

    {
        const std::lock_guard<std::mutex> lk(peers_mtx);
        auto                             &pi = peers[recipient_fp.value];
        pi.send_seq++;
        pi.last_send_time = now_ms();
    }

    const std::string ts = format_hhmmss(now_ms());
    std::cout << "[" << ts << "] [" << ctx.target_username << " " << ctx.shortfp
              << "] \"" << msg << "\"\n";

    return true;
}

// "I am the fire to your ice.", "I do what I must to return home."



void writer_thread(int sock, SSL *ssl)
{
    std::string line;
    bool eof_notified = false;

    while (is_connected.load(std::memory_order_acquire))
    {
        if (!std::getline(std::cin, line))
        {
            if (std::cin.eof())
            {
                if (!eof_notified)
                {
                    std::cerr << "[" << now_ms() << "] writer_thread: stdin EOF; entering poll mode\n";
                    eof_notified = true;
                }
                std::cin.clear();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            std::cerr << "[" << now_ms() << "] writer_thread: std::getline failed\n";
            is_connected.store(false, std::memory_order_release);
            break;
        }

        eof_notified = false;

        if (!is_connected.load(std::memory_order_acquire)) break;

        if (handle_client_command(line, sock, ssl))
            continue;

        const std::size_t pos = line.find(' ');
        if (pos == std::string::npos)
        {
            std::cout << "usage: <recipient> <message>\n";
            continue;
        }

        const std::string to  = trim(line.substr(0, pos));
        const std::string msg = line.substr(pos + 1);

        if (msg.empty() || msg.size() > 65535)
        {
            std::cout << "invalid message size\n";
            continue;
        }

        const auto recipients = parse_recipient_list(to);
        const auto resolved_recipients = resolve_fingerprint_recipients(recipients);
        const auto ready_recipients = get_ready_recipients(resolved_recipients);

        if (ready_recipients.empty())
        {
            std::cout << "peer not ready\n";
            continue;
        }

        for (const auto &r : ready_recipients)
        {
            if (!send_message_to_peer(sock, msg, RecipientFP{r}, ssl))
            {
                int err = SSL_get_error(ssl, 0);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                    dev_println("[" + std::to_string(now_ms()) + "] send would block, retrying...");
                    continue;  // temporary, try next loop iteration
                }
                std::cerr << "[" << now_ms() << "] send failed (err=" << err << ") - peer/server likely dropped connection\n";
                is_connected.store(false, std::memory_order_release);
                break;
            }
        }
    }

    // Do not close the socket here. Let main/connection loop perform orderly shutdown.
}

// --- 1. Command line parsing ---
struct ConnectionConfig
{
    std::string server;
    int         port{};
    std::string username;
    std::string client_cert_path;
    std::string client_key_path;
};

inline ConnectionConfig parse_command_line_args(std::span<char *> args)
{
    if (args.size() < 5)
    {
        std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                     "<private_key_path> [--sessionid <id>] [--debug]\n\n"
                     "Runtime commands:\n"
                     "help                      show commands\n"
                     "q                         quit\n"
                     "list | list users         list connected users\n"
                     "pubk <username>           fetch user public key\n"
                     "<fp[,fp...]> <message>    send message to peer(s)\n";
        std::exit(1);
    }

    for (std::size_t i = 1; i < args.size(); ++i)
    {
        if (std::string_view(args[i]) == "--debug")
        {
            debug_mode = true;
        }
    }

    ConnectionConfig config;
    config.server   = args[1];
    config.username = trim(args[3]);

    try
    {
        config.port = std::stoi(args[2]);
    }
    catch (const std::exception &)
    {
        std::cout << "Invalid port number\n";
        std::exit(1);
    }

    if (!is_valid_username(config.username))
    {
        std::cout
            << "Invalid username. Use only alphanumeric, underscore, hyphen\n";
        std::exit(1);
    }

    return config;
}

// --- 2. Identity key loading ---
// Helper: Load PEM private key and extract raw sk + pk for protocol use
inline bool load_pem_private_key(const std::string& path,
                                 secure_vector& out_sk,
                                 secure_vector& out_pk) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        std::cerr << "Cannot open PEM file: " << path << "\n";
        return false;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        std::cerr << "Failed to read PEM private key from " << path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Extract raw secret key bytes (ML-DSA-87 secret key)
    size_t sk_len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &sk_len) <= 0) {
        EVP_PKEY_free(pkey);
        return false;
    }
    std::vector<unsigned char> raw_sk(sk_len);
    if (EVP_PKEY_get_raw_private_key(pkey, raw_sk.data(), &sk_len) <= 0) {
        EVP_PKEY_free(pkey);
        return false;
    }
    out_sk.assign(raw_sk.begin(), raw_sk.end());

    // Extract raw public key bytes
    size_t pk_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pk_len) <= 0) {
        EVP_PKEY_free(pkey);
        return false;
    }
    std::vector<unsigned char> raw_pk(pk_len);
    if (EVP_PKEY_get_raw_public_key(pkey, raw_pk.data(), &pk_len) <= 0) {
        EVP_PKEY_free(pkey);
        return false;
    }
    out_pk.assign(raw_pk.begin(), raw_pk.end());

    EVP_PKEY_free(pkey);
    return true;
}

// --- 2. Identity key loading (PEM version only) ---
inline bool load_identity_keys(const char* key_path) {
    try {
        secure_vector raw_sk, raw_pk;
        if (!load_pem_private_key(key_path, raw_sk, raw_pk)) {
            return false;
        }

        if (raw_sk.empty()) {
            throw std::runtime_error("identity secret key missing");
        }
        my_identity_sk = std::move(raw_sk);

        if (raw_pk.empty()) {
            throw std::runtime_error("identity public key not present");
        }
        my_identity_pk = std::move(raw_pk);

        const auto fp = fingerprint_sha256(std::vector<unsigned char>(
            my_identity_pk.begin(), my_identity_pk.end()));
        my_fp_hex = fingerprint_to_hex(fp);

        std::cout << "Loaded PEM identity key: " << key_path << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cout << "Failed to load private/public key: " << e.what() << "\n";
        return false;
    }
}

// --- 3. Session ID handling ---
inline bool setup_session_id(std::span<char *> args)
{
    std::string_view session_flag = "--sessionid";
    std::string_view alt_flag = "-sessionid";

    for (size_t i = 1; i < args.size() - 1; ++i) {  // -1 because we need next arg
        std::string_view arg = args[i];

        if (arg == session_flag || arg == alt_flag) {
            session_id = args[i + 1];
            if (!is_valid_session_id(session_id)) {
                std::cout << "Invalid session_id format\n";
                return false;
            }
            std::cout << "Using provided session: " << session_id << "\n";
            return true;
        }
    }

    // Fallback: generate new
    session_id = generate_session_id();
    std::cout << "Created session: " << session_id << "\n";
    return true;
}

// --- 4. Single connection attempt ---
inline int attempt_connection(const std::string &server, int port,
                              secure_vector &persisted_eph_pk,
                              secure_vector &persisted_eph_sk,
                              bool          &have_persisted_eph)
{
    // Generate persistent ephemeral keypair once
    if (!have_persisted_eph)
    {
        const auto [pk, sk] = pqkem_keypair("Kyber512");
        persisted_eph_pk    = pk;
        persisted_eph_sk    = sk;
        have_persisted_eph  = true;
    }

    my_eph_pk = persisted_eph_pk;
    my_eph_sk = persisted_eph_sk;

    int s = connect_to(server, port);
    if (s < 0)
    {
        std::cout << "[" << now_ms() << "] connection failed\n";
        return -1;
    }

    SSL* new_ssl = SSL_new(ssl_ctx);
    if (!new_ssl)
    {
        std::cerr << "SSL_new failed\n";
        ERR_print_errors_fp(stderr);
        close(s);
        return -1;
    }

    SSL_set_fd(new_ssl, s);

    int ret = SSL_connect(new_ssl);
    if (ret <= 0)
    {
        int err = SSL_get_error(new_ssl, ret);
        std::cerr << "SSL_connect failed (err=" << err << ")\n";
        ERR_print_errors_fp(stderr);
        SSL_free(new_ssl);
        close(s);
        return -1;
    }

    std::cout << "[" << now_ms() << "] TLS handshake successful\n";
    {
        std::lock_guard<std::mutex> lk(ssl_io_mtx);
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ssl = new_ssl;
    }

      std::vector<unsigned char> sig_data;
      sig_data.reserve(my_eph_pk.size() + session_id.size());
      sig_data.insert(sig_data.end(), my_eph_pk.begin(), my_eph_pk.end());
      sig_data.insert(sig_data.end(), session_id.begin(), session_id.end());

      const auto signature =
          pqsig_sign("ML-DSA-87",
                     std::vector<unsigned char>(my_identity_sk.begin(),
                                                my_identity_sk.end()),
                     sig_data);

      const auto hello_frame = build_hello(
          my_username, ALGO_KYBER512,
          std::vector<unsigned char>(my_eph_pk.begin(), my_eph_pk.end()),
          ALGO_MLDSA87,
          std::vector<unsigned char>(my_identity_pk.begin(),
                                     my_identity_pk.end()),
          signature, std::vector<unsigned char>{}, session_id);

      {
          std::lock_guard<std::mutex> lk(ssl_io_mtx);
          if (tls_full_send(ssl, hello_frame.data(), hello_frame.size()) <= 0)
          {
              std::cout << "[" << now_ms() << "] failed to send hello\n";
              SSL_free(ssl);
              ssl = nullptr;
              close(s);
              return -1;
          }
      }

      return s;
}

int main(int argc, char **argv) noexcept
try
{
      const std::span args(argv, static_cast<std::size_t>(argc));

      const auto config = parse_command_line_args(args);
      my_username       = config.username;

      std::signal(SIGPIPE, SIG_IGN);

      if (!load_identity_keys(args[4]))
      {
          return 1;
      }

      if (!setup_session_id(args))
      {
          return 1;
      }

      if (args.size() < 6)
      {
          std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                       "<identity_sk.pem> <client_cert.crt> "
                       "[--sessionid <id>] [--debug]\n";
          return 1;
      }

      std::string client_key_path  = args[4];
      std::string client_cert_path = args[5];

      crypto_init();

      if (!init_oqs_provider())
      {
          std::cerr << "Cannot continue without OQS provider\n";
          return 1;
      }

      OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(nullptr, "default");
      if (!default_prov)
      {
          std::cerr << "Failed to load default provider\n";
          return 1;
      }

      OSSL_PROVIDER *oqs_prov = OSSL_PROVIDER_load(nullptr, "oqsprovider");
      if (!oqs_prov)
      {
          std::cerr << "Failed to load oqsprovider\n";
          OSSL_PROVIDER_unload(default_prov);
          return 1;
      }

      ssl_ctx = SSL_CTX_new_ex(nullptr, nullptr, TLS_client_method());
      if (!ssl_ctx)
      {
          std::cerr << "SSL_CTX_new failed\n";
          ERR_print_errors_fp(stderr);
          OSSL_PROVIDER_unload(oqs_prov);
          OSSL_PROVIDER_unload(default_prov);
          return 1;
      }

      SSL_CTX_set_security_level(ssl_ctx, 0);
      SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
      SSL_CTX_set_ciphersuites(ssl_ctx,
                               "TLS_AES_256_GCM_SHA384:"
                               "TLS_CHACHA20_POLY1305_SHA256:"
                               "TLS_AES_128_GCM_SHA256");

      if (SSL_CTX_set1_groups_list(ssl_ctx, "X25519MLKEM768:X25519") != 1)
      {
          std::cerr << "Failed to set KEM groups\n";
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(ssl_ctx);
          ssl_ctx = nullptr;
          OSSL_PROVIDER_unload(oqs_prov);
          OSSL_PROVIDER_unload(default_prov);
          return 1;
      }

      std::string cert_path =
          std::string("sample/sample_test_cert/") + my_username + ".crt";
      std::string key_path =
          std::string("sample/sample_test_cert/") + my_username + "_tls.key";

      if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path.c_str(),
                                       SSL_FILETYPE_PEM) <= 0 ||
          SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.c_str(),
                                      SSL_FILETYPE_PEM) <= 0)
      {
          std::cerr << "Failed to load client cert/key\n";
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(ssl_ctx);
          ssl_ctx = nullptr;
          OSSL_PROVIDER_unload(oqs_prov);
          OSSL_PROVIDER_unload(default_prov);
          return 1;
      }

      if (SSL_CTX_load_verify_locations(
              ssl_ctx, "sample/sample_test_cert/ca.crt", nullptr) <= 0)
      {
          std::cerr << "Failed to load server CA\n";
          SSL_CTX_free(ssl_ctx);
          ssl_ctx = nullptr;
          OSSL_PROVIDER_unload(oqs_prov);
          OSSL_PROVIDER_unload(default_prov);
        return -1;
    }

      SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);

      std::cout << "Client TLS context ready\n"
                << "  Cert: " << cert_path << "\n"
                << "  Key:  " << key_path << "\n"
                << "  Hybrid KEM: X25519MLKEM768\n";

    secure_vector persisted_eph_pk;
    secure_vector persisted_eph_sk;
      bool          have_persisted_eph = false;

    uint32_t reconnect_attempts = 0;

    while (should_reconnect && reconnect_attempts < MAX_RECONNECT_ATTEMPTS)
    {
        if (reconnect_attempts > 0)
        {
            const uint64_t backoff = std::min<uint64_t>(
                INITIAL_BACKOFF_MS * (1ULL << (reconnect_attempts - 1)),
                MAX_BACKOFF_MS);
            std::cout << "[" << now_ms() << "] reconnecting in " << backoff
                      << "ms (attempt " << reconnect_attempts + 1 << ")\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }

          const int s =
              attempt_connection(config.server, config.port, persisted_eph_pk,
                                 persisted_eph_sk, have_persisted_eph);
        if (s < 0) {
            ++reconnect_attempts;
            continue;
        }

        is_connected       = true;
        reconnect_attempts = 0;
       // std::cout << "[" << now_ms() << "] re-connected (session resumed)\n";  // optional, clearer
       // Or completely remove/silence it to avoid spam

        std::thread reader(reader_thread, s, ssl);
        std::thread writer(writer_thread, s, ssl);

        writer.join();
        reader.join();

          {
              std::lock_guard<std::mutex> lk(ssl_io_mtx);
              if (ssl)
              {
                  if (SSL_is_init_finished(ssl))
                  {
                      SSL_shutdown(ssl);
                }
                  SSL_free(ssl);
                  ssl = nullptr;
            }

        }

          if (close(s) != 0)
          {
            std::cerr << "[" << now_ms() << "] Socket close failed: " << strerror(errno) << "\n";
        }

        {
            const std::lock_guard<std::mutex> lk(peers_mtx);
            for (auto &kv : peers)
            {
                kv.second.ready      = false;
                kv.second.sent_hello = false;
                kv.second.sk.key.clear();
            }
        }
    }

    if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS)
    {
        std::cout << "[" << now_ms() << "] max reconnection attempts reached\n";
    }

      if (ssl_ctx)
      {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }

    OSSL_PROVIDER_unload(default_prov);
    OSSL_PROVIDER_unload(oqs_prov);

    return 0;
}
catch (const std::exception &e)
{
    std::cerr << "Fatal error: " << e.what() << "\n";
    return 1;
}
catch (...)
{
    std::cerr << "Fatal unknown error\n";
    return 1;
}
