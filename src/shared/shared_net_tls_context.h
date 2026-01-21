#ifndef SHARED_NET_TLS_CONTEXT_H
#define SHARED_NET_TLS_CONTEXT_H

#include <asio/ssl.hpp>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <string_view>

// Centralized TLS configuration strings (used in apply_pq_security_policy and
// success message)
constexpr std::string_view TLS_HYBRID_GROUPS      = "X25519MLKEM768:X25519";
constexpr std::string_view TLS_CIPHER_SUITES      = "TLS_AES_256_GCM_SHA384:"
                                                    "TLS_CHACHA20_POLY1305_SHA256:"
                                                    "TLS_AES_128_GCM_SHA256";
constexpr std::string_view TLS_HYBRID_KEM_DISPLAY = "X25519MLKEM768";
constexpr std::string_view TLS_CIPHER_DISPLAY =
    "TLS 1.3 (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM)";

struct SSL_CTX_Deleter
{
    void operator()(SSL_CTX *ctx) const noexcept
    {
        if (ctx)
            SSL_CTX_free(ctx);
    }
};

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;

struct TLSContextConfig
{
    std::string_view cert_path;
    std::string_view key_path;
    std::string_view ca_path;
    bool             is_server;
    bool             require_peer_cert{true};
};

[[nodiscard]] inline bool init_openssl_providers() noexcept
{
    static bool initialized = false;
    if (initialized)
        return true;

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                     nullptr);

    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(nullptr, "default");
    if (!default_prov)
    {
        std::cerr << "Failed to load default provider\n";
        return false;
    }

    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(nullptr, "oqsprovider");
    if (!oqsprov)
    {
        std::cerr << "ERROR: Failed to load oqsprovider (KEM_ALG_NAME / "
                     "SIG_ALG_NAME missing)!\n";
        ERR_print_errors_fp(stderr);
        OSSL_PROVIDER_unload(default_prov);
        return false;
    }

    initialized = true;
    return true;
}

[[nodiscard]] inline bool apply_pq_security_policy(SSL_CTX *ctx) noexcept
{
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_set_ciphersuites(ctx, TLS_CIPHER_SUITES.data()) != 1)
    {
        std::cerr << "Failed to set cipher suites\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_set1_groups_list(ctx, TLS_HYBRID_GROUPS.data()) != 1)
    {
        std::cerr << "ERROR: Failed to set X25519MLKEM768\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

[[nodiscard]] inline bool
load_certificates(SSL_CTX *ctx, const TLSContextConfig &config) noexcept
{
    if (SSL_CTX_use_certificate_file(ctx, config.cert_path.data(),
                                     SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Failed to load certificate: " << config.cert_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.key_path.data(),
                                    SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Failed to load private key: " << config.key_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "Private key does not match certificate\n";
        return false;
    }

    return true;
}

[[nodiscard]] inline bool load_ca_bundle(SSL_CTX         *ctx,
                                         std::string_view ca_path) noexcept
{
    if (SSL_CTX_load_verify_locations(ctx, ca_path.data(), nullptr) <= 0)
    {
        std::cerr << "Failed to load CA bundle: " << ca_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

[[nodiscard]] inline std::shared_ptr<asio::ssl::context>
init_tls_context_asio(const TLSContextConfig &config) noexcept
{
    if (!init_openssl_providers())
        return nullptr;

    auto ctx = std::make_shared<asio::ssl::context>(
        config.is_server ? asio::ssl::context::tls_server
                         : asio::ssl::context::tls_client);

    SSL_CTX *raw = ctx->native_handle();
    if (!apply_pq_security_policy(raw))
        return nullptr;
    if (!load_certificates(raw, config))
        return nullptr;
    if (!load_ca_bundle(raw, config.ca_path))
        return nullptr;
    const int verify_mode =
        config.require_peer_cert
            ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
            : SSL_VERIFY_PEER;
    SSL_CTX_set_verify(raw, verify_mode, nullptr);
    const char *role = config.is_server ? "Server" : "Client";
    std::cout << role << " TLS context ready:\n"
              << "  Cert: " << config.cert_path << "\n"
              << "  Key:  " << config.key_path << "\n"
              << "  CA:   " << config.ca_path << "\n"
              << "  Hybrid KEM: " << TLS_HYBRID_KEM_DISPLAY << "\n"
              << "  Cipher suites: " << TLS_CIPHER_DISPLAY << "\n";
    return ctx;
}
struct AsioSSLContextWrapper
{
    SSL_CTX *ctx;

    explicit AsioSSLContextWrapper(SSL_CTX *c) noexcept : ctx(c) {}
    ~AsioSSLContextWrapper() noexcept
    {
        if (ctx)
            SSL_CTX_free(ctx);
    }
    AsioSSLContextWrapper(const AsioSSLContextWrapper &)            = delete;
    AsioSSLContextWrapper &operator=(const AsioSSLContextWrapper &) = delete;

    SSL_CTX *native_handle() const noexcept { return ctx; }
};

[[nodiscard]] inline std::shared_ptr<asio::ssl::context>
init_tls_server_context(std::string_view cert, std::string_view key,
                        std::string_view ca) noexcept

{
    return init_tls_context_asio({cert, key, ca, true, true});
}

[[nodiscard]] inline std::shared_ptr<asio::ssl::context>
init_tls_client_context(std::string_view cert, std::string_view key,
                        std::string_view ca) noexcept
{
    return init_tls_context_asio({cert, key, ca, false, true});
}
#endif