#ifndef SHARED_NET_KEY_UTIL_H
#define SHARED_NET_KEY_UTIL_H

#include "shared_common_crypto.h"
#include "shared_net_common_protocol.h"

#include "client_peer_manager.h"

#include <Poco/Buffer.h>
#include <Poco/Exception.h>
#include <Poco/File.h>
#include <Poco/FileStream.h>
#include <array>
#include <asio.hpp>

#include <functional>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <optional>
#include <string>
#include <variant>

namespace asio
{
class io_context;
}

struct PQKeypair
{
    secure_vector              sk;
    std::vector<unsigned char> pk;
};

struct SessionId
{
    std::string value;

    [[nodiscard]] constexpr bool
    operator==(const SessionId &other) const noexcept
    {
        return value == other.value;
    }
    [[nodiscard]] constexpr auto
    operator<=>(const SessionId &other) const noexcept = default;
};

struct PeerName
{
    std::string value;
};

enum class KeyLoadError : uint8_t
{
    FileNotFound,
    ReadFailed,
    ParseFailed,
    InvalidKey,
    NoPrivateKey,
    NoPublicKey
};

[[nodiscard]] inline constexpr std::string_view
key_load_error_str(KeyLoadError e) noexcept
{
    constexpr std::array<std::string_view, 6> msgs = {
        "file not found", "read failed",    "parse failed",
        "invalid key",    "no private key", "no public key"};
    return msgs[static_cast<size_t>(e)];
}

inline PQKeypair derive_ephemeral_for_peer(const secure_vector &identity_sk,
                                           const SessionId     &session_id,
                                           const PeerName      &peer)
{
#ifdef USE_LIBOQS
    std::vector<unsigned char> salt(session_id.value.begin(),
                                    session_id.value.end());
    salt.insert(salt.end(), peer.value.begin(), peer.value.end());

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG_NAME);
    if (!kem)
        throw std::runtime_error("pqkem new failed");

    const secure_vector derived_key =
        hkdf(identity_sk, salt, kem->length_secret_key);
    OQS_KEM_free(kem);

    auto pqkp = pqkem_keypair_from_seed(KEM_ALG_NAME, derived_key);

    PQKeypair ret;
    ret.pk.assign(pqkp.first.begin(), pqkp.first.end());
    ret.sk = secure_vector(pqkp.second.begin(), pqkp.second.end());
    return ret;
#else
    throw std::runtime_error("liboqs not enabled at build");
#endif
}

inline void load_pem_private_key_async(
    asio::io_context &io, const std::string &path,
    std::function<void(
        std::variant<std::pair<secure_vector, secure_vector>, KeyLoadError>)>
        callback)
{
    asio::post(
        io,
        [&io, path, cb = std::move(callback)]() mutable
        {
            try
            {
                Poco::File pem_file(path);
                if (!pem_file.exists())
                {
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::FileNotFound});
                        });
                    return;
                }

                const auto            size = pem_file.getSize();
                Poco::Buffer<char>    buffer(size);
                Poco::FileInputStream fis(path);

                if (!fis.good())
                {
                    asio::post(io,
                               [cb = std::move(cb)]() mutable
                               {
                                   cb(std::variant<
                                       std::pair<secure_vector, secure_vector>,
                                       KeyLoadError>{KeyLoadError::ReadFailed});
                               });
                    return;
                }

                fis.read(buffer.begin(), size);
                const auto bytes_read = fis.gcount();

                if (bytes_read != static_cast<std::streamsize>(size))
                {
                    asio::post(io,
                               [cb = std::move(cb)]() mutable
                               {
                                   cb(std::variant<
                                       std::pair<secure_vector, secure_vector>,
                                       KeyLoadError>{KeyLoadError::ReadFailed});
                               });
                    return;
                }

                BIO *bio = BIO_new_mem_buf(buffer.begin(),
                                           static_cast<int>(bytes_read));
                if (!bio)
                {
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ParseFailed});
                        });
                    return;
                }

                EVP_PKEY *pkey =
                    PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);

                if (!pkey)
                {
                    ERR_print_errors_fp(stderr);
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ParseFailed});
                        });
                    return;
                }

                size_t sk_len = 0;
                size_t pk_len = 0;

                if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &sk_len) <= 0)
                {
                    EVP_PKEY_free(pkey);
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPrivateKey});
                        });
                    return;
                }

                if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pk_len) <= 0)
                {
                    EVP_PKEY_free(pkey);
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPublicKey});
                        });
                    return;
                }

                secure_vector raw_sk(sk_len);
                secure_vector raw_pk(pk_len);

                if (EVP_PKEY_get_raw_private_key(pkey, raw_sk.data(),
                                                 &sk_len) <= 0)
                {
                    EVP_PKEY_free(pkey);
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPrivateKey});
                        });
                    return;
                }

                if (EVP_PKEY_get_raw_public_key(pkey, raw_pk.data(), &pk_len) <=
                    0)
                {
                    EVP_PKEY_free(pkey);
                    asio::post(
                        io,
                        [cb = std::move(cb)]() mutable
                        {
                            cb(std::variant<
                                std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPublicKey});
                        });
                    return;
                }

                EVP_PKEY_free(pkey);

                asio::post(io,
                           [cb = std::move(cb), sk = std::move(raw_sk),
                            pk = std::move(raw_pk)]() mutable
                           {
                               std::string pk_hex;
                               pk_hex.reserve(pk.size() * 2);
                               static const char *hx = "0123456789abcdef";
                               for (auto b : pk)
                               {
                                   pk_hex.push_back(hx[(b >> 4) & 0xF]);
                                   pk_hex.push_back(hx[b & 0xF]);
                               }
                               std::cerr << "[KEYLOAD] async loaded pk_len="
                                         << pk.size() << " pk_prefix="
                                         << pk_hex.substr(0, 64) << "\n";
                               cb(std::make_pair(std::move(sk), std::move(pk)));
                           });
            }
            catch (const Poco::Exception &)
            {
                asio::post(
                    io,
                    [cb = std::move(cb)]() mutable
                    {
                        cb(std::variant<std::pair<secure_vector, secure_vector>,
                                        KeyLoadError>{
                            KeyLoadError::ReadFailed});
                    });
            }
            catch (...)
            {
                asio::post(
                    io,
                    [cb = std::move(cb)]() mutable
                    {
                        cb(std::variant<std::pair<secure_vector, secure_vector>,
                                        KeyLoadError>{
                            KeyLoadError::InvalidKey});
                    });
            }
        });
}

[[nodiscard]] inline std::variant<std::pair<secure_vector, secure_vector>,
                                  KeyLoadError>
load_pem_private_key_sync(const std::string &path) noexcept
{
    try
    {
        Poco::File pem_file(path);
        if (!pem_file.exists())
        {
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::FileNotFound};
        }

        const auto            size = pem_file.getSize();
        Poco::Buffer<char>    buffer(size);
        Poco::FileInputStream fis(path);

        if (!fis.good())
        {
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ReadFailed};
        }

        fis.read(buffer.begin(), size);
        const auto bytes_read = fis.gcount();

        if (bytes_read != static_cast<std::streamsize>(size))
        {
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ReadFailed};
        }

        BIO *bio =
            BIO_new_mem_buf(buffer.begin(), static_cast<int>(bytes_read));
        if (!bio)
        {
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ParseFailed};
        }

        EVP_PKEY *pkey =
            PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            ERR_print_errors_fp(stderr);
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::ParseFailed};
        }

        size_t sk_len = 0;
        size_t pk_len = 0;

        if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &sk_len) <= 0)
        {
            EVP_PKEY_free(pkey);
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPrivateKey};
        }

        if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pk_len) <= 0)
        {
            EVP_PKEY_free(pkey);
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPublicKey};
        }

        secure_vector raw_sk(sk_len);
        secure_vector raw_pk(pk_len);

        if (EVP_PKEY_get_raw_private_key(pkey, raw_sk.data(), &sk_len) <= 0)
        {
            EVP_PKEY_free(pkey);
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPrivateKey};
        }

        if (EVP_PKEY_get_raw_public_key(pkey, raw_pk.data(), &pk_len) <= 0)
        {
            EVP_PKEY_free(pkey);
            return std::variant<std::pair<secure_vector, secure_vector>,
                                KeyLoadError>{KeyLoadError::NoPublicKey};
        }

        EVP_PKEY_free(pkey);
        {
            std::string pk_hex;
            pk_hex.reserve(raw_pk.size() * 2);
            static const char *hx = "0123456789abcdef";
            for (auto b : raw_pk)
            {
                pk_hex.push_back(hx[(b >> 4) & 0xF]);
                pk_hex.push_back(hx[b & 0xF]);
            }
            std::cerr << "[KEYLOAD] sync loaded pk_len=" << raw_pk.size()
                      << " pk_prefix=" << pk_hex.substr(0, 64) << "\n";
        }
        return std::variant<std::pair<secure_vector, secure_vector>,
                            KeyLoadError>{
            std::make_pair(std::move(raw_sk), std::move(raw_pk))};
    }
    catch (const Poco::Exception &)
    {
        return std::variant<std::pair<secure_vector, secure_vector>,
                            KeyLoadError>{KeyLoadError::ReadFailed};
    }
    catch (...)
    {
        return std::variant<std::pair<secure_vector, secure_vector>,
                            KeyLoadError>{KeyLoadError::InvalidKey};
    }
}

inline bool load_pem_private_key(const std::string &path, secure_vector &out_sk,
                                 secure_vector &out_pk) noexcept
{
    const auto result = load_pem_private_key_sync(path);
    if (std::holds_alternative<KeyLoadError>(result))
    {
        const auto err = std::get<KeyLoadError>(result);
        std::cerr << "Key load failed: " << key_load_error_str(err) << "\n";
        return false;
    }

    auto pair = std::get<std::pair<secure_vector, secure_vector>>(result);
    out_sk    = std::move(pair.first);
    out_pk    = std::move(pair.second);
    return true;
}

inline bool load_identity_keys(const char *key_path) noexcept
{
    try
    {
        const auto result = load_pem_private_key_sync(key_path);
        if (std::holds_alternative<KeyLoadError>(result))
        {
            const auto err = std::get<KeyLoadError>(result);
            std::cerr << "Identity key load failed: " << key_load_error_str(err)
                      << "\n";
            return false;
        }
        auto pair   = std::get<std::pair<secure_vector, secure_vector>>(result);
        auto raw_sk = std::move(pair.first);
        auto raw_pk = std::move(pair.second);

        peer_globals::my_identity_sk() = std::move(raw_sk);
        if (peer_globals::my_identity_sk().empty())
        {
            throw std::runtime_error("identity secret key empty");
        }

        if (raw_pk.empty())
        {
            throw std::runtime_error("identity public key not present");
        }

        peer_globals::my_identity_pk() = std::move(raw_pk);
        peer_globals::my_fp_hex() =
            compute_fingerprint_hex(peer_globals::my_identity_pk());

        std::cout << "Loaded PEM identity key: " << key_path << "\n";
        std::cout << "My fingerprint: " << peer_globals::my_fp_hex() << "\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cout << "Failed to load private/public key: " << e.what() << "\n";
        return false;
    }
}

// Eliminate Non-Cryptographic Identity Fallback
[[nodiscard]] inline std::optional<std::string>
compute_peer_key(const Parsed &p, std::string &peer_fp_hex) noexcept
{

    if (!p.identity_pk.empty())
    {
        const auto fp = fingerprint_sha256(p.identity_pk);
        peer_fp_hex   = fingerprint_to_hex(fp);
        return std::optional<std::string>{peer_fp_hex};
    }
    return std::nullopt;
}

#endif
