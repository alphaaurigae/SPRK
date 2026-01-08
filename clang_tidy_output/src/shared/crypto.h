#pragma once

#include "util.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

inline constexpr std::size_t KEY_LEN     = 32;
inline constexpr std::size_t TAG_LEN     = 16;
inline constexpr std::size_t NONCE_BYTES = 12;
inline constexpr std::size_t SHA256_LEN  = 32;

struct secure_vector : std::vector<unsigned char>
{
    using std::vector<unsigned char>::vector;

    secure_vector(const secure_vector &)            = default;
    secure_vector &operator=(const secure_vector &) = default;

    secure_vector(secure_vector &&) noexcept            = default;
    secure_vector &operator=(secure_vector &&) noexcept = default;

    ~secure_vector()
    {
        if (!this->empty())
        {
            OPENSSL_cleanse(this->data(), this->size());
        }
    }
};

struct EVP_CIPHER_CTX_Deleter
{
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept
    {
        if (ctx != nullptr)
        {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

struct EVP_MD_CTX_Deleter
{
    void operator()(EVP_MD_CTX *ctx) const noexcept
    {
        if (ctx != nullptr)
        {
            EVP_MD_CTX_free(ctx);
        }
    }
};

struct EVP_PKEY_CTX_Deleter
{
    void operator()(EVP_PKEY_CTX *ctx) const noexcept
    {
        if (ctx != nullptr)
        {
            EVP_PKEY_CTX_free(ctx);
        }
    }
};

#ifdef USE_LIBOQS
struct OQS_KEM_Deleter
{
    void operator()(OQS_KEM *kem) const noexcept
    {
        if (kem != nullptr)
        {
            OQS_KEM_free(kem);
        }
    }
};

struct OQS_SIG_Deleter
{
    void operator()(OQS_SIG *sig) const noexcept
    {
        if (sig != nullptr)
        {
            OQS_SIG_free(sig);
        }
    }
};
#endif

using EVP_CIPHER_CTX_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
using EVP_MD_CTX_ptr   = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;

#ifdef USE_LIBOQS
using OQS_KEM_ptr = std::unique_ptr<OQS_KEM, OQS_KEM_Deleter>;
using OQS_SIG_ptr = std::unique_ptr<OQS_SIG, OQS_SIG_Deleter>;
#endif

struct Keypair
{
    secure_vector pk;
    secure_vector sk;
};

struct SessionKey
{
    secure_vector key;
};

template <std::size_t N> class SecureArray
{
  public:
    SecureArray() = default;

    ~SecureArray() { OPENSSL_cleanse(data_.data(), N); }

    SecureArray(const SecureArray &)            = delete;
    SecureArray &operator=(const SecureArray &) = delete;
    SecureArray(SecureArray &&)                 = delete;
    SecureArray &operator=(SecureArray &&)      = delete;

    [[nodiscard]] unsigned char       *data() noexcept { return data_.data(); }
    [[nodiscard]] const unsigned char *data() const noexcept
    {
        return data_.data();
    }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }
    [[nodiscard]] auto           begin() noexcept { return data_.begin(); }
    [[nodiscard]] auto           end() noexcept { return data_.end(); }
    [[nodiscard]] unsigned char &operator[](std::size_t i) noexcept
    {
        return data_[i];
    }
    [[nodiscard]] const unsigned char &operator[](std::size_t i) const noexcept
    {
        return data_[i];
    }

  private:
    std::array<unsigned char, N> data_{};
};

inline void crypto_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(0, nullptr);
#endif
#ifdef USE_LIBOQS
    /* OQS requires no explicit init */
#endif
}

inline std::pair<secure_vector, secure_vector>
pqkem_keypair(std::string_view oqs_alg)
{
#ifdef USE_LIBOQS
    OQS_KEM_ptr kem(OQS_KEM_new(std::string(oqs_alg).c_str()));
    if (kem == nullptr)
    {
        throw std::runtime_error("Failed to create KEM object for algorithm: " +
                                 std::string(oqs_alg));
    }

    secure_vector pk(kem->length_public_key);
    secure_vector sk(kem->length_secret_key);

    if (OQS_KEM_keypair(kem.get(), pk.data(), sk.data()) != OQS_SUCCESS)
    {
        throw std::runtime_error("Failed to generate keypair for algorithm: " +
                                 std::string(oqs_alg));
    }

    return {std::move(pk), std::move(sk)};
#else
    throw std::runtime_error("pqkem not enabled at build for " +
                             std::string(oqs_alg));
#endif
}

inline std::pair<std::vector<unsigned char>, secure_vector>
pqkem_encaps(std::string_view oqs_alg, std::span<const unsigned char> peer_pk)
{
#ifdef USE_LIBOQS
    OQS_KEM_ptr kem(OQS_KEM_new(std::string(oqs_alg).c_str()));
    if (kem == nullptr)
    {
        throw std::runtime_error("pqkem new failed");
    }
    std::vector<unsigned char> ct(kem->length_ciphertext);
    secure_vector              ss(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem.get(), ct.data(), ss.data(), peer_pk.data()) !=
        OQS_SUCCESS)
    {
        throw std::runtime_error("pqkem encaps failed");
    }
    return {std::move(ct), std::move(ss)};
#else
    (void)oqs_alg;
    (void)peer_pk;
    throw std::runtime_error("pqkem not enabled at build");
#endif
}

inline secure_vector pqkem_decaps(std::string_view               oqs_alg,
                                  std::span<const unsigned char> ct,
                                  const secure_vector           &sk)
{
#ifdef USE_LIBOQS
    OQS_KEM_ptr kem(OQS_KEM_new(std::string(oqs_alg).c_str()));
    if (kem == nullptr)
    {
        throw std::runtime_error("pqkem new failed");
    }
    secure_vector ss(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem.get(), ss.data(), ct.data(), sk.data()) !=
        OQS_SUCCESS)
    {
        throw std::runtime_error("pqkem decaps failed");
    }
    return ss;
#else
    (void)oqs_alg;
    (void)ct;
    (void)sk;
    throw std::runtime_error("pqkem not enabled at build");
#endif
}

struct PublicKey
{
    std::span<const unsigned char> data;
    explicit PublicKey(std::span<const unsigned char> d) : data(d) {}
};

struct SecretKey
{
    std::span<const unsigned char> data;
    explicit SecretKey(std::span<const unsigned char> d) : data(d) {}
};

struct Message
{
    std::span<const unsigned char> data;
    explicit Message(std::span<const unsigned char> d) : data(d) {}
};

struct Signature
{
    std::span<const unsigned char> data;
    explicit Signature(std::span<const unsigned char> d) : data(d) {}
};

inline std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
pqsig_keypair(std::string_view oqs_alg)
{
#ifdef USE_LIBOQS
    OQS_SIG_ptr sig(OQS_SIG_new(std::string(oqs_alg).c_str()));
    if (sig == nullptr)
    {
        throw std::runtime_error("pqsig new failed");
    }
    std::vector<unsigned char> pk(sig->length_public_key);
    std::vector<unsigned char> sk(sig->length_secret_key);
    if (OQS_SIG_keypair(sig.get(), pk.data(), sk.data()) != OQS_SUCCESS)
    {
        throw std::runtime_error("pqsig keypair failed");
    }
    return {std::move(pk), std::move(sk)};
#else
    (void)oqs_alg;
    throw std::runtime_error("pqsig not enabled at build");
#endif
}

inline std::vector<unsigned char> pqsig_sign(std::string_view oqs_alg,
                                             SecretKey sk, Message msg)
{
#ifdef USE_LIBOQS
    OQS_SIG_ptr sig(OQS_SIG_new(std::string(oqs_alg).c_str()));
    if (sig == nullptr)
    {
        throw std::runtime_error("pqsig new failed");
    }
    std::size_t                siglen = sig->length_signature;
    std::vector<unsigned char> out(siglen);
    if (OQS_SIG_sign(sig.get(), out.data(), &siglen, msg.data.data(),
                     msg.data.size(), sk.data.data()) != OQS_SUCCESS)
    {
        throw std::runtime_error("pqsig sign failed");
    }
    out.resize(siglen);
    return out;
#else
    (void)oqs_alg;
    (void)sk;
    (void)msg;
    throw std::runtime_error("pqsig not enabled at build");
#endif
}

inline bool pqsig_verify(std::string_view oqs_alg, PublicKey pk, Message msg,
                         Signature signature)
{
#ifdef USE_LIBOQS
    OQS_SIG_ptr sig(OQS_SIG_new(std::string(oqs_alg).c_str()));
    if (sig == nullptr)
    {
        throw std::runtime_error("pqsig new failed");
    }
    const bool ok =
        (OQS_SIG_verify(sig.get(), msg.data.data(), msg.data.size(),
                        signature.data.data(), signature.data.size(),
                        pk.data.data()) == OQS_SUCCESS);
    return ok;
#else
    (void)oqs_alg;
    (void)pk;
    (void)msg;
    (void)signature;
    throw std::runtime_error("pqsig not enabled at build");
#endif
}

inline std::vector<unsigned char> pqsig_sign(std::string_view oqs_alg,
                                             std::span<const unsigned char> sk,
                                             std::span<const unsigned char> msg)
{
    return pqsig_sign(oqs_alg, SecretKey{sk}, Message{msg});
}

inline bool pqsig_verify(std::string_view               oqs_alg,
                         std::span<const unsigned char> pk,
                         std::span<const unsigned char> msg,
                         std::span<const unsigned char> signature)
{
    return pqsig_verify(oqs_alg, PublicKey{pk}, Message{msg},
                        Signature{signature});
}

inline secure_vector random_bytes(std::size_t n)
{
    if (n == 0)
    {
        return {};
    }

    secure_vector v(n);
    if (RAND_bytes(v.data(), static_cast<int>(n)) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }

    return v;
}

inline std::vector<unsigned char>
aead_encrypt(const secure_vector &key, std::span<const unsigned char> plaintext,
             std::span<const unsigned char> aad,
             std::vector<unsigned char>    &out_nonce)
{
    if (key.size() < KEY_LEN)
    {
        throw std::runtime_error("bad key size for AEAD");
    }

    out_nonce.resize(NONCE_BYTES);
    if (RAND_bytes(out_nonce.data(), static_cast<int>(NONCE_BYTES)) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + TAG_LEN);
    int                        len  = 0;
    int                        clen = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                                nullptr, nullptr))
    {
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                 static_cast<int>(NONCE_BYTES), nullptr))
    {
        throw std::runtime_error("set ivlen failed");
    }
    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                                out_nonce.data()))
    {
        throw std::runtime_error("key/iv set failed");
    }

    if (!aad.empty())
    {
        if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                   static_cast<int>(aad.size())))
        {
            throw std::runtime_error("AAD failed");
        }
    }

    if (!plaintext.empty())
    {
        if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                                   plaintext.data(),
                                   static_cast<int>(plaintext.size())))
        {
            throw std::runtime_error("EncryptUpdate failed");
        }
        clen = len;
    }

    auto ciphertext_span = std::span(ciphertext);
    if (1 != EVP_EncryptFinal_ex(ctx.get(),
                                 ciphertext_span.subspan(clen).data(), &len))
    {
        throw std::runtime_error("EncryptFinal failed");
    }
    clen += len;

    std::array<unsigned char, TAG_LEN> tag{};
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                                 static_cast<int>(TAG_LEN), tag.data()))
    {
        throw std::runtime_error("Get tag failed");
    }

    ciphertext.resize(static_cast<std::size_t>(clen) + TAG_LEN);
    std::ranges::copy(tag, ciphertext.begin() + clen);

    return ciphertext;
}

inline std::vector<unsigned char> aead_encrypt_with_nonce(
    const secure_vector &key, std::span<const unsigned char> plaintext,
    std::span<const unsigned char> aad, std::span<const unsigned char> nonce)
{
    if (key.size() < KEY_LEN)
    {
        throw std::runtime_error("bad key size for AEAD");
    }
    if (nonce.size() != NONCE_BYTES)
    {
        throw std::runtime_error("bad nonce length");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + TAG_LEN);
    int                        len  = 0;
    int                        clen = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                                nullptr, nullptr))
    {
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                 static_cast<int>(NONCE_BYTES), nullptr))
    {
        throw std::runtime_error("set ivlen failed");
    }
    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                                nonce.data()))
    {
        throw std::runtime_error("key/iv set failed");
    }

    if (!aad.empty())
    {
        if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                   static_cast<int>(aad.size())))
        {
            throw std::runtime_error("AAD failed");
        }
    }

    if (!plaintext.empty())
    {
        if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                                   plaintext.data(),
                                   static_cast<int>(plaintext.size())))
        {
            throw std::runtime_error("EncryptUpdate failed");
        }
        clen = len;
    }

    auto ciphertext_span = std::span(ciphertext);
    if (1 != EVP_EncryptFinal_ex(ctx.get(),
                                 ciphertext_span.subspan(clen).data(), &len))
    {
        throw std::runtime_error("EncryptFinal failed");
    }
    clen += len;

    std::array<unsigned char, TAG_LEN> tag{};
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                                 static_cast<int>(TAG_LEN), tag.data()))
    {
        throw std::runtime_error("Get tag failed");
    }

    ciphertext.resize(static_cast<std::size_t>(clen) + TAG_LEN);
    std::ranges::copy(tag, ciphertext.begin() + clen);

    return ciphertext;
}

inline std::vector<unsigned char> aead_decrypt(
    const secure_vector &key, std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> aad, std::span<const unsigned char> nonce)
{
    if (key.size() < KEY_LEN)
    {
        throw std::runtime_error("bad key size for AEAD");
    }
    if (nonce.size() != NONCE_BYTES)
    {
        throw std::runtime_error("bad nonce length");
    }
    if (ciphertext.size() < TAG_LEN)
    {
        throw std::runtime_error("ciphertext too small");
    }

    const std::size_t          ctlen = ciphertext.size() - TAG_LEN;
    std::vector<unsigned char> out(ctlen);
    int                        len  = 0;
    int                        plen = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                                nullptr, nullptr))
    {
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                 static_cast<int>(NONCE_BYTES), nullptr))
    {
        throw std::runtime_error("set ivlen failed");
    }
    if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                                nonce.data()))
    {
        throw std::runtime_error("key/iv set failed");
    }

    if (!aad.empty())
    {
        if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                   static_cast<int>(aad.size())))
        {
            throw std::runtime_error("AAD failed");
        }
    }

    if (ctlen > 0)
    {
        if (1 != EVP_DecryptUpdate(ctx.get(), out.data(), &len,
                                   ciphertext.data(), static_cast<int>(ctlen)))
        {
            throw std::runtime_error("DecryptUpdate failed");
        }
        plen = len;
    }

    auto tag_span = ciphertext.subspan(ctlen, TAG_LEN);
    std::array<unsigned char, TAG_LEN> tag_copy{};
    std::ranges::copy(tag_span, tag_copy.begin());
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                                 static_cast<int>(TAG_LEN), tag_copy.data()))
    {
        throw std::runtime_error("set tag failed");
    }

    auto out_span = std::span(out);
    if (1 !=
        EVP_DecryptFinal_ex(ctx.get(), out_span.subspan(plen).data(), &len))
    {
        throw std::runtime_error("decryption failed (tag mismatch)");
    }
    plen += len;
    out.resize(static_cast<std::size_t>(plen));

    return out;
}

inline SessionKey derive_shared_key_from_secret(const secure_vector &shared,
                                                std::string_view     context)
{
    if (shared.empty())
    {
        throw std::runtime_error("empty shared secret");
    }

    const EVP_MD *md       = EVP_sha256();
    const auto    hash_len = static_cast<std::size_t>(EVP_MD_size(md));

    std::vector<unsigned char> zero_salt(hash_len, 0);

    SecureArray<EVP_MAX_MD_SIZE> prk;
    unsigned int                 prk_len = 0;

    if (HMAC(md, zero_salt.data(), static_cast<int>(zero_salt.size()),
             shared.data(), static_cast<int>(shared.size()), prk.data(),
             &prk_len) == nullptr)
    {
        throw std::runtime_error("HKDF-Extract (HMAC) failed");
    }

    constexpr std::size_t      okm_len = 32;
    std::vector<unsigned char> info(context.begin(), context.end());
    info.push_back(0x01);

    SecureArray<okm_len> okm;
    unsigned int         out_len = 0;

    if (HMAC(md, prk.data(), static_cast<int>(prk_len), info.data(),
             static_cast<int>(info.size()), okm.data(), &out_len) == nullptr)
    {
        throw std::runtime_error("HKDF-Expand (HMAC) failed");
    }
    if (out_len < okm_len)
    {
        throw std::runtime_error("HKDF derived insufficient output");
    }

    secure_vector key(
        okm.begin(),
        std::next(okm.begin(), static_cast<std::ptrdiff_t>(okm_len)));
    return SessionKey{std::move(key)};
}

inline secure_vector derive_nonce_from_session(const secure_vector &session_key,
                                               std::uint32_t        seq)
{
    if (session_key.empty())
    {
        throw std::runtime_error("empty session key");
    }

    std::array<unsigned char, 4> seqb{};
    seqb[0] = static_cast<unsigned char>((seq >> 24U) & 0xFFU);
    seqb[1] = static_cast<unsigned char>((seq >> 16U) & 0xFFU);
    seqb[2] = static_cast<unsigned char>((seq >> 8U) & 0xFFU);
    seqb[3] = static_cast<unsigned char>(seq & 0xFFU);

    unsigned int                 outlen = EVP_MAX_MD_SIZE;
    SecureArray<EVP_MAX_MD_SIZE> hmac_out;

    if (HMAC(EVP_sha256(), session_key.data(),
             static_cast<int>(session_key.size()), seqb.data(), seqb.size(),
             hmac_out.data(), &outlen) == nullptr)
    {
        throw std::runtime_error("HMAC failed");
    }

    secure_vector nonce(NONCE_BYTES);
    std::copy_n(hmac_out.data(), NONCE_BYTES, nonce.begin());
    return nonce;
}

inline secure_vector hkdf(const secure_vector           &key,
                          std::span<const unsigned char> salt, std::size_t len)
{
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (pctx == nullptr)
    {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    if (1 != EVP_PKEY_derive_init(pctx.get()))
    {
        throw std::runtime_error("EVP_PKEY_derive_init failed");
    }
    if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()))
    {
        throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
    }
    if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(),
                                         static_cast<int>(salt.size())))
    {
        throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");
    }
    if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key.data(),
                                        static_cast<int>(key.size())))
    {
        throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
    }

    secure_vector out(len);
    if (1 != EVP_PKEY_derive(pctx.get(), out.data(), &len))
    {
        throw std::runtime_error("EVP_PKEY_derive failed");
    }

    return out;
}

inline std::array<unsigned char, SHA256_LEN>
fingerprint_sha256(std::span<const unsigned char> pk)
{
    if (pk.empty())
    {
        throw std::runtime_error("empty public key for fingerprint");
    }

    std::array<unsigned char, SHA256_LEN> out{};

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr))
    {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (1 != EVP_DigestUpdate(ctx.get(), pk.data(), pk.size()))
    {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    unsigned int out_len = 0;
    if (1 != EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len))
    {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    if (out_len != out.size())
    {
        throw std::runtime_error("unexpected digest length");
    }
    return out;
}

inline std::string
fingerprint_to_hex(const std::array<unsigned char, SHA256_LEN> &f)
{
    return to_hex(f.data(), f.size());
}

inline std::pair<std::vector<unsigned char>, secure_vector>
pqkem_keypair_from_seed(std::string_view alg, const secure_vector &seed)
{
#ifdef USE_LIBOQS
    OQS_KEM_ptr kem(OQS_KEM_new(std::string(alg).c_str()));
    if (kem == nullptr)
    {
        throw std::runtime_error("pqkem new failed");
    }
    if (seed.size() < kem->length_secret_key)
    {
        throw std::runtime_error("seed too small");
    }
    secure_vector sk(kem->length_secret_key);
    std::copy_n(seed.begin(), kem->length_secret_key, sk.begin());
    std::vector<unsigned char> pk(kem->length_public_key);
    if (OQS_KEM_encaps(kem.get(), pk.data(), sk.data(), pk.data()) !=
        OQS_SUCCESS)
    {
        throw std::runtime_error("pqkem seed keypair failed");
    }
    return {std::move(pk), std::move(sk)};
#else
    (void)alg;
    (void)seed;
    throw std::runtime_error("pqkem not enabled at build");
#endif
}