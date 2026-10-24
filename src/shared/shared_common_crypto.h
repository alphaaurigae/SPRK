#ifndef SHARED_COMMON_CRYPTO_H
#define SHARED_COMMON_CRYPTO_H

#include "shared_common_util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

inline constexpr std::size_t KEY_LEN = 32;
inline constexpr std::size_t TAG_LEN = 16;
inline constexpr std::size_t NONCE_BYTES = 12;
inline constexpr std::size_t SHA256_LEN = 32;

inline constexpr std::size_t MIN_FP_PREFIX_HEX = 16;

inline std::string make_symmetric_message_aad(std::string_view sender_fp,
                                              std::string_view receiver_fp,
                                              uint32_t seq) {
  std::string a(sender_fp);
  std::string b(receiver_fp);
  if (a > b)
    std::swap(a, b);
  return a + "|" + b + "|" + std::to_string(seq);
}

struct AADBuilder {
  std::string local_fp;
  std::string remote_fp;

  std::string build_for_seq(uint32_t seq) const {
    return make_symmetric_message_aad(local_fp, remote_fp, seq);
  }
};

inline bool is_valid_hex_token(const std::string &token) noexcept {
  return token.size() >= MIN_FP_PREFIX_HEX &&
         std::all_of(token.begin(), token.end(), [](unsigned char c) noexcept {
           return std::isxdigit(c) != 0;
         });
}

struct secure_vector : std::vector<unsigned char> {
  using std::vector<unsigned char>::vector;

  secure_vector(const secure_vector &) = default;
  secure_vector &operator=(const secure_vector &) = default;

  secure_vector(secure_vector &&) noexcept = default;
  secure_vector &operator=(secure_vector &&) noexcept = default;

  ~secure_vector() {
    if (!this->empty()) {
      OPENSSL_cleanse(this->data(), this->size());
    }
  }
};

struct EVP_CIPHER_CTX_Deleter {
  void operator()(EVP_CIPHER_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      EVP_CIPHER_CTX_free(ctx);
    }
  }
};

struct EVP_MD_CTX_Deleter {
  void operator()(EVP_MD_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      EVP_MD_CTX_free(ctx);
    }
  }
};

struct EVP_PKEY_CTX_Deleter {
  void operator()(EVP_PKEY_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      EVP_PKEY_CTX_free(ctx);
    }
  }
};

struct EVP_PKEY_Deleter {
  void operator()(EVP_PKEY *p) const noexcept {
    if (p != nullptr) {
      EVP_PKEY_free(p);
    }
  }
};

struct EVP_SIGNATURE_Deleter {
  void operator()(EVP_SIGNATURE *p) const noexcept {
    if (p != nullptr) {
      EVP_SIGNATURE_free(p);
    }
  }
};

struct OSSL_PARAM_BLD_Deleter {
  void operator()(OSSL_PARAM_BLD *p) const noexcept {
    if (p != nullptr) {
      OSSL_PARAM_BLD_free(p);
    }
  }
};

struct OSSL_PARAM_Deleter {
  void operator()(OSSL_PARAM *p) const noexcept {
    if (p != nullptr) {
      OSSL_PARAM_free(p);
    }
  }
};

using EVP_CIPHER_CTX_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using EVP_SIGNATURE_ptr = std::unique_ptr<EVP_SIGNATURE, EVP_SIGNATURE_Deleter>;
using OSSL_PARAM_BLD_ptr = std::unique_ptr<OSSL_PARAM_BLD, OSSL_PARAM_BLD_Deleter>;
using OSSL_PARAM_ptr = std::unique_ptr<OSSL_PARAM, OSSL_PARAM_Deleter>;

struct Keypair {
  secure_vector pk;
  secure_vector sk;
};

struct DirectionalSessionKeys {
  secure_vector send_key;
  secure_vector recv_key;
};

template <std::size_t N> class SecureArray {
public:
  SecureArray() = default;

  ~SecureArray() { OPENSSL_cleanse(data_.data(), N); }

  SecureArray(const SecureArray &) = delete;
  SecureArray &operator=(const SecureArray &) = delete;
  SecureArray(SecureArray &&) = delete;
  SecureArray &operator=(SecureArray &&) = delete;

  [[nodiscard]] unsigned char *data() noexcept { return data_.data(); }
  [[nodiscard]] const unsigned char *data() const noexcept {
    return data_.data();
  }
  [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }
  [[nodiscard]] auto begin() noexcept { return data_.begin(); }
  [[nodiscard]] auto end() noexcept { return data_.end(); }
  [[nodiscard]] unsigned char &operator[](std::size_t i) noexcept {
    return data_[i];
  }
  [[nodiscard]] const unsigned char &operator[](std::size_t i) const noexcept {
    return data_[i];
  }

private:
  std::array<unsigned char, N> data_{};
};

inline void crypto_init() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
#else
  OPENSSL_init_crypto(0, nullptr);
#endif
}

namespace pqc_detail {

[[nodiscard]] inline EVP_PKEY_ptr
pkey_from_public_bytes(std::string_view alg, std::span<const unsigned char> pub) {
  EVP_PKEY_CTX_ptr ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, std::string(alg).c_str(), nullptr));
  if (!ctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for " +
                             std::string(alg));
  }
  if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
    throw std::runtime_error("EVP_PKEY_fromdata_init failed for " +
                             std::string(alg));
  }
  OSSL_PARAM_BLD_ptr bld(OSSL_PARAM_BLD_new());
  if (!bld) {
    throw std::runtime_error("OSSL_PARAM_BLD_new failed");
  }
  if (OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       pub.data(), pub.size()) != 1) {
    throw std::runtime_error("OSSL_PARAM_BLD_push_octet_string(pub) failed");
  }
  OSSL_PARAM_ptr params(OSSL_PARAM_BLD_to_param(bld.get()));
  if (!params) {
    throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");
  }
  EVP_PKEY *raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) !=
          1 ||
      raw == nullptr) {
    throw std::runtime_error("EVP_PKEY_fromdata (public) failed for " +
                             std::string(alg));
  }
  return EVP_PKEY_ptr(raw);
}

[[nodiscard]] inline EVP_PKEY_ptr
pkey_from_private_bytes(std::string_view alg,
                        std::span<const unsigned char> priv,
                        std::span<const unsigned char> pub = {}) {
  EVP_PKEY_CTX_ptr ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, std::string(alg).c_str(), nullptr));
  if (!ctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for " +
                             std::string(alg));
  }
  if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
    throw std::runtime_error("EVP_PKEY_fromdata_init failed for " +
                             std::string(alg));
  }
  OSSL_PARAM_BLD_ptr bld(OSSL_PARAM_BLD_new());
  if (!bld) {
    throw std::runtime_error("OSSL_PARAM_BLD_new failed");
  }
  if (OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                                       priv.data(), priv.size()) != 1) {
    throw std::runtime_error("OSSL_PARAM_BLD_push_octet_string(priv) failed");
  }
  if (!pub.empty() &&
      OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       pub.data(), pub.size()) != 1) {
    throw std::runtime_error("OSSL_PARAM_BLD_push_octet_string(pub) failed");
  }
  OSSL_PARAM_ptr params(OSSL_PARAM_BLD_to_param(bld.get()));
  if (!params) {
    throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");
  }
  EVP_PKEY *raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params.get()) !=
          1 ||
      raw == nullptr) {
    throw std::runtime_error("EVP_PKEY_fromdata (private) failed for " +
                             std::string(alg));
  }
  return EVP_PKEY_ptr(raw);
}

[[nodiscard]] inline secure_vector get_priv_octets(EVP_PKEY *pkey) {
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, nullptr,
                                      0, &len) != 1) {
    throw std::runtime_error(
        "EVP_PKEY_get_octet_string_param(priv) size query failed");
  }
  secure_vector out(len);
  size_t out_len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                      out.data(), out.size(), &out_len) != 1) {
    throw std::runtime_error("EVP_PKEY_get_octet_string_param(priv) failed");
  }
  out.resize(out_len);
  return out;
}

[[nodiscard]] inline std::vector<unsigned char> get_pub_octets(EVP_PKEY *pkey) {
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr,
                                      0, &len) != 1) {
    throw std::runtime_error(
        "EVP_PKEY_get_octet_string_param(pub) size query failed");
  }
  std::vector<unsigned char> out(len);
  size_t out_len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                      out.data(), out.size(), &out_len) != 1) {
    throw std::runtime_error("EVP_PKEY_get_octet_string_param(pub) failed");
  }
  out.resize(out_len);
  return out;
}

} // namespace pqc_detail

inline std::pair<secure_vector, secure_vector>
pqkem_keypair(std::string_view alg) {
  EVP_PKEY *raw = EVP_PKEY_Q_keygen(nullptr, nullptr, std::string(alg).c_str());
  if (raw == nullptr) {
    throw std::runtime_error("Failed to generate keypair for algorithm: " +
                             std::string(alg));
  }
  EVP_PKEY_ptr pkey(raw);
  auto pub = pqc_detail::get_pub_octets(pkey.get());
  secure_vector pk(pub.begin(), pub.end());
  secure_vector sk = pqc_detail::get_priv_octets(pkey.get());
  return {std::move(pk), std::move(sk)};
}

inline std::pair<std::vector<unsigned char>, secure_vector>
pqkem_encaps(std::string_view alg, std::span<const unsigned char> peer_pk) {
  auto peer_pkey = pqc_detail::pkey_from_public_bytes(alg, peer_pk);
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, peer_pkey.get(), nullptr));
  if (!ctx) {
    throw std::runtime_error("pqkem encaps: EVP_PKEY_CTX_new_from_pkey failed");
  }
  if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) != 1) {
    throw std::runtime_error("pqkem encaps init failed");
  }
  size_t wrapped_len = 0;
  size_t secret_len = 0;
  if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &wrapped_len, nullptr,
                           &secret_len) != 1) {
    throw std::runtime_error("pqkem encaps size query failed");
  }
  std::vector<unsigned char> ct(wrapped_len);
  secure_vector ss(secret_len);
  if (EVP_PKEY_encapsulate(ctx.get(), ct.data(), &wrapped_len, ss.data(),
                           &secret_len) != 1) {
    throw std::runtime_error("pqkem encaps failed");
  }
  ct.resize(wrapped_len);
  ss.resize(secret_len);
  return {std::move(ct), std::move(ss)};
}

inline secure_vector pqkem_decaps(std::string_view alg,
                                  std::span<const unsigned char> ct,
                                  const secure_vector &sk) {
  auto pkey = pqc_detail::pkey_from_private_bytes(alg, sk);
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
  if (!ctx) {
    throw std::runtime_error("pqkem decaps: EVP_PKEY_CTX_new_from_pkey failed");
  }
  if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) != 1) {
    throw std::runtime_error("pqkem decaps init failed");
  }
  size_t secret_len = 0;
  if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &secret_len, ct.data(),
                           ct.size()) != 1) {
    throw std::runtime_error("pqkem decaps size query failed");
  }
  secure_vector ss(secret_len);
  if (EVP_PKEY_decapsulate(ctx.get(), ss.data(), &secret_len, ct.data(),
                           ct.size()) != 1) {
    throw std::runtime_error("pqkem decaps failed");
  }
  ss.resize(secret_len);
  return ss;
}

struct PublicKey {
  std::span<const unsigned char> data;
  explicit PublicKey(std::span<const unsigned char> d) : data(d) {}
};

struct SecretKey {
  std::span<const unsigned char> data;
  explicit SecretKey(std::span<const unsigned char> d) : data(d) {}
};

struct Message {
  std::span<const unsigned char> data;
  explicit Message(std::span<const unsigned char> d) : data(d) {}
};

struct Signature {
  std::span<const unsigned char> data;
  explicit Signature(std::span<const unsigned char> d) : data(d) {}
};

inline std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
pqsig_keypair(std::string_view alg) {
  EVP_PKEY *raw = EVP_PKEY_Q_keygen(nullptr, nullptr, std::string(alg).c_str());
  if (raw == nullptr) {
    throw std::runtime_error("pqsig keypair failed for " + std::string(alg));
  }
  EVP_PKEY_ptr pkey(raw);
  auto pub = pqc_detail::get_pub_octets(pkey.get());
  auto priv = pqc_detail::get_priv_octets(pkey.get());
  return {std::move(pub), std::vector<unsigned char>(priv.begin(), priv.end())};
}

inline std::vector<unsigned char> pqsig_sign(std::string_view alg,
                                             SecretKey sk, Message msg) {
  auto pkey = pqc_detail::pkey_from_private_bytes(alg, sk.data);
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
  if (!ctx) {
    throw std::runtime_error("pqsig sign: EVP_PKEY_CTX_new_from_pkey failed");
  }
  EVP_SIGNATURE_ptr sig_alg(
      EVP_SIGNATURE_fetch(nullptr, std::string(alg).c_str(), nullptr));
  if (!sig_alg) {
    throw std::runtime_error("pqsig sign: EVP_SIGNATURE_fetch failed for " +
                             std::string(alg));
  }
  if (EVP_PKEY_sign_message_init(ctx.get(), sig_alg.get(), nullptr) != 1) {
    throw std::runtime_error("pqsig sign_message_init failed");
  }
  size_t sig_len = 0;
  if (EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, msg.data.data(),
                    msg.data.size()) != 1) {
    throw std::runtime_error("pqsig sign size query failed");
  }
  std::vector<unsigned char> out(sig_len);
  if (EVP_PKEY_sign(ctx.get(), out.data(), &sig_len, msg.data.data(),
                    msg.data.size()) != 1) {
    throw std::runtime_error("pqsig sign failed");
  }
  out.resize(sig_len);
  return out;
}

inline bool pqsig_verify(std::string_view alg, PublicKey pk, Message msg,
                         Signature signature) {
  auto pkey = pqc_detail::pkey_from_public_bytes(alg, pk.data);
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
  if (!ctx) {
    throw std::runtime_error("pqsig verify: EVP_PKEY_CTX_new_from_pkey failed");
  }
  EVP_SIGNATURE_ptr sig_alg(
      EVP_SIGNATURE_fetch(nullptr, std::string(alg).c_str(), nullptr));
  if (!sig_alg) {
    throw std::runtime_error("pqsig verify: EVP_SIGNATURE_fetch failed for " +
                             std::string(alg));
  }
  if (EVP_PKEY_verify_message_init(ctx.get(), sig_alg.get(), nullptr) != 1) {
    throw std::runtime_error("pqsig verify_message_init failed");
  }
  return EVP_PKEY_verify(ctx.get(), signature.data.data(), signature.data.size(),
                        msg.data.data(), msg.data.size()) == 1;
}

inline std::vector<unsigned char>
pqsig_sign(std::string_view alg, std::span<const unsigned char> sk,
           std::span<const unsigned char> msg) {
  return pqsig_sign(alg, SecretKey{sk}, Message{msg});
}

inline bool pqsig_verify(std::string_view alg,
                         std::span<const unsigned char> pk,
                         std::span<const unsigned char> msg,
                         std::span<const unsigned char> signature) {
  return pqsig_verify(alg, PublicKey{pk}, Message{msg},
                      Signature{signature});
}

inline secure_vector random_bytes(std::size_t n) {
  if (n == 0) {
    return {};
  }

  secure_vector v(n);
  if (RAND_bytes(v.data(), static_cast<int>(n)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }

  return v;
}

inline std::vector<unsigned char>
aead_encrypt(const secure_vector &key, std::span<const unsigned char> plaintext,
             std::span<const unsigned char> aad,
             std::vector<unsigned char> &out_nonce) {
  if (key.size() < KEY_LEN) {
    throw std::runtime_error("bad key size for AEAD");
  }

  out_nonce.resize(NONCE_BYTES);
  if (RAND_bytes(out_nonce.data(), static_cast<int>(NONCE_BYTES)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }

  std::vector<unsigned char> ciphertext(plaintext.size() + TAG_LEN);
  int len = 0;
  int clen = 0;

  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                              nullptr, nullptr)) {
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                               static_cast<int>(NONCE_BYTES), nullptr)) {
    throw std::runtime_error("set ivlen failed");
  }
  if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                              out_nonce.data())) {
    throw std::runtime_error("key/iv set failed");
  }

  if (!aad.empty()) {
    if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                               static_cast<int>(aad.size()))) {
      throw std::runtime_error("AAD failed");
    }
  }

  if (!plaintext.empty()) {
    if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                               plaintext.data(),
                               static_cast<int>(plaintext.size()))) {
      throw std::runtime_error("EncryptUpdate failed");
    }
    clen = len;
  }

  auto ciphertext_span = std::span(ciphertext);
  if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext_span.subspan(clen).data(),
                               &len)) {
    throw std::runtime_error("EncryptFinal failed");
  }
  clen += len;

  std::array<unsigned char, TAG_LEN> tag{};
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                               static_cast<int>(TAG_LEN), tag.data())) {
    throw std::runtime_error("Get tag failed");
  }

  ciphertext.resize(static_cast<std::size_t>(clen) + TAG_LEN);
  std::ranges::copy(tag, ciphertext.begin() + clen);

  return ciphertext;
}

inline std::vector<unsigned char> aead_encrypt_with_nonce(
    const secure_vector &key, std::span<const unsigned char> plaintext,
    std::span<const unsigned char> aad, std::span<const unsigned char> nonce) {
  if (key.size() < KEY_LEN) {
    throw std::runtime_error("bad key size for AEAD");
  }
  if (nonce.size() != NONCE_BYTES) {
    throw std::runtime_error("bad nonce length");
  }

  std::vector<unsigned char> ciphertext(plaintext.size() + TAG_LEN);
  int len = 0;
  int clen = 0;

  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                              nullptr, nullptr)) {
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                               static_cast<int>(NONCE_BYTES), nullptr)) {
    throw std::runtime_error("set ivlen failed");
  }
  if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                              nonce.data())) {
    throw std::runtime_error("key/iv set failed");
  }

  if (!aad.empty()) {
    if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                               static_cast<int>(aad.size()))) {
      throw std::runtime_error("AAD failed");
    }
  }

  if (!plaintext.empty()) {
    if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                               plaintext.data(),
                               static_cast<int>(plaintext.size()))) {
      throw std::runtime_error("EncryptUpdate failed");
    }
    clen = len;
  }

  auto ciphertext_span = std::span(ciphertext);
  if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext_span.subspan(clen).data(),
                               &len)) {
    throw std::runtime_error("EncryptFinal failed");
  }
  clen += len;

  std::array<unsigned char, TAG_LEN> tag{};
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                               static_cast<int>(TAG_LEN), tag.data())) {
    throw std::runtime_error("Get tag failed");
  }

  ciphertext.resize(static_cast<std::size_t>(clen) + TAG_LEN);
  std::ranges::copy(tag, ciphertext.begin() + clen);

  return ciphertext;
}

inline std::vector<unsigned char> aead_decrypt(
    const secure_vector &key, std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> aad, std::span<const unsigned char> nonce) {
  if (key.size() < KEY_LEN) {
    throw std::runtime_error("bad key size for AEAD");
  }
  if (nonce.size() != NONCE_BYTES) {
    throw std::runtime_error("bad nonce length");
  }
  if (ciphertext.size() < TAG_LEN) {
    throw std::runtime_error("ciphertext too small");
  }

  const std::size_t ctlen = ciphertext.size() - TAG_LEN;
  std::vector<unsigned char> out(ctlen);
  int len = 0;
  int plen = 0;

  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                              nullptr, nullptr)) {
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                               static_cast<int>(NONCE_BYTES), nullptr)) {
    throw std::runtime_error("set ivlen failed");
  }
  if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                              nonce.data())) {
    throw std::runtime_error("key/iv set failed");
  }

  if (!aad.empty()) {
    if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                               static_cast<int>(aad.size()))) {
      throw std::runtime_error("AAD failed");
    }
  }

  if (ctlen > 0) {
    if (1 != EVP_DecryptUpdate(ctx.get(), out.data(), &len, ciphertext.data(),
                               static_cast<int>(ctlen))) {
      throw std::runtime_error("DecryptUpdate failed");
    }
    plen = len;
  }

  auto tag_span = ciphertext.subspan(ctlen, TAG_LEN);
  std::array<unsigned char, TAG_LEN> tag_copy{};
  std::ranges::copy(tag_span, tag_copy.begin());
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                               static_cast<int>(TAG_LEN), tag_copy.data())) {
    throw std::runtime_error("set tag failed");
  }

  auto out_span = std::span(out);
  if (1 !=
      EVP_DecryptFinal_ex(ctx.get(), out_span.subspan(plen).data(), &len)) {
    throw std::runtime_error("decryption failed (tag mismatch)");
  }
  plen += len;
  out.resize(static_cast<std::size_t>(plen));

  return out;
}

inline DirectionalSessionKeys
derive_directional_keys_from_secret(const secure_vector &shared,
                                    std::string_view context,
                                    bool i_am_initiator) {
  if (shared.empty()) {
    throw std::runtime_error("empty shared secret");
  }

  const EVP_MD *md = EVP_sha256();
  const auto hash_len = static_cast<std::size_t>(EVP_MD_size(md));

  std::vector<unsigned char> zero_salt(hash_len, 0);

  SecureArray<EVP_MAX_MD_SIZE> prk;
  unsigned int prk_len = 0;

  if (HMAC(md, zero_salt.data(), static_cast<int>(zero_salt.size()),
           shared.data(), static_cast<int>(shared.size()), prk.data(),
           &prk_len) == nullptr) {
    throw std::runtime_error("HKDF-Extract (HMAC) failed");
  }

  constexpr std::size_t okm_len = 32;

  const auto expand = [&](std::string_view label) {
    std::vector<unsigned char> info;
    info.reserve(label.size() + 1 + context.size() + 1);
    info.insert(info.end(), label.begin(), label.end());
    info.push_back('|');
    info.insert(info.end(), context.begin(), context.end());
    info.push_back(0x01);

    SecureArray<okm_len> okm;
    unsigned int out_len = 0;
    if (HMAC(md, prk.data(), static_cast<int>(prk_len), info.data(),
             static_cast<int>(info.size()), okm.data(), &out_len) ==
        nullptr) {
      throw std::runtime_error("HKDF-Expand (HMAC) failed");
    }
    if (out_len < okm_len) {
      throw std::runtime_error("HKDF derived insufficient output");
    }
    return secure_vector(
        okm.begin(), std::next(okm.begin(), static_cast<std::ptrdiff_t>(okm_len)));
  };

  secure_vector k_i2r = expand("SPRK-v2-initiator-to-responder");
  secure_vector k_r2i = expand("SPRK-v2-responder-to-initiator");

  if (i_am_initiator) {
    return DirectionalSessionKeys{std::move(k_i2r), std::move(k_r2i)};
  }
  return DirectionalSessionKeys{std::move(k_r2i), std::move(k_i2r)};
}

inline secure_vector derive_nonce_from_session(const secure_vector &session_key,
                                               std::uint32_t seq) {
  if (session_key.empty()) {
    throw std::runtime_error("empty session key");
  }

  std::array<unsigned char, 4> seqb{};
  seqb[0] = static_cast<unsigned char>((seq >> 24U) & 0xFFU);
  seqb[1] = static_cast<unsigned char>((seq >> 16U) & 0xFFU);
  seqb[2] = static_cast<unsigned char>((seq >> 8U) & 0xFFU);
  seqb[3] = static_cast<unsigned char>(seq & 0xFFU);

  unsigned int outlen = EVP_MAX_MD_SIZE;
  SecureArray<EVP_MAX_MD_SIZE> hmac_out;

  if (HMAC(EVP_sha256(), session_key.data(),
           static_cast<int>(session_key.size()), seqb.data(), seqb.size(),
           hmac_out.data(), &outlen) == nullptr) {
    throw std::runtime_error("HMAC failed");
  }

  secure_vector nonce(NONCE_BYTES);
  std::copy_n(hmac_out.data(), NONCE_BYTES, nonce.begin());
  return nonce;
}

inline secure_vector hkdf(const secure_vector &key,
                          std::span<const unsigned char> salt,
                          std::size_t len) {
  EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  if (pctx == nullptr) {
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  }

  if (1 != EVP_PKEY_derive_init(pctx.get())) {
    throw std::runtime_error("EVP_PKEY_derive_init failed");
  }
  if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256())) {
    throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
  }
  if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(),
                                       static_cast<int>(salt.size()))) {
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");
  }
  if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key.data(),
                                      static_cast<int>(key.size()))) {
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
  }

  secure_vector out(len);
  if (1 != EVP_PKEY_derive(pctx.get(), out.data(), &len)) {
    throw std::runtime_error("EVP_PKEY_derive failed");
  }

  return out;
}

inline std::array<unsigned char, SHA256_LEN>
fingerprint_sha256(std::span<const unsigned char> pk) {
  if (pk.empty()) {
    throw std::runtime_error("empty public key for fingerprint");
  }

  std::array<unsigned char, SHA256_LEN> out{};

  EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }
  if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) {
    throw std::runtime_error("EVP_DigestInit_ex failed");
  }
  if (1 != EVP_DigestUpdate(ctx.get(), pk.data(), pk.size())) {
    throw std::runtime_error("EVP_DigestUpdate failed");
  }
  unsigned int out_len = 0;
  if (1 != EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len)) {
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  }
  if (out_len != out.size()) {
    throw std::runtime_error("unexpected digest length");
  }
  return out;
}

inline std::string
fingerprint_to_hex(const std::array<unsigned char, SHA256_LEN> &f) {
  return to_hex(f.data(), f.size());
}

inline std::string compute_fingerprint_hex(std::span<const unsigned char> pk) {
  return fingerprint_to_hex(fingerprint_sha256(pk));
}

inline std::array<unsigned char, SHA256_LEN>
compute_fingerprint_array(std::span<const unsigned char> pk) {
  return fingerprint_sha256(pk);
}

#endif
