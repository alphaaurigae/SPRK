#ifndef NET_KEY_UTIL_H
#define NET_KEY_UTIL_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "common_crypto.h"
#include "common_util.h"
#include "net_common_protocol.h"

// Key-related utilities moved from client code
struct PQKeypair {
     secure_vector sk;
     std::vector<unsigned char> pk;
};

struct SessionId {
     std::string value;
};

struct PeerName {
     std::string value;
};

extern secure_vector my_identity_sk;
extern secure_vector my_identity_pk;
extern std::string my_fp_hex;

inline PQKeypair derive_ephemeral_for_peer(const secure_vector &identity_sk,
                                            const SessionId &session_id,
                                            const PeerName &peer)
{

#ifdef USE_LIBOQS
     std::vector<unsigned char> salt(session_id.value.begin(), session_id.value.end());
     salt.insert(salt.end(), peer.value.begin(), peer.value.end());

     OQS_KEM *kem = OQS_KEM_new("Kyber512");
     if (!kem) throw std::runtime_error("pqkem new failed");

     const secure_vector derived_key = hkdf(identity_sk, salt, kem->length_secret_key);
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

inline bool load_identity_keys(const char* key_path) {
     try {
         secure_vector raw_sk, raw_pk;
         if (!load_pem_private_key(key_path, raw_sk, raw_pk)) {
             return false;
         }
         my_identity_sk = std::move(raw_sk);
         if (raw_pk.empty()) {
             throw std::runtime_error("identity public key not present");
         }
         my_identity_pk = std::move(raw_pk);

         my_fp_hex = compute_fingerprint_hex(my_identity_pk);

         std::cout << "Loaded PEM identity key: " << key_path << "\n";
         std::cout << "My fingerprint: " << my_fp_hex << "\n";

         return true;
     } catch (const std::exception& e) {
         std::cout << "Failed to load private/public key: " << e.what() << "\n";
         return false;
     }
}

inline std::string compute_peer_key(const Parsed &p, std::string &peer_fp_hex) {
     if (!p.identity_pk.empty())
     {
         const auto fp = fingerprint_sha256(p.identity_pk);
         peer_fp_hex   = fingerprint_to_hex(fp);
         return peer_fp_hex;
     }
     return "uname:" + trim(p.username);
}

#endif
