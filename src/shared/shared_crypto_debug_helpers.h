#ifndef SHARED_CRYPTO_DEBUG_HELPERS_H
#define SHARED_CRYPTO_DEBUG_HELPERS_H

#include "shared_common_util.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <vector>

inline bool aead_aes_gcm_encrypt_debug(const unsigned char *key, int key_len,
                                       const unsigned char *iv, int iv_len,
                                       const unsigned char *aad, int aad_len,
                                       const unsigned char *pt, int pt_len,
                                       std::vector<unsigned char> &out_ct,
                                       std::vector<unsigned char> &out_tag,
                                       uint64_t seq, std::string_view context)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    const EVP_CIPHER *cipher =
        (key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    int rv = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rv = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (aad && aad_len > 0)
    {
        int outl = 0;
        rv       = EVP_EncryptUpdate(ctx, nullptr, &outl, aad, aad_len);
        if (rv != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    out_ct.resize(pt_len);
    int outl = 0;
    rv       = EVP_EncryptUpdate(ctx, out_ct.data(), &outl, pt, pt_len);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int tmplen = 0;
    rv         = EVP_EncryptFinal_ex(ctx, out_ct.data() + outl, &tmplen);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outl += tmplen;
    out_ct.resize(outl);
    out_tag.resize(16);
    rv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(out_tag.size()), out_tag.data());
    EVP_CIPHER_CTX_free(ctx);
    if (rv != 1)
        return false;
    std::cerr << "[AEAD-ENC] seq=" << seq << " ctx=" << std::string(context)
              << " key_len=" << key_len << " iv_len=" << iv_len
              << " pt_len=" << pt_len << " ct_len=" << out_ct.size()
              << " tag=" << to_hex(out_tag)
              << " iv_prefix=" << to_hex(iv, std::min(iv_len, 12)) << "\n";
    return true;
}

inline bool aead_aes_gcm_decrypt_debug(const unsigned char *key, int key_len,
                                       const unsigned char *iv, int iv_len,
                                       const unsigned char *aad, int aad_len,
                                       const unsigned char *ct, int ct_len,
                                       const unsigned char *tag, int tag_len,
                                       std::vector<unsigned char> &out_pt,
                                       uint64_t seq, std::string_view context)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    const EVP_CIPHER *cipher =
        (key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    int rv = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rv = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (aad && aad_len > 0)
    {
        int outl = 0;
        rv       = EVP_DecryptUpdate(ctx, nullptr, &outl, aad, aad_len);
        if (rv != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    out_pt.resize(ct_len);
    int outl = 0;
    rv       = EVP_DecryptUpdate(ctx, out_pt.data(), &outl, ct, ct_len);
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len,
                             const_cast<unsigned char *>(tag));
    if (rv != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int tmplen = 0;
    rv         = EVP_DecryptFinal_ex(ctx, out_pt.data() + outl, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    if (rv != 1)
    {
        std::cerr << "[AEAD-DEC-FAIL] seq=" << seq
                  << " ctx=" << std::string(context) << " key_len=" << key_len
                  << " iv_len=" << iv_len << " ct_len=" << ct_len
                  << " tag=" << to_hex(tag, tag_len)
                  << " iv_prefix=" << to_hex(iv, std::min(iv_len, 12)) << "\n";
        return false;
    }
    outl += tmplen;
    out_pt.resize(outl);
    std::cerr << "[AEAD-DEC] seq=" << seq << " ctx=" << std::string(context)
              << " pt_len=" << out_pt.size() << " ct_len=" << ct_len << "\n";
    return true;
}

#endif