#include <cstring> // for strcmp
#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>
#include <vector>

static void write_file(const std::string                &path,
                       const std::vector<unsigned char> &data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("cannot open " + path);
    f.write(reinterpret_cast<const char *>(data.data()), data.size());
    if (!f)
        throw std::runtime_error("write failed for " + path);
}

static EVP_PKEY *generate_ml_dsa_key(const std::string &alg_name)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr);
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for " +
                                 alg_name);

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("keygen_init failed for " + alg_name);
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("keygen failed for " + alg_name);
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void generate_pq_key_and_cert(const std::string &base_name,
                                     bool               output_raw = false)
{
    EVP_PKEY *pkey = generate_ml_dsa_key("ML-DSA-87");

    // 1. PEM format (recommended - standard OpenSSL)
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio_mem, pkey, nullptr, nullptr, 0, nullptr,
                                  nullptr))
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio_mem);
        throw std::runtime_error("PEM_write_privatekey failed");
    }
    char                      *buf;
    long                       len = BIO_get_mem_data(bio_mem, &buf);
    std::vector<unsigned char> pem_data(buf, buf + len);
    BIO_free(bio_mem);
    write_file(base_name + ".sk.pem", pem_data);

    // 2. Optional raw binary (sk || pk) - for old code compatibility
    std::string raw_path;
    if (output_raw)
    {
        size_t sk_len = 0, pk_len = 0;
        EVP_PKEY_get_raw_private_key(pkey, nullptr, &sk_len);
        EVP_PKEY_get_raw_public_key(pkey, nullptr, &pk_len);

        std::vector<unsigned char> raw_sk(sk_len);
        EVP_PKEY_get_raw_private_key(pkey, raw_sk.data(), &sk_len);

        std::vector<unsigned char> raw_pk(pk_len);
        EVP_PKEY_get_raw_public_key(pkey, raw_pk.data(), &pk_len);

        std::vector<unsigned char> raw_out;
        raw_out.reserve(sk_len + pk_len);
        raw_out.insert(raw_out.end(), raw_sk.begin(), raw_sk.end());
        raw_out.insert(raw_out.end(), raw_pk.begin(), raw_pk.end());

        raw_path = base_name + ".sk.raw";
        write_file(raw_path, raw_out);
    }

    // 3. Self-signed cert (always PEM)
    X509 *x509 = X509_new();
    if (!x509)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("X509_new failed");
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)base_name.c_str(), -1, -1,
                               0);
    X509_set_issuer_name(x509, name);
    X509_set_pubkey(x509, pkey);

    // NULL digest is mandatory for ML-DSA
    if (X509_sign(x509, pkey, nullptr) <= 0)
    {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        throw std::runtime_error(
            "X509_sign failed (ML-DSA requires NULL digest)");
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(bio_mem, x509))
    {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        BIO_free(bio_mem);
        throw std::runtime_error("PEM_write_X509 failed");
    }

    len = BIO_get_mem_data(bio_mem, &buf);
    std::vector<unsigned char> cert_data(buf, buf + len);
    BIO_free(bio_mem);
    write_file(base_name + ".crt", cert_data);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    std::cout << "Generated:\n"
              << "  " << base_name
              << ".sk.pem   (PEM - recommended for new code)\n";
    if (output_raw)
    {
        std::cout << "  " << raw_path << " (raw binary - old compat)\n";
    }
    std::cout << "  " << base_name << ".crt     (self-signed ML-DSA-87 cert)\n";
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3)
    {
        std::cerr
            << "Usage: keygen <base_name> [--raw]\n"
            << "  --raw   also generate .sk.raw (old raw binary format)\n";
        return 1;
    }

    std::string base_name = argv[1];
    bool        want_raw  = (argc == 3 && std::strcmp(argv[2], "--raw") == 0);

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    ERR_load_crypto_strings();

    try
    {
        generate_pq_key_and_cert(base_name, want_raw);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}