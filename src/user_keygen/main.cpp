#include <Poco/Exception.h>
#include <Poco/File.h>
#include <Poco/FileStream.h>
#include <Poco/Path.h>
#include <Poco/StreamCopier.h>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

static void write_file(const Poco::Path                 &path,
                       const std::vector<unsigned char> &data)
{
    Poco::File file(path);
    if (file.exists() && !file.canWrite())
        throw std::runtime_error("Cannot write to file " + path.toString());

    Poco::FileOutputStream f(path.toString(),
                             std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("Failed to open " + path.toString());
    f.write(reinterpret_cast<const char *>(data.data()),
            std::streamsize(data.size()));
    if (!f)
        throw std::runtime_error("Write failed for " + path.toString());
}

static EVP_PKEY *generate_ml_dsa_key(const std::string &alg_name)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr);
    if (ctx == nullptr)
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
static void generate_pq_key_and_cert(const Poco::Path &base_path,
                                     bool              output_raw = false)
{
    EVP_PKEY *pkey = generate_ml_dsa_key("ML-DSA-87");

    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bio_mem, pkey, nullptr, nullptr, 0, nullptr,
                                 nullptr) == 0)
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio_mem);
        throw std::runtime_error("PEM_write_privatekey failed");
    }

    char                      *buf = nullptr;
    long                       len = BIO_get_mem_data(bio_mem, &buf);
    std::vector<unsigned char> pem_data(buf, buf + static_cast<size_t>(len));

    Poco::Path pem_path = base_path;
    pem_path.setExtension("sk.pem");
    write_file(pem_path, pem_data);

    if (output_raw)
    {
        size_t sk_len = 0;
        size_t pk_len = 0;
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

        Poco::Path raw_path = base_path;
        raw_path.setExtension("sk.raw");
        write_file(raw_path, raw_out);
    }

    X509 *x509 = X509_new();
    if (x509 == nullptr)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("X509_new failed");
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    const std::string cn   = base_path.getFileName();
    X509_NAME        *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(cn.data()),
        static_cast<int>(cn.size()), -1, 0);
    X509_set_issuer_name(x509, name);
    X509_set_pubkey(x509, pkey);

    if (X509_sign(x509, pkey, nullptr) <= 0)
    {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("X509_sign failed");
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bio_mem, x509) == 0)
    {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        BIO_free(bio_mem);
        throw std::runtime_error("PEM_write_X509 failed");
    }

    len = BIO_get_mem_data(bio_mem, &buf);
    std::vector<unsigned char> cert_data(buf, buf + static_cast<size_t>(len));
    BIO_free(bio_mem);

    Poco::Path crt_path = base_path;
    crt_path.setExtension("crt");
    write_file(crt_path, cert_data);

    X509_free(x509);
    EVP_PKEY_free(pkey);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3)
    {
        std::cerr << "Usage: keygen <base_name> [--raw]\n";
        return 1;
    }

    Poco::Path base_path(argv[1]);
    if (!base_path.isAbsolute())
        base_path.makeAbsolute();

    bool want_raw = (argc == 3 && std::string_view(argv[2]) == "--raw");

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    ERR_load_crypto_strings();

    try
    {
        generate_pq_key_and_cert(base_path, want_raw);
    }
    catch (const Poco::Exception &e)
    {
        std::cerr << "Poco Error: " << e.displayText() << "\n";
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}