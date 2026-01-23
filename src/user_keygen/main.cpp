#include <Poco/Exception.h>
#include <Poco/File.h>
#include <Poco/FileStream.h>
#include <Poco/Path.h>
#include <Poco/StreamCopier.h>
#include <Poco/TemporaryFile.h>
#include <array>
#include <bit>
#include <cstring>
#include <iostream>
#include <memory>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

struct EVPKeyDeleter
{
    void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); }
};

struct EVPKeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX *p) const noexcept { EVP_PKEY_CTX_free(p); }
};

struct BIODeleter
{
    void operator()(BIO *p) const noexcept { BIO_free(p); }
};

struct X509Deleter
{
    void operator()(X509 *p) const noexcept { X509_free(p); }
};

using UniqueEVPKey    = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using UniqueEVPKeyCtx = std::unique_ptr<EVP_PKEY_CTX, EVPKeyCtxDeleter>;
using UniqueBIO       = std::unique_ptr<BIO, BIODeleter>;
using UniqueX509      = std::unique_ptr<X509, X509Deleter>;

static void write_file(const Poco::Path &path, std::span<const std::byte> data)
{
    Poco::File file(path);
    if (file.exists() && !file.canWrite())
        throw std::runtime_error("Cannot write to file " + path.toString());

    Poco::FileOutputStream f(path.toString(),
                             std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("Failed to open " + path.toString());

    f.write(std::bit_cast<const char *>(data.data()),
            std::streamsize(data.size()));

    if (!f)
        throw std::runtime_error("Write failed for " + path.toString());
}

static UniqueEVPKey generate_ml_dsa_key(std::string_view alg_name)
{
    UniqueEVPKeyCtx ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, alg_name.data(), nullptr));
    if (!ctx)
        throw std::runtime_error(std::string("EVP_PKEY_CTX_new_from_name "
                                             "failed for ") +
                                 std::string(alg_name));

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        throw std::runtime_error(std::string("keygen_init failed for ") +
                                 std::string(alg_name));

    EVP_PKEY *raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0)
        throw std::runtime_error(std::string("keygen failed for ") +
                                 std::string(alg_name));

    return UniqueEVPKey(raw_pkey);
}

static std::vector<std::byte> evp_to_pem_private(EVP_PKEY *pkey)
{
    UniqueBIO bio(BIO_new(BIO_s_mem()));
    if (!bio)
        throw std::runtime_error("BIO_new failed");

    if (PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr,
                                 nullptr) == 0)
        throw std::runtime_error("PEM_write_privatekey failed");

    char      *buf = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &buf);
    if (len < 0 || buf == nullptr)
        throw std::runtime_error("BIO_get_mem_data failed");

    std::vector<std::byte> result;
    result.reserve(static_cast<std::size_t>(len));
    const auto src = std::span(buf, static_cast<std::size_t>(len));
    for (const char c : src)
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));

    return result;
}

static std::vector<std::byte> evp_to_raw_combined(EVP_PKEY *pkey)
{
    std::size_t sk_len = 0;
    std::size_t pk_len = 0;

    EVP_PKEY_get_raw_private_key(pkey, nullptr, &sk_len);
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &pk_len);

    std::vector<std::byte> raw_out;
    raw_out.resize(sk_len + pk_len);

    auto *sk_ptr = std::bit_cast<unsigned char *>(raw_out.data());
    std::span<unsigned char> sk_span(sk_ptr, sk_len);
    std::span<unsigned char> pk_span =
        std::span<unsigned char>(sk_ptr, raw_out.size()).subspan(sk_len);

    EVP_PKEY_get_raw_private_key(pkey, sk_span.data(), &sk_len);
    EVP_PKEY_get_raw_public_key(pkey, pk_span.data(), &pk_len);

    return raw_out;
}

static UniqueX509 create_self_signed_cert(EVP_PKEY *pkey, std::string_view cn)
{
    UniqueX509 x509(X509_new());
    if (!x509)
        throw std::runtime_error("X509_new failed");

    X509_set_version(x509.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);

    X509_NAME        *name = X509_get_subject_name(x509.get());
    const auto *const cn_uchar =
        std::bit_cast<const unsigned char *>(cn.data());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn_uchar,
                               static_cast<int>(cn.size()), -1, 0);
    X509_set_issuer_name(x509.get(), name);
    X509_set_pubkey(x509.get(), pkey);

    if (X509_sign(x509.get(), pkey, nullptr) <= 0)
        throw std::runtime_error("X509_sign failed");

    return x509;
}

static std::vector<std::byte> x509_to_pem(X509 *x509)
{
    UniqueBIO bio(BIO_new(BIO_s_mem()));
    if (!bio)
        throw std::runtime_error("BIO_new failed for cert");

    if (PEM_write_bio_X509(bio.get(), x509) == 0)
        throw std::runtime_error("PEM_write_X509 failed");

    char      *buf = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &buf);
    if (len < 0 || buf == nullptr)
        throw std::runtime_error("BIO_get_mem_data failed for cert");

    std::vector<std::byte> result;
    result.reserve(static_cast<std::size_t>(len));
    const auto src = std::span(buf, static_cast<std::size_t>(len));
    for (const char c : src)
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));

    return result;
}

static void generate_pq_key_and_cert(const Poco::Path &base_path,
                                     bool              output_raw)
{
    UniqueEVPKey pkey = generate_ml_dsa_key("ML-DSA-87");

    const std::vector<std::byte> pem_data = evp_to_pem_private(pkey.get());
    Poco::Path                   pem_path = base_path;
    pem_path.setExtension("sk.pem");
    write_file(pem_path, pem_data);

    if (output_raw)
    {
        const std::vector<std::byte> raw_data = evp_to_raw_combined(pkey.get());
        Poco::Path                   raw_path = base_path;
        raw_path.setExtension("sk.raw");
        write_file(raw_path, raw_data);
    }

    const std::string_view cn   = base_path.getFileName();
    UniqueX509             x509 = create_self_signed_cert(pkey.get(), cn);

    const std::vector<std::byte> cert_data = x509_to_pem(x509.get());
    Poco::Path                   crt_path  = base_path;
    crt_path.setExtension("crt");
    write_file(crt_path, cert_data);
}

static void print_usage(const Poco::Path &base_path)
{
    Poco::Path pem_path = base_path;
    pem_path.setExtension("sk.pem");

    Poco::Path raw_path = base_path;
    raw_path.setExtension("sk.raw");

    Poco::Path crt_path = base_path;
    crt_path.setExtension("crt");

    std::cerr
        << "Usage: keygen <base_name> [--raw] [--out-dir <directory>]\n"
           "  <base_name>      : Base filename for output key and certificate\n"
           "  --raw            : Optional flag to output raw private/public "
           "key combined\n"
           "  --out-dir <dir>  : Optional output directory (default: current "
           "directory)\n"
           "  --help           : Show this help message\n\n"
           "Output files will be generated as:\n"
           "  Private key (PEM)  : "
        << pem_path.toString()
        << "\n"
           "  Certificate (PEM)  : "
        << crt_path.toString()
        << "\n"
           "  Raw key combined   : "
        << raw_path.toString() << " (if --raw is specified)\n";
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage(Poco::Path::current());
        return 1;
    }

    const std::span        argv_span(argv, static_cast<std::size_t>(argc));
    const std::string_view base_name = argv_span[1];
    bool                   want_raw  = false;
    Poco::Path             out_dir   = Poco::Path::current();

    for (std::size_t i = 2; i < argv_span.size(); ++i)
    {
        const std::string_view arg = argv_span[i];
        if (arg == "--raw")
        {
            want_raw = true;
        }
        else if (arg == "--out-dir" && i + 1 < argv_span.size())
        {
            out_dir = argv_span[i + 1];
            if (!out_dir.isAbsolute())
                out_dir.makeAbsolute();
            ++i;
        }
        else if (arg == "--help")
        {
            print_usage(out_dir);
            return 0;
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(Poco::Path::current());
            return 1;
        }
    }

    Poco::Path base_path = out_dir;
    base_path.setFileName(std::string(base_name));

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