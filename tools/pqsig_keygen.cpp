#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <iostream>

#include <openssl/err.h>

#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

static void write_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if(!f) throw std::runtime_error("cannot open output file");
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    if(!f) throw std::runtime_error("write failed");
}

int main(int argc, char** argv) {
    if(argc != 2) {
        std::cerr << "Usage: pqsig_keygen <output.sk>\n";
        return 1;
    }

    std::string out = argv[1];

#ifndef USE_LIBOQS
    throw std::runtime_error("liboqs not enabled at build");
#else
    OQS_SIG* sig = OQS_SIG_new("ML-DSA-87");
    if(!sig) throw std::runtime_error("OQS_SIG_new failed");

    std::vector<unsigned char> pk(sig->length_public_key);
    std::vector<unsigned char> sk(sig->length_secret_key);

    if(OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("keypair generation failed");
    }

    OQS_SIG_free(sig);

    std::vector<unsigned char> outbuf;
    outbuf.reserve(sk.size() + pk.size());
    outbuf.insert(outbuf.end(), sk.begin(), sk.end());
    outbuf.insert(outbuf.end(), pk.begin(), pk.end());

    write_file(out, outbuf);

    return 0;
#endif
}