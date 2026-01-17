#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "client_runtime.h"
#include "shared_common_util.h"
#include "client_crypto_util.h"
#include "shared_net_key_util.h"
#include "shared_net_tls_frame_io.h"
#include "shared_net_username_util.h"
#include "shared_net_rekey_util.h"
#include "shared_net_common_protocol.h"

#include <string>
#include <span>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <vector>
#include <functional>
#include <memory>
#include <openssl/ssl.h>



extern std::string session_id;
extern secure_vector my_eph_pk;
extern secure_vector my_eph_sk;
extern std::string my_username;


inline bool setup_session_id(std::span<char *> args)
{
    std::string_view session_flag = "--sessionid";
    std::string_view alt_flag = "-sessionid";

    for (size_t i = 1; i < args.size() - 1; ++i)
    {
        std::string_view arg = args[i];
        if (arg == session_flag || arg == alt_flag)
        {
            session_id = args[i + 1];
            if (!is_valid_session_id(session_id))
            {
                std::cout << "Invalid session_id format\n";
                return false;
            }
            std::cout << "Using provided session_id: " << session_id << "\n";
            return true;
        }
    }

    session_id = generate_session_id();
    std::cout << "Generated new session_id: " << session_id << "\n";
    return true;
}


inline int attempt_connection(const std::string &server, int port,
                              secure_vector &persisted_eph_pk,
                              secure_vector &persisted_eph_sk,
                              bool          &have_persisted_eph)
{
    if (!have_persisted_eph)
    {
        const auto [pk, sk] = pqkem_keypair(KEM_ALG_NAME);
        persisted_eph_pk    = pk;
        persisted_eph_sk    = sk;
        have_persisted_eph  = true;
    }

    my_eph_pk = persisted_eph_pk;
    my_eph_sk = persisted_eph_sk;

    const int s = connect_to_host(server.c_str(), port);
    if (s < 0)
    {
        std::cout << "[" << get_current_timestamp_ms() << "] connection failed\n";
        return -1;
    }

    SSL* new_ssl = SSL_new(ssl_ctx->native_handle());
    if (!new_ssl)
    {
        std::cerr << "SSL_new failed\n";
        ERR_print_errors_fp(stderr);
        close(s);
        return -1;
    }

    SSL_set_fd(new_ssl, s);

    int ret = SSL_connect(new_ssl);
    if (ret <= 0)
    {
        int err = SSL_get_error(new_ssl, ret);
        std::cerr << "SSL_connect failed (err=" << err << ")\n";
        ERR_print_errors_fp(stderr);
        SSL_free(new_ssl);
        close(s);
        return -1;
    }

    std::cout << "[" << get_current_timestamp_ms() << "] TLS handshake successful\n";
    {
        std::lock_guard<std::mutex> lk(ssl_io_mtx);
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ssl = new_ssl;
    }

      std::vector<unsigned char> sig_data;
      sig_data.reserve(my_eph_pk.size() + session_id.size());
      sig_data.insert(sig_data.end(), my_eph_pk.begin(), my_eph_pk.end());
      sig_data.insert(sig_data.end(), session_id.begin(), session_id.end());

      const auto signature =
          pqsig_sign(SIG_ALG_NAME,
                     std::vector<unsigned char>(my_identity_sk.begin(),
                                                my_identity_sk.end()),
                     sig_data);

      const auto hello_frame = build_hello(
          my_username, ALGO_KEM_ALG_NAME,
          std::vector<unsigned char>(my_eph_pk.begin(), my_eph_pk.end()),
          ALGO_MLDSA87,
          std::vector<unsigned char>(my_identity_pk.begin(),
                                     my_identity_pk.end()),
          signature, std::vector<unsigned char>{}, session_id);

      {
          std::lock_guard<std::mutex> lk(ssl_io_mtx);
          if (tls_full_send(ssl, hello_frame.data(), hello_frame.size()) <= 0)
          {
              std::cout << "[" << get_current_timestamp_ms() << "] failed to send hello\n";
              SSL_free(ssl);
              ssl = nullptr;
              close(s);
              return -1;
          }
      }

      return s;
}

#endif