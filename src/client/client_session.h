#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "shared_common_crypto.h"
#include "shared_net_common_protocol.h"
#include "shared_net_key_util.h"
#include "shared_net_socket_util.h"
#include "shared_net_tls_frame_io.h"
#include "shared_net_username_util.h"

#include <asio/io_context.hpp>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <span>
#include <vector>

extern std::string                 session_id;
extern secure_vector               my_eph_pk;
extern secure_vector               my_eph_sk;
extern secure_vector               my_identity_pk;
extern secure_vector               my_identity_sk;
extern std::string                 my_username;
extern std::mutex                  ssl_io_mtx;
extern std::shared_ptr<ssl_socket> ssl_stream;

void asio_reader_loop();

inline bool setup_session_id(std::span<char *> args)
{
    std::string_view session_flag = "--sessionid";
    std::string_view alt_flag     = "-sessionid";

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

inline void attempt_connection_async(
    asio::io_context &io, const std::string &server, int port,
    secure_vector &persisted_eph_pk, secure_vector &persisted_eph_sk,
    bool &have_persisted_eph, std::function<void(bool)> completion_handler)
{
    std::cout << "[" << get_current_timestamp_ms()
              << "] attempting connection to " << server << ":" << port << "\n";

    if (!have_persisted_eph)
    {
        const auto [pk, sk] = pqkem_keypair(KEM_ALG_NAME);
        persisted_eph_pk    = pk;
        persisted_eph_sk    = sk;
        have_persisted_eph  = true;
    }

    my_eph_pk = persisted_eph_pk;
    my_eph_sk = persisted_eph_sk;

    async_connect_to_host_asio(
        io, server.c_str(), port,
        [&io, completion_handler](std::shared_ptr<asio::ip::tcp::socket> sock,
                                  std::error_code                        ec)
        {
            if (ec)
            {
                std::cout << "[" << get_current_timestamp_ms()
                          << "] connection failed: " << ec.message() << "\n";
                completion_handler(false);
                return;
            }
            std::cout << "[" << get_current_timestamp_ms()
                      << "] TCP connection established\n";
            auto stream =
                std::make_shared<ssl_socket>(std::move(*sock), *ssl_ctx);

            std::cout << "[" << get_current_timestamp_ms()
                      << "] starting TLS handshake\n";

            stream->async_handshake(
                asio::ssl::stream_base::client,
                [stream, completion_handler](const std::error_code &ec)
                {
                    if (ec)
                    {
                        std::cerr << "[" << get_current_timestamp_ms()
                                  << "] TLS handshake failed: " << ec.message()
                                  << "\n";
                        completion_handler(false);
                        return;
                    }

                    std::cout << "[" << get_current_timestamp_ms()
                              << "] TLS handshake successful\n";

                    {
                        std::lock_guard<std::mutex> lk(ssl_io_mtx);
                        ssl_stream = stream;
                    }

                    std::vector<unsigned char> sig_data;
                    sig_data.reserve(my_eph_pk.size() + session_id.size());
                    sig_data.insert(sig_data.end(), my_eph_pk.begin(),
                                    my_eph_pk.end());
                    sig_data.insert(sig_data.end(), session_id.begin(),
                                    session_id.end());

                    const auto signature = pqsig_sign(
                        SIG_ALG_NAME,
                        std::vector<unsigned char>(my_identity_sk.begin(),
                                                   my_identity_sk.end()),
                        sig_data);

                    const auto hello_frame = build_hello(
                        my_username, ALGO_KEM_ALG_NAME,
                        std::vector<unsigned char>(my_eph_pk.begin(),
                                                   my_eph_pk.end()),
                        ALGO_MLDSA87,
                        std::vector<unsigned char>(my_identity_pk.begin(),
                                                   my_identity_pk.end()),
                        signature, std::vector<unsigned char>{}, session_id);

                    auto frame_ptr =
                        std::make_shared<std::vector<unsigned char>>(
                            hello_frame);

                    async_write_frame(
                        stream, frame_ptr,
                        [completion_handler,
                         frame_ptr](const std::error_code &ec, std::size_t)
                        {
                            if (ec)
                            {
                                std::cout << "[" << get_current_timestamp_ms()
                                          << "] failed to send hello: "
                                          << ec.message() << "\n";
                                completion_handler(false);
                                return;
                            }

                            is_connected = true;
                            asio_reader_loop();
                            completion_handler(true);
                        });
                });
        });
}

#endif