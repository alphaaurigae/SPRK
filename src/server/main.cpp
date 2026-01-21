#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_key_util.h"
#include "shared_net_message_util.h"
#include "shared_net_rekey_util.h"
#include "shared_net_socket_util.h"
#include "shared_net_tls_context.h"
#include "shared_net_tls_frame_io.h"
#include "shared_net_username_util.h"

#include "server/server_client_state.h"
#include "server/server_connection.h"
#include "server/server_handlers.h"
#include "server/server_session.h"

#include <asio/io_context.hpp>
#include <iostream>

#include <unordered_map>
#include <unordered_set>
#include <vector>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cout << "Usage: chat_server <port>\n";
        return 1;
    }

    int              port = std::stoi(argv[1]);
    asio::io_context io;
    std::error_code  ec;

    auto acceptor = make_listen_socket_asio(io, port, 16, true, &ec);
    if (!acceptor)
    {
        std::cerr << "Failed to create acceptor: " << ec.message() << "\n";
        return 1;
    }

    auto ctx = init_tls_server_context("sample/sample_test_cert/server.crt",
                                       "sample/sample_test_cert/server.key",
                                       "sample/sample_test_cert/ca.crt");
    if (!ctx)
    {
        std::cerr << "TLS server context initialization failed\n";
        return 1;
    }
    std::unordered_map<std::string, SessionData> sessions;

    std::cout << "Server listening on port " << port
              << " with post-quantum TLS\n";
    std::function<void()> accept_loop = [&]()
    {
        std::cerr << "[" << get_current_timestamp_ms()
                  << "] accept_loop: posting async_accept_client\n";
        async_accept_client(
            acceptor, ctx,
            [&sessions, &accept_loop](std::shared_ptr<ssl_socket> stream,
                                      std::error_code             ec)
            {
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] accept callback: ec="
                          << (ec ? ec.message() : "ok")
                          << " stream=" << (stream ? "yes" : "no") << "\n";

                if (ec)
                {
                    // log and continue accepting
                    std::cerr << "[" << get_current_timestamp_ms()
                              << "] accept failed: " << ec.message() << "\n";
                    accept_loop();
                    return;
                }

                if (!stream)
                {
                    std::cerr << "[" << get_current_timestamp_ms()
                              << "] accept returned null stream\n";
                    accept_loop();
                    return;
                }

                std::cerr << "[" << get_current_timestamp_ms()
                          << "] starting TLS handshake for new client\n";
                stream->async_handshake(
                    asio::ssl::stream_base::server,
                    [stream, &sessions](const std::error_code &ec)
                    {
                        std::cerr << "[" << get_current_timestamp_ms()
                                  << "] handshake callback: ec="
                                  << (ec ? ec.message() : "ok") << "\n";
                        if (ec)
                        {
                            std::cerr
                                << "[" << get_current_timestamp_ms()
                                << "] TLS handshake failed: " << ec.message()
                                << "\n";
                            return;
                        }

                        std::cerr << "[" << get_current_timestamp_ms()
                                  << "] TLS handshake successful, creating "
                                     "ClientState\n";
                        auto client = std::make_shared<ClientState>(stream);
                        start_client_session(client, sessions);
                    });
                accept_loop();
            });
    };

    accept_loop();
    asio::executor_work_guard<asio::io_context::executor_type> work_guard(
        io.get_executor());
    std::vector<std::thread> io_threads;
    for (unsigned i = 0; i < std::thread::hardware_concurrency(); ++i)
    {
        io_threads.emplace_back([&io] { io.run(); });
    }

    work_guard.reset();
    for (auto &t : io_threads)
    {
        if (t.joinable())
            t.join();
    }

    return 0;
}
