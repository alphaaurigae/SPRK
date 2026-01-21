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

#include "client_cmdline_util.h"
#include "client_commands.h"
#include "client_crypto_util.h"
#include "client_message_util.h"
#include "client_peer_manager.h"
#include "client_reader_writer.h"
#include "client_runtime.h"
#include "client_session.h"

#include <algorithm>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include <array>
#include <atomic>
#include <chrono>

#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>

#include <span>
#include <sstream>
#include <string>
#include <string_view>

#include <thread>

#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
static constexpr uint64_t INITIAL_BACKOFF_MS     = 1000;
static constexpr uint64_t MAX_BACKOFF_MS         = 60000;

int main(int argc, char **argv) noexcept
try
{
    const std::span args(argv, static_cast<std::size_t>(argc));

    const auto config = parse_command_line_args(args);
    my_username       = config.username;

    std::signal(SIGPIPE, SIG_IGN);

    if (!load_identity_keys(args[4]))
    {
        return 1;
    }

    if (!setup_session_id(args))
    {
        return 1;
    }

    asio::io_context io;

    if (args.size() < 6)
    {
        std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                     "<identity_sk.pem> <client_cert.crt> "
                     "[--sessionid <id>] [--debug]\n";
        return 1;
    }

    crypto_init();

    // Initialize TLS context
    std::string cert_path =
        std::string("sample/sample_test_cert/") + my_username + ".crt";
    std::string key_path =
        std::string("sample/sample_test_cert/") + my_username + "_tls.key";

    ssl_ctx = init_tls_client_context(cert_path, key_path,
                                      "sample/sample_test_cert/ca.crt");
    if (!ssl_ctx)
    {
        std::cerr << "TLS context initialization failed\n";
        return 1;
    }

    secure_vector persisted_eph_pk;
    secure_vector persisted_eph_sk;
    bool          have_persisted_eph = false;

    uint32_t          reconnect_attempts = 0;
    std::atomic<bool> connection_complete{false};

    auto        io_work = asio::require(io.get_executor(),
                                        asio::execution::outstanding_work.tracked);
    std::thread io_thread(
        [&io, work = std::move(io_work)]
        {
            std::cout << "[" << get_current_timestamp_ms()
                      << "] io_context thread started\n";
            try
            {
                io.run();
            }
            catch (const std::exception &e)
            {
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] io_context exception: " << e.what() << "\n";
            }
            catch (...)
            {
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] io_context unknown exception\n";
            }
            std::cout << "[" << get_current_timestamp_ms()
                      << "] io_context thread exiting\n";
        });

    while (should_reconnect && reconnect_attempts < MAX_RECONNECT_ATTEMPTS)
    {
        if (reconnect_attempts > 0)
        {
            const uint64_t backoff = std::min<uint64_t>(
                INITIAL_BACKOFF_MS * (1ULL << (reconnect_attempts - 1)),
                MAX_BACKOFF_MS);
            std::cout << "[" << get_current_timestamp_ms()
                      << "] reconnecting in " << backoff << "ms (attempt "
                      << reconnect_attempts + 1 << ")\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }

        connection_complete = false;
        attempt_connection_async(io, config.server, config.port,
                                 persisted_eph_pk, persisted_eph_sk,
                                 have_persisted_eph,
                                 [&connection_complete](bool success)
                                 {
                                     if (success)
                                     {
                                         is_connected = true;
                                     }
                                     connection_complete = true;
                                 });

        while (!connection_complete)

        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!is_connected)
        {
            ++reconnect_attempts;
            continue;
        }

        reconnect_attempts = 0;

        // std::thread reader(reader_thread);
        std::thread writer(writer_thread);

        writer.join();
        // reader.join();

        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (ssl_stream)
            {
                std::error_code ec;
                ssl_stream->lowest_layer().close(ec);
                ssl_stream.reset();
            }
        }

        {
            const std::lock_guard<std::mutex> lk(peers_mtx);
            for (auto &kv : peers)
            {
                kv.second.ready      = false;
                kv.second.sent_hello = false;
                kv.second.sk.key.clear();
            }
        }
    }

    if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS)
    {
        std::cout << "[" << get_current_timestamp_ms()
                  << "] max reconnection attempts reached\n";
    }

    {
        const std::lock_guard<std::mutex> lk(ssl_io_mtx);
        if (ssl_stream)
        {
            std::error_code ec;
            ssl_stream->lowest_layer().close(ec);
            ssl_stream.reset();
        }
    }
    io.stop();
    if (io_thread.joinable())
        io_thread.join();

    ssl_ctx.reset();

    return 0;
}
catch (const std::exception &e)
{
    std::cerr << "Fatal error: " << e.what() << "\n";
    return 1;
}
catch (...)
{
    std::cerr << "Fatal unknown error\n";
    return 1;
}
