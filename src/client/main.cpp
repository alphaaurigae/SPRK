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
#include <arpa/inet.h>
#include <array>
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
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

    asio::io_context    io;
    RekeyTimeoutManager rtm(io); // Initialize with io

    std::thread io_thread(
        [&io]
        {
            io.run(); // Run Asio event loop for timers
        });

    if (args.size() < 6)
    {
        std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                     "<identity_sk.pem> <client_cert.crt> "
                     "[--sessionid <id>] [--debug]\n";
        return 1;
    }

    crypto_init();

    // Initialize TLS context (this also loads OQS providers)
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

    // Load OQS provider for protocol-level crypto (separate from TLS)
    if (!init_oqs_provider())
    {
        std::cerr
            << "Cannot continue without OQS provider for protocol crypto\n";
        ssl_ctx.reset();
        return 1;
    }

    {
        const std::lock_guard<std::mutex> lk(ssl_io_mtx);
        ssl =
            SSL_new(ssl_ctx->native_handle()); // create SSL* from Asio context
        if (!ssl)
        {
            std::cerr << "Failed to create SSL object\n";
            ssl_ctx.reset();
            return 1;
        }
    }

    secure_vector    persisted_eph_pk;
    secure_vector    persisted_eph_sk;
    bool             have_persisted_eph = false;
    asio::io_context backoff_io;

    uint32_t reconnect_attempts = 0;

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

            OneShotTimer      backoff_timer(backoff_io);
            std::atomic<bool> backoff_done{false};
            backoff_timer.start(std::chrono::milliseconds(backoff),
                                [&](const std::error_code &)
                                { backoff_done = true; });

            while (!backoff_done)
            {
                backoff_io.poll_one();
            }
        }

        const int s =
            attempt_connection(config.server, config.port, persisted_eph_pk,
                               persisted_eph_sk, have_persisted_eph);
        if (s < 0)
        {
            ++reconnect_attempts;
            continue;
        }

        is_connected       = true;
        reconnect_attempts = 0;

        std::thread reader(reader_thread, s, ssl);
        std::thread writer(writer_thread, s, ssl);

        writer.join();
        reader.join();

        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (ssl)
            {
                if (SSL_is_init_finished(ssl))
                {
                    SSL_shutdown(ssl);
                }
                SSL_free(ssl);
                ssl = nullptr;
            }
        }

        if (close(s) != 0)
        {
            std::cerr << "[" << get_current_timestamp_ms()
                      << "] Socket close failed: " << strerror(errno) << "\n";
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
        if (ssl)
        {
            if (SSL_is_init_finished(ssl))
            {
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            ssl = nullptr;
        }
    }
    io.stop();
    if (io_thread.joinable())
        io_thread.join();

    ssl_ctx.reset(); // shared_ptr releases the context automatically

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
