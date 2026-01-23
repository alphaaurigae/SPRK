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

#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
static constexpr uint64_t INITIAL_BACKOFF_MS     = 1000;
static constexpr uint64_t MAX_BACKOFF_MS         = 60000;

static void close_ssl_stream_if_any()
{
    const std::lock_guard<std::mutex> lk(ssl_io_mtx);
    if (ssl_stream)
    {
        std::error_code ec;
        ssl_stream->lowest_layer().close(ec);
        ssl_stream.reset();
    }
}

static void reset_peers_state()
{
    const std::lock_guard<std::mutex> lk(peers_mtx);
    for (auto &kv : peers)
    {
        kv.second.ready      = false;
        kv.second.sent_hello = false;
        kv.second.sk.key.clear();
    }
}

template <typename Work>
static std::thread start_io_thread(asio::io_context &io, Work work)
{
    return std::thread(
        [&io, work = std::move(work)]
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
}

static bool wait_backoff(uint32_t reconnect_attempts)
{
    if (reconnect_attempts == 0)
        return false;

    const uint64_t backoff = std::min<uint64_t>(
        INITIAL_BACKOFF_MS * (1ULL << (reconnect_attempts - 1)),
        MAX_BACKOFF_MS);

    std::cout << "[" << get_current_timestamp_ms() << "] reconnecting in "
              << backoff << "ms (attempt " << reconnect_attempts + 1 << ")\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
    return true;
}

static bool attempt_connection(asio::io_context       &io,
                               const ConnectionConfig &config,
                               secure_vector          &persisted_eph_pk,
                               secure_vector          &persisted_eph_sk,
                               bool                    have_persisted_eph)
{
    std::atomic<bool>       connection_complete{false};
    std::mutex              mtx;
    std::condition_variable cv;

    attempt_connection_async(io, ServerStr{config.server}, PortInt{config.port},
                             persisted_eph_pk, persisted_eph_sk,
                             have_persisted_eph,
                             [&connection_complete, &cv](bool success)
                             {
                                 if (success)
                                     is_connected = true;
                                 connection_complete = true;
                                 cv.notify_one();
                             });

    std::unique_lock<std::mutex> ul(mtx);
    cv.wait_for(ul, std::chrono::milliseconds(100),
                [&connection_complete] { return connection_complete.load(); });

    return is_connected;
}

static void handle_post_connection()
{
    std::thread(writer_thread).join();
    close_ssl_stream_if_any();
    reset_peers_state();
}

static void run_reconnect_loop(asio::io_context       &io,
                               const ConnectionConfig &config,
                               secure_vector          &persisted_eph_pk,
                               secure_vector          &persisted_eph_sk,
                               bool                    have_persisted_eph)
{
    uint32_t reconnect_attempts = 0;

    while (should_reconnect && reconnect_attempts < MAX_RECONNECT_ATTEMPTS)
    {
        wait_backoff(reconnect_attempts);

        if (!attempt_connection(io, config, persisted_eph_pk, persisted_eph_sk,
                                have_persisted_eph))
        {
            ++reconnect_attempts;
            continue;
        }

        reconnect_attempts = 0;
        handle_post_connection();
    }

    if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS)
    {
        std::cout << "[" << get_current_timestamp_ms()
                  << "] max reconnection attempts reached\n";
    }
}

int main(int argc, char **argv) noexcept
try
{
    const std::span<char *> args(argv, static_cast<std::size_t>(argc));
    const auto              config = parse_command_line_args(args);
    my_username                    = config.username;

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

    auto io_work = asio::require(io.get_executor(),
                                 asio::execution::outstanding_work.tracked);

    std::thread io_thread = start_io_thread(io, std::move(io_work));

    run_reconnect_loop(io, config, persisted_eph_pk, persisted_eph_sk,
                       have_persisted_eph);

    close_ssl_stream_if_any();

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
