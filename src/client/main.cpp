#include "net_tls_context.h"
#include "common_crypto.h"
#include "net_common_protocol.h"
#include "common_util.h"

#include "net_socket_util.h"
#include "net_tls_frame_io.h"
#include "net_username_util.h"
#include "net_rekey_util.h"
#include "net_message_util.h"
#include "net_key_util.h"
#include "peer_manager.h"
#include "reader_writer.h"
#include "commands.h"
#include "session.h"
#include "client_cmdline_util.h"   // parse_command_line_args
#include "client_crypto_util.h"    // ssl_ctx, ssl, init_oqs_provider, rotate_ephemeral_if_needed
#include "client_message_util.h"   // handle_hello, handle_chat, process_list_response, process_pubkey_response, etc.
#include "reader_writer.h"         // reader_thread, writer_thread
#include "client_runtime.h"


#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h> 
#include <csignal>




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

    if (args.size() < 6)
    {
        std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                     "<identity_sk.pem> <client_cert.crt> "
                     "[--sessionid <id>] [--debug]\n";
        return 1;
    }

    crypto_init();

    // Initialize TLS context (this also loads OQS providers)
    std::string cert_path = std::string("sample/sample_test_cert/") + my_username + ".crt";
    std::string key_path  = std::string("sample/sample_test_cert/") + my_username + "_tls.key";
    
    ssl_ctx = init_tls_client_context(cert_path, key_path, "sample/sample_test_cert/ca.crt");
    if (!ssl_ctx) {
        std::cerr << "TLS context initialization failed\n";
        return 1;
    }

    // Load OQS provider for protocol-level crypto (separate from TLS)
    if (!init_oqs_provider()) {
        std::cerr << "Cannot continue without OQS provider for protocol crypto\n";
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
        return 1;
    }

    secure_vector persisted_eph_pk;
    secure_vector persisted_eph_sk;
    bool          have_persisted_eph = false;

    uint32_t reconnect_attempts = 0;

    while (should_reconnect && reconnect_attempts < MAX_RECONNECT_ATTEMPTS)
    {
        if (reconnect_attempts > 0)
        {
            const uint64_t backoff = std::min<uint64_t>(
                INITIAL_BACKOFF_MS * (1ULL << (reconnect_attempts - 1)),
                MAX_BACKOFF_MS);
            std::cout << "[" << get_current_timestamp_ms() << "] reconnecting in " << backoff
                      << "ms (attempt " << reconnect_attempts + 1 << ")\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }

        const int s = attempt_connection(config.server, config.port, persisted_eph_pk,
                                         persisted_eph_sk, have_persisted_eph);
        if (s < 0) {
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
            std::cerr << "[" << get_current_timestamp_ms() << "] Socket close failed: " << strerror(errno) << "\n";
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
        std::cout << "[" << get_current_timestamp_ms() << "] max reconnection attempts reached\n";
    }

    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }

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
