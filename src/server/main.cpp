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

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <ranges>
#include <sys/socket.h>
#include <unistd.h>
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

    int port = std::stoi(argv[1]);

    const int listen_fd = make_listen_socket(port);
    if (listen_fd < 0)
        return 1;

    if (set_socket_nonblocking(listen_fd) < 0)
    {
        close(listen_fd);
        return 1;
    }

    // ──────────────────────────────
    // Initialize TLS context
    // ──────────────────────────────
    auto ctx = init_tls_server_context("sample/sample_test_cert/server.crt",
                                       "sample/sample_test_cert/server.key",
                                       "sample/sample_test_cert/ca.crt");
    if (!ctx)
    {
        std::cerr << "TLS server context initialization failed\n";
        return 1;
    }

    SSL *ssl_obj = SSL_new(ctx->native_handle());
    if (!ssl_obj)
    {
        std::cerr << "Failed to create SSL object\n";
        ctx.reset();
        return 1;
    }
    if (!ctx)
    {
        std::cerr << "TLS initialization failed - exiting\n";
        close(listen_fd);
        return 1;
    }

    std::vector<ClientState>                     clients;
    std::unordered_map<std::string, SessionData> sessions;
    std::unordered_map<int, std::string>         session_by_fd;

    std::cout << "Server listening on port " << port
              << " with post-quantum TLS\n";

    asio::io_context    io;
    RekeyTimeoutManager rtm(io);

    std::thread io_thread([&io] { io.run(); });

    while (true)
    {
        prune_invalid_clients(clients);

        fd_set rfds;
        int    maxfd = prepare_select(rfds, listen_fd, clients);

        timeval tv{0, 200000};
        int     r = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0)
        {
            perror("select");
            break;
        }
        else if (r == 0)
        {
            io.poll(); // Process Asio timers/events on timeout
        }

        if (FD_ISSET(listen_fd, &rfds))
        {
            accept_new_client(listen_fd, clients, ctx);
        }

        std::vector<int> to_remove;
        process_client_events(rfds, clients, sessions, session_by_fd,
                              to_remove);

        for (int fd : to_remove)
        {
            cleanup_disconnected_client(fd, clients, session_by_fd, sessions);
        }
    }

    // Cleanup
    clients.clear();
    if (ssl_obj)
    {
        if (SSL_is_init_finished(ssl_obj))
            SSL_shutdown(ssl_obj);
        SSL_free(ssl_obj);
        ssl_obj = nullptr;
    }

    io.stop();
    if (io_thread.joinable())
        io_thread.join();
    ctx.reset();
    close(listen_fd);
    return 0;
    return 0;
}
