#include "common_crypto.h"
#include "net_common_protocol.h"
#include "common_util.h"
#include "net_tls_context.h"
#include "net_socket_util.h"
#include "net_tls_frame_io.h"
#include "net_username_util.h"
#include "net_rekey_util.h"
#include "net_message_util.h"
#include "net_key_util.h"

#include "server/client_state.h"
#include "server/session.h"
#include "server/handlers.h"
#include "server/connection.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <ranges>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h> 

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "Usage: chat_server <port>\n";
        return 1;
    }

    int port = std::stoi(argv[1]);

    const int listen_fd = make_listen_socket(port);
    if (listen_fd < 0) return 1;

    if (set_socket_nonblocking(listen_fd) < 0) {
        close(listen_fd);
        return 1;
    }

    // ──────────────────────────────
    // Initialize TLS context
    // ──────────────────────────────
    SSL_CTX* ctx = init_tls_server_context(
        "sample/sample_test_cert/server.crt",
        "sample/sample_test_cert/server.key",
        "sample/sample_test_cert/ca.crt");
    
    if (!ctx) {
        std::cerr << "TLS initialization failed - exiting\n";
        close(listen_fd);
        return 1;
    }

    std::vector<ClientState> clients;
    std::unordered_map<std::string, SessionData> sessions;
    std::unordered_map<int, std::string> session_by_fd;

    std::cout << "Server listening on port " << port << " with post-quantum TLS\n";

    while (true) {
        prune_invalid_clients(clients);

        fd_set rfds;
        int maxfd = prepare_select(rfds, listen_fd, clients);

        timeval tv{0, 200000};
        int r = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            accept_new_client(listen_fd, clients, ctx);
        }

        std::vector<int> to_remove;
        process_client_events(rfds, clients, sessions, session_by_fd, to_remove);

        for (int fd : to_remove) {
            cleanup_disconnected_client(fd, clients, session_by_fd, sessions);
        }
    }

    // Cleanup
    clients.clear();
    SSL_CTX_free(ctx);

    close(listen_fd);
    return 0;
}

