#pragma once
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <openssl/ssl.h>

struct ClientState {
    int fd = -1;
    SSL* ssl = nullptr;

    ClientState() = default;
    ClientState(int f, SSL* s) : fd(f), ssl(s) {}
    
    ClientState(const ClientState&) = delete;
    ClientState& operator=(const ClientState&) = delete;
    
    ClientState(ClientState&& other) noexcept : fd(other.fd), ssl(other.ssl) {
        other.fd = -1;
        other.ssl = nullptr;
    }
    
    ClientState& operator=(ClientState&& other) noexcept {
        if (this != &other) {
            cleanup();
            fd = other.fd;
            ssl = other.ssl;
            other.fd = -1;
            other.ssl = nullptr;
        }
        return *this;
    }

    ~ClientState() {
        cleanup();
    }

private:
    void cleanup() noexcept {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }
};

inline bool accept_new_client(int listen_fd, std::vector<ClientState>& clients, SSL_CTX* ctx) {
    int c = accept(listen_fd, nullptr, nullptr);
    if (c < 0) return false;
    if (c >= FD_SETSIZE) {
        close(c);
        return true;
    }
    
    if (set_socket_nonblocking(c) != 0) {
        close(c);
        return true;
    }
    
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        close(c);
        return true;
    }
    SSL_set_fd(ssl, c);
    SSL_set_accept_state(ssl);
    
    clients.push_back({c, ssl});
    return true;
}

static void prune_invalid_clients(std::vector<ClientState>& clients) {
    clients.erase(std::remove_if(clients.begin(), clients.end(),
                                 [](const ClientState& cs) {
                                     if (cs.fd >= FD_SETSIZE) {
                                         // Destructor handles close & SSL_free
                                         return true;
                                     }
                                     return false;
                                 }),
                  clients.end());
}