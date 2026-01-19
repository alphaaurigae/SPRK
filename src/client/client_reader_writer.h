#ifndef CLIENT_READER_WRITER_H
#define CLIENT_READER_WRITER_H

#include "client_crypto_util.h"
#include "client_message_util.h"
#include "client_peer_disconnect.h"
#include "client_peer_manager.h"
#include "client_runtime.h"
#include "client_session.h"
#include "shared_common_crypto.h"
#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_key_util.h"
#include "shared_net_tls_frame_io.h"

#include <atomic>
#include <iostream>
#include <mutex>
#include <openssl/ssl.h>
#include <poll.h>
#include <span>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

inline void reader_thread(int sock, SSL *ssl)
{
    while (should_reconnect && is_connected)
    {
        std::vector<unsigned char> frame;
        if (!tls_peek_and_read_frame(ssl, frame))
        {
            is_connected = false;
            handle_disconnect("(unknown)", ""); // reader thread TLS read failed
            break;
        }

        try
        {
            std::span<const unsigned char> span(frame);
            const Parsed                   p =
                parse_payload(span.subspan(4).data(), span.size() - 4);

            switch (p.type)
            {
            case MSG_HELLO:
                handle_hello(p, sock);
                break;
            case MSG_CHAT:
                handle_chat(p);
                break;
            case MSG_LIST_RESPONSE:
                process_list_response(p);
                break;
            case MSG_PUBKEY_RESPONSE:
                process_pubkey_response(p);
                break;
            default:
                std::cout << "unknown message type: "
                          << static_cast<int>(p.type) << "\n";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "parse error: " << e.what() << "\n";
        }
    }
}

// "I am the fire to your ice.", "I do what I must to return home."
inline void writer_thread(int sock, SSL *ssl)
{
    std::string line;

    while (is_connected.load(std::memory_order_acquire))
    {
        // Non-blocking poll on stdin with yield to allow reader output
        struct pollfd pfd;
        pfd.fd     = STDIN_FILENO;
        pfd.events = POLLIN;

        const int poll_result = poll(&pfd, 1, 50); // 50ms timeout (shorter)

        if (poll_result < 0)
        {
            if (errno == EINTR)
                continue;
            std::cerr << "[" << get_current_timestamp_ms()
                      << "] poll error: " << strerror(errno) << "\n";
            break;
        }

        if (poll_result == 0)
        {
            // No input available, yield to allow reader thread to display
            // messages
            std::this_thread::yield();
            continue;
        }

        // Check if POLLIN event is actually set (not just timeout/error)
        if (!(pfd.revents & POLLIN))
        {
            continue;
        }

        // Input available, read it
        if (!std::getline(std::cin, line))

        {
            if (std::cin.eof())
            {
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] stdin closed\n";

                std::cin.clear();
                is_connected.store(false, std::memory_order_release);
                break;
            }

            if (std::cin.fail())
            {
                std::cerr << "[" << get_current_timestamp_ms()
                          << "] getline failed\n";
                std::cin.clear();
                continue;
            }

            is_connected.store(false, std::memory_order_release);
            break;
        }

        if (!is_connected.load(std::memory_order_acquire))
            break;

        if (handle_client_command(line, sock, ssl))
            continue;

        const auto pos = line.find(' ');
        if (pos == std::string::npos)
        {
            std::cout << "usage: <recipient> <message>\n";
            continue;
        }

        const std::string to  = trim(line.substr(0, pos));
        const std::string msg = line.substr(pos + 1);

        if (msg.empty() || msg.size() > 65535)
        {
            std::cout << "invalid message size\n";
            continue;
        }

        const auto recipients = parse_recipient_list(to);
        const auto resolved   = resolve_fingerprint_recipients(recipients);
        const auto ready      = get_ready_recipients(resolved);

        if (ready.empty())
        {
            std::cout << "peer not ready\n";
            continue;
        }

        for (const auto &r : ready)
        {
            if (!send_message_to_peer(sock, msg, RecipientFP{r}, ssl))
            {
                int err = SSL_get_error(ssl, 0);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                    continue;

                std::cerr << "[" << get_current_timestamp_ms()
                          << "] send failed (err=" << err
                          << ") - peer/server likely dropped connection\n";

                is_connected.store(false, std::memory_order_release);
                break;
            }
        }
    }
}
#endif