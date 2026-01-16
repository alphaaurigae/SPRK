#pragma once

#include "client_runtime.h"
#include "common_crypto.h"
#include "net_tls_frame_io.h"
#include "net_common_protocol.h"
#include "common_util.h"
#include "net_key_util.h"
#include "peer_manager.h"       // check_rate_limit, peers, PeerInfo
#include "session.h"            // session_id, my_eph_pk, my_username
#include "client_message_util.h" // validate_username, handle_hello, etc.
#include "client_crypto_util.h"  // ssl_ctx, rotate_ephemeral_if_needed


#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <iostream>
#include <span>
#include <openssl/ssl.h>


inline void reader_thread(int sock, SSL* ssl)
{
    while (should_reconnect && is_connected)
    {
        std::vector<unsigned char> frame;
        if (!tls_peek_and_read_frame(ssl, frame))
        {
            is_connected = false;
            break;
        }

        try
        {
            std::span<const unsigned char> span(frame);
            const Parsed p = parse_payload(span.subspan(4).data(), span.size() - 4);

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
                    std::cout << "unknown message type: " << static_cast<int>(p.type) << "\n";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "parse error: " << e.what() << "\n";
        }
    }
}

// "I am the fire to your ice.", "I do what I must to return home."
inline void writer_thread(int sock, SSL* ssl)
{
    std::string line;
    bool eof_notified = false;

    while (is_connected.load(std::memory_order_acquire))
    {
        if (!std::getline(std::cin, line))
        {
            if (std::cin.eof())
            {
                if (!eof_notified)
                {
                    std::cerr << "[" << get_current_timestamp_ms() << "] writer_thread: stdin EOF; entering poll mode\n";
                    eof_notified = true;
                }
                std::cin.clear();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            std::cerr << "[" << get_current_timestamp_ms() << "] writer_thread: std::getline failed\n";
            is_connected.store(false, std::memory_order_release);
            break;
        }

        eof_notified = false;

        if (!is_connected.load(std::memory_order_acquire)) break;

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

                std::cerr << "[" << get_current_timestamp_ms() << "] send failed (err=" << err << ") - peer/server likely dropped connection\n";

                is_connected.store(false, std::memory_order_release);
                break;
            }
        }
    }
// Do not close the socket here. Let main/connection loop perform orderly shutdown.
}