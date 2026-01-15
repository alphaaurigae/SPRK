#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <openssl/ssl.h>
#include "common_util.h"
#include "peer_manager.h"
#include "net_message_util.h"
#include "net_tls_frame_io.h"
#include "client_runtime.h"

// Strong type to prevent swapping msg and recipient_fp
struct RecipientFP
{
    std::string value;
    explicit RecipientFP(std::string fp) : value(std::move(fp)) {}
    [[nodiscard]] const std::string &str() const & { return value; }
    [[nodiscard]] std::string      &&str()      &&{ return std::move(value); }
};

// Recipient parsing
inline std::vector<std::string> parse_recipient_list(const std::string &input)
{
    std::vector<std::string> recipients;
    size_t                   start = 0;
    while (true)
    {
        const auto comma = input.find(',', start);
        if (comma == std::string::npos)
        {
            const std::string r = trim(input.substr(start));
            if (!r.empty())
                recipients.push_back(r);
            break;
        }
        const std::string r = trim(input.substr(start, comma - start));
        if (!r.empty())
            recipients.push_back(r);
        start = comma + 1;
    }
    return recipients;
}

// Returns true if the line was a command that was fully handled
inline bool handle_client_command(const std::string &line, 
                                  [[maybe_unused]] int sock, SSL *ssl)
{
    if (line == "help")
    {
        std::cout << "q                         quit\n"
                     "list | list users         list connected users\n"
                     "pubk <username>           fetch user public key\n"
                     "<fp[,fp...]> <message>    send message to peer(s)\n";
        return true;
    }

    if (line == "q")
    {
        should_reconnect = false;
        is_connected     = false;
        return true;
    }

    if (line == "list" || line == "list users" || line == "list user")
    {
        const std::vector<unsigned char> p{PROTO_VERSION, MSG_LIST_REQUEST};
        const auto                       f = build_frame(p);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (tls_full_send(ssl, f.data(), f.size()) <= 0)
            {
                is_connected = false;
            }
        }
        {
        }
        return true;
    }

    if (line.starts_with("pubk "))
    {
        const std::string who = trim(line.substr(5));
        if (!is_valid_username(who))
        {
            std::cout << "invalid username\n";
            return true;
        }
        const auto req = build_pubkey_request(who);
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (tls_full_send(ssl, req.data(), req.size()) <= 0)
            {
                is_connected = false;
            }
        }
        return true;
    }

    return false;
}