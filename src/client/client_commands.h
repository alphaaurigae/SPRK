#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_tls_frame_io.h"
#include "shared_net_username_util.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

struct RecipientFP
{
    std::string value;
    explicit RecipientFP(std::string fp) noexcept : value(std::move(fp)) {}
    [[nodiscard]] const std::string &str() const & { return value; }
    [[nodiscard]] std::string      &&str()      &&{ return std::move(value); }
};

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wglobal-constructors"
#endif

extern std::mutex                  ssl_io_mtx;
extern std::shared_ptr<ssl_socket> ssl_stream;
extern std::atomic_bool            is_connected;
extern std::atomic_bool            should_reconnect;

#ifdef __clang__
#pragma clang diagnostic pop
#endif

void handle_disconnect(const std::string &username, const std::string &fp_hex);

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

inline bool handle_client_command(const std::string &line)
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

        auto frame_ptr = std::make_shared<std::vector<unsigned char>>(f);

        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (!ssl_stream)
            {
                is_connected = false;
                handle_disconnect("", "");
                return true;
            }
            async_write_frame(
                ssl_stream, frame_ptr,
                [frame_ptr](const std::error_code &ec, std::size_t)
                {
                    if (ec)
                    {
                        is_connected = false;
                        handle_disconnect("", "");
                    }
                });
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
        auto frame_ptr = std::make_shared<std::vector<unsigned char>>(req);

        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            if (!ssl_stream)
            {
                is_connected = false;
                handle_disconnect(who, "");
                return true;
            }
            async_write_frame(
                ssl_stream, frame_ptr,
                [frame_ptr, who](const std::error_code &ec, std::size_t)
                {
                    if (ec)
                    {
                        is_connected = false;
                        handle_disconnect(who, "");
                    }
                });
        }
        return true;
    }
    return false;
}

#endif
