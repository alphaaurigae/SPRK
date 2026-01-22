#ifndef CLIENT_READER_WRITER_H
#define CLIENT_READER_WRITER_H

#include "client_commands.h"
#include "client_message_util.h"
#include "client_peer_disconnect.h"

#include "shared_common_util.h"
#include "shared_net_common_protocol.h"
#include "shared_net_rekey_util.h"
#include "shared_net_tls_frame_io.h"

#include <atomic>

#include <iostream>
#include <mutex>

#include <string>
#include <thread>

void                     handle_hello(const Parsed &p);
void                     handle_chat(const Parsed &p);
void                     process_list_response(const Parsed &p);
void                     process_pubkey_response(const Parsed &p);
std::vector<std::string> parse_recipient_list(const std::string &input);
std::vector<std::string>
resolve_fingerprint_recipients(const std::vector<std::string> &recipients);
std::vector<std::string>
     get_ready_recipients(const std::vector<std::string> &resolved);
bool send_message_to_peer(const std::string &msg,
                          const RecipientFP &recipient_fp);

extern std::shared_ptr<ssl_socket> ssl_stream;

inline void asio_reader_loop()
{
    auto frame_buf = std::make_shared<std::vector<unsigned char>>();

    auto read_next = std::make_shared<std::function<void()>>();
    *read_next     = [frame_buf, read_next]()
    {
        if (!is_connected.load())
        {
            std::cerr << "[DEBUG] asio_reader_loop: not connected, returning\n";
            return;
        }

        std::shared_ptr<ssl_socket> s;
        {
            std::lock_guard<std::mutex> lk(ssl_io_mtx);
            s = ssl_stream;
        }

        if (!s)
        {
            std::cerr << "[DEBUG] asio_reader_loop: ssl_stream null\n";
            is_connected = false;
            handle_disconnect("(unknown)", "");
            return;
        }

        std::cerr << "[DEBUG] asio_reader_loop: posting async_read_frame\n";
        async_read_frame(
            s, frame_buf,
            [frame_buf, read_next](const std::error_code &ec, std::size_t)
            {
                if (ec)
                {
                    is_connected = false;
                    handle_disconnect("(unknown)", "");
                    return;
                }

                try
                {
                    std::span<const unsigned char> span(*frame_buf);
                    Parsed                         p =
                        parse_payload(span.subspan(4).data(), span.size() - 4);
                    std::cerr
                        << "[DEBUG] asio_reader_loop: received message type="
                        << int(p.type) << "\n";

                    switch (p.type)
                    {
                    case MSG_HELLO:
                        std::cerr << "[DEBUG] handling MSG_HELLO from "
                                  << p.username << "\n";
                        handle_hello(p);
                        break;
                    case MSG_CHAT:
                        std::cerr << "[DEBUG] handling MSG_CHAT from " << p.from
                                  << "\n";
                        handle_chat(p);
                        break;
                    case MSG_LIST_RESPONSE:
                        std::cerr << "[DEBUG] handling MSG_LIST_RESPONSE\n";
                        process_list_response(p);
                        break;
                    case MSG_PUBKEY_RESPONSE:
                        std::cerr << "[DEBUG] handling MSG_PUBKEY_RESPONSE\n";
                        process_pubkey_response(p);
                        break;
                    default:
                        std::cerr << "[DEBUG] unknown message type "
                                  << int(p.type) << "\n";
                        break;
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[ERROR] asio_reader_loop: parse exception: "
                              << e.what() << "\n";
                }
                catch (...)
                {
                    std::cerr << "[ERROR] asio_reader_loop: unknown parse "
                                 "exception\n";
                }

                (*read_next)();
            });
    };

    std::cerr << "[DEBUG] asio_reader_loop: starting read loop\n";
    (*read_next)();
}

// "I am the fire to your ice.", "I do what I must to return home."
inline void writer_thread()
{
    std::string line;

    while (is_connected.load(std::memory_order_acquire))
    {

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

        if (handle_client_command(line))
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

        std::cerr << "[DEBUG] writer_thread: ready recipients count="
                  << ready.size() << "\n";

        if (ready.empty())
        {
            std::cout << "peer not ready\n";
            continue;
        }

        for (const auto &r : ready)
        {
            std::cerr << "[DEBUG] writer_thread: sending to " << r << "\n";
            if (!send_message_to_peer(msg, RecipientFP{r}))
            {
                std::cerr << "[DEBUG] writer_thread: failed to send to " << r
                          << "\n";
                break;
            }
        }
    }
}
#endif