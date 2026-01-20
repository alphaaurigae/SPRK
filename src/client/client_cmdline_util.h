#ifndef CLIENT_CMDLINE_H
#define CLIENT_CMDLINE_H

#include "shared_common_util.h"
#include "shared_net_username_util.h"

#include <cstdlib>
#include <iostream>
#include <span>

struct ConnectionConfig
{
    std::string server;
    int         port{};
    std::string username;
    std::string client_cert_path;
    std::string client_key_path;
};

inline ConnectionConfig parse_command_line_args(std::span<char *> args)
{
    if (args.size() < 5)
    {
        std::cout << "Usage: chat_client <server_ip> <server_port> <username> "
                     "<private_key_path> [--sessionid <id>] [--debug]\n\n"
                     "Runtime commands:\n"
                     "help                      show commands\n"
                     "q                         quit\n"
                     "list | list users         list connected users\n"
                     "pubk <username>           fetch user public key\n"
                     "<fp[,fp...]> <message>    send message to peer(s)\n";
        std::exit(1);
    }

    for (std::size_t i = 1; i < args.size(); ++i)
    {
        if (std::string_view(args[i]) == "--debug")
        {
            debug_mode = true;
        }
    }

    ConnectionConfig config;
    config.server   = args[1];
    config.username = trim(args[3]);

    try
    {
        config.port = std::stoi(args[2]);
    }
    catch (const std::exception &)
    {
        std::cout << "Invalid port number\n";
        std::exit(1);
    }

    if (!is_valid_username(config.username))
    {
        std::cout
            << "Invalid username. Use only alphanumeric, underscore, hyphen\n";
        std::exit(1);
    }

    return config;
}
#endif