#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "client_peer_manager.h"
#include "client_runtime.h"
#include "shared_common_crypto.h"
#include "shared_net_common_protocol.h"
#include "shared_net_key_util.h"
#include "shared_net_socket_util.h"
#include "shared_net_tls_frame_io.h"
#include "shared_net_username_util.h"

#include <asio/io_context.hpp>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <span>
#include <vector>

struct ServerStr
{
    std::string_view v{};
    explicit ServerStr(std::string_view s) noexcept : v(s) {}
};

struct PortInt
{
    int v{};
    explicit PortInt(int x) noexcept : v(x) {}
};

struct PersistedEphPk
{
    struct Proxy
    {
        secure_vector *p{};
        explicit Proxy(secure_vector &r) noexcept : p(&r) {}
        Proxy &operator=(const secure_vector &rhs) noexcept
        {
            *p = rhs;
            return *this;
        }
        operator secure_vector &() noexcept { return *p; }
    } v;
    explicit PersistedEphPk(secure_vector &ref) noexcept : v(ref) {}
};

struct PersistedEphSk
{
    struct Proxy
    {
        secure_vector *p{};
        explicit Proxy(secure_vector &r) noexcept : p(&r) {}
        Proxy &operator=(const secure_vector &rhs) noexcept
        {
            *p = rhs;
            return *this;
        }
        operator secure_vector &() noexcept { return *p; }
    } v;
    explicit PersistedEphSk(secure_vector &ref) noexcept : v(ref) {}
};

struct HavePersistedEph
{
    struct Proxy
    {
        bool *p{};
        explicit Proxy(bool &r) noexcept : p(&r) {}
        Proxy &operator=(bool rhs) noexcept
        {
            *p = rhs;
            return *this;
        }
        operator bool() const noexcept { return *p; }
    } v;
    explicit HavePersistedEph(bool &ref) noexcept : v(ref) {}
};

inline bool setup_session_id(std::span<char *> args)
{
    std::string_view session_flag = "--sessionid";
    std::string_view alt_flag     = "-sessionid";

    for (size_t i = 1; i < args.size() - 1; ++i)
    {
        std::string_view arg = args[i];
        if (arg == session_flag || arg == alt_flag)
        {
            peer_globals::session_id() = args[i + 1];
            if (!is_valid_session_id(peer_globals::session_id()))
            {
                std::cout << "Invalid peer_globals::session_id() format\n";
                return false;
            }
            std::cout << "Using provided peer_globals::session_id(): "
                      << peer_globals::session_id() << "\n";
            return true;
        }
    }

    peer_globals::session_id() = generate_session_id();
    std::cout << "Generated new peer_globals::session_id(): "
              << peer_globals::session_id() << "\n";
    return true;
}

inline void
attempt_connection_async(asio::io_context &io, ServerStr server, PortInt port,
                         PersistedEphPk            persisted_eph_pk,
                         PersistedEphSk            persisted_eph_sk,
                         HavePersistedEph          have_persisted_eph,
                         std::function<void(bool)> completion_handler)
{
    std::cout << "[" << get_current_timestamp_ms()
              << "] attempting connection to " << std::string(server.v) << ":"
              << port.v << "\n";

    if (!have_persisted_eph.v)
    {
        const auto [pk, sk]  = pqkem_keypair(KEM_ALG_NAME);
        persisted_eph_pk.v   = pk;
        persisted_eph_sk.v   = sk;
        have_persisted_eph.v = true;
    }

    peer_globals::my_eph_pk() = persisted_eph_pk.v;
    peer_globals::my_eph_sk() = persisted_eph_sk.v;

    async_connect_to_host_asio(
        io, std::string(server.v).c_str(), port.v,
        [completion_handler](std::shared_ptr<asio::ip::tcp::socket> sock,
                             std::error_code                        ec)
        {
            if (ec)
            {
                std::cout << "[" << get_current_timestamp_ms()
                          << "] connection failed: " << ec.message() << "\n";
                completion_handler(false);
                return;
            }
            std::cout << "[" << get_current_timestamp_ms()
                      << "] TCP connection established\n";
            auto stream = std::make_shared<ssl_socket>(
                std::move(*sock), *runtime_globals::ssl_ctx());

            std::cout << "[" << get_current_timestamp_ms()
                      << "] starting TLS handshake\n";

            stream->async_handshake(
                asio::ssl::stream_base::client,
                [stream, completion_handler](const std::error_code &ec)
                {
                    if (ec)
                    {
                        std::cerr << "[" << get_current_timestamp_ms()
                                  << "] TLS handshake failed: " << ec.message()
                                  << "\n";
                        completion_handler(false);
                        return;
                    }

                    std::cout << "[" << get_current_timestamp_ms()
                              << "] TLS handshake successful\n";

                    {
                        std::lock_guard<std::mutex> lk(
                            runtime_globals::ssl_io_mtx());
                        runtime_globals::ssl_stream() = stream;
                    }

                    std::vector<unsigned char> sig_data;
                    sig_data.reserve(peer_globals::my_eph_pk().size() +
                                     peer_globals::session_id().size());
                    sig_data.insert(sig_data.end(),
                                    peer_globals::my_eph_pk().begin(),
                                    peer_globals::my_eph_pk().end());
                    sig_data.insert(sig_data.end(),
                                    peer_globals::session_id().begin(),
                                    peer_globals::session_id().end());

                    const auto signature =
                        pqsig_sign(SIG_ALG_NAME,
                                   std::vector<unsigned char>(
                                       peer_globals::my_identity_sk().begin(),
                                       peer_globals::my_identity_sk().end()),
                                   sig_data);

                    const auto hello_frame = build_hello(
                        peer_globals::my_username(), ALGO_KEM_ALG_NAME,
                        std::vector<unsigned char>(
                            peer_globals::my_eph_pk().begin(),
                            peer_globals::my_eph_pk().end()),
                        ALGO_MLDSA87,
                        std::vector<unsigned char>(
                            peer_globals::my_identity_pk().begin(),
                            peer_globals::my_identity_pk().end()),
                        signature, std::vector<unsigned char>{},
                        peer_globals::session_id());

                    auto frame_ptr =
                        std::make_shared<std::vector<unsigned char>>(
                            hello_frame);

                    async_write_frame(
                        stream, frame_ptr,
                        [completion_handler,
                         frame_ptr](const std::error_code &ec, std::size_t)
                        {
                            if (ec)
                            {
                                std::cout << "[" << get_current_timestamp_ms()
                                          << "] failed to send hello: "
                                          << ec.message() << "\n";
                                completion_handler(false);
                                return;
                            }

                            runtime_globals::is_connected() = true;
                            asio_reader_loop();
                            completion_handler(true);
                        });
                });
        });
}
#endif
