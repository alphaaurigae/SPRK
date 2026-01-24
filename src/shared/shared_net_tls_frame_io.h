#ifndef SHARED_NET_TLS_FRAME_IO_H
#define SHARED_NET_TLS_FRAME_IO_H

#include "shared_common_util.h"

#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <system_error>
#include <vector>

using ::read_u32_be;

using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>;

template <typename Handler>
void async_read_frame(std::shared_ptr<ssl_socket> stream,
                      std::shared_ptr<std::vector<unsigned char>> frame_buf,
                      Handler &&handler) {
  auto len_buf = std::make_shared<std::array<unsigned char, 4>>();

  asio::async_read(
      *stream, asio::buffer(*len_buf),
      [stream, frame_buf, len_buf, handler = std::forward<Handler>(handler)](
          const std::error_code &ec, std::size_t) mutable {
        if (ec) {
          handler(ec, 0);
          return;
        }

        const uint32_t payload_len = read_u32_be(len_buf->data());

        if (payload_len > 1048576) {
          handler(std::make_error_code(std::errc::message_size), 0);
          return;
        }

        frame_buf->resize(4 + payload_len);
        std::copy(len_buf->begin(), len_buf->end(), frame_buf->begin());

        asio::async_read(*stream,
                         asio::buffer(frame_buf->data() + 4, payload_len),
                         [handler = std::move(handler), payload_len](
                             const std::error_code &ec, std::size_t) mutable {
                           handler(ec, ec ? 0 : payload_len);
                         });
      });
}

template <typename Handler>
void async_write_frame(std::shared_ptr<ssl_socket> stream,
                       std::shared_ptr<const std::vector<unsigned char>> frame,
                       Handler &&handler) {
  asio::async_write(*stream, asio::buffer(*frame),
                    [handler = std::forward<Handler>(handler),
                     frame](const std::error_code &ec,
                            std::size_t bytes) mutable { handler(ec, bytes); });
}

inline void chain_read_frames(
    std::shared_ptr<ssl_socket> stream,
    std::function<void(const std::error_code &, std::vector<unsigned char> &)>
        frame_handler) {
  auto frame_buf = std::make_shared<std::vector<unsigned char>>();

  async_read_frame(stream, frame_buf,
                   [stream, frame_buf, frame_handler](const std::error_code &ec,
                                                      std::size_t) {
                     if (ec) {
                       frame_handler(ec, *frame_buf);
                       return;
                     }

                     frame_handler(ec, *frame_buf);
                     chain_read_frames(stream, frame_handler);
                   });
}

inline std::error_code
sync_write_frame(ssl_socket &stream, const std::vector<unsigned char> &frame) {
  std::error_code ec;
  asio::write(stream, asio::buffer(frame), ec);
  return ec;
}

inline std::error_code sync_read_frame(ssl_socket &stream,
                                       std::vector<unsigned char> &frame) {
  std::array<unsigned char, 4> len_buf;
  std::error_code ec;

  asio::read(stream, asio::buffer(len_buf), ec);
  if (ec)
    return ec;

  const uint32_t payload_len = read_u32_be(len_buf.data());
  if (payload_len > 1048576)
    return std::make_error_code(std::errc::message_size);

  frame.resize(4 + payload_len);
  std::copy(len_buf.begin(), len_buf.end(), frame.begin());

  asio::read(stream, asio::buffer(frame.data() + 4, payload_len), ec);
  return ec;
}

inline bool sync_peek_and_read_frame(ssl_socket &stream,
                                     std::vector<unsigned char> &out_frame) {
  std::error_code ec = sync_read_frame(stream, out_frame);
  return !ec;
}

inline bool sync_write_full_frame(ssl_socket &stream,
                                  const std::vector<unsigned char> &frame) {
  std::error_code ec = sync_write_frame(stream, frame);
  return !ec;
}

#endif