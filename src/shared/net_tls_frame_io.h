#ifndef NET_TLS_FRAME_IO_H
#define NET_TLS_FRAME_IO_H

#include "common_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <cstdint>

inline ssize_t tls_full_recv(SSL* ssl, void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t got = SSL_read(ssl, static_cast<char*>(buf) + total, len - total);
        if (got <= 0) {
            int err = SSL_get_error(ssl, got);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return got;
        }
        total += got;
    }
    return total;
}

inline ssize_t tls_full_send(SSL* ssl, const void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t got = SSL_write(ssl, static_cast<const char*>(buf) + total, len - total);
        if (got <= 0) return got;
        total += got;
    }
    return total;
}

inline bool tls_peek_and_read_frame(SSL* ssl, std::vector<unsigned char>& out_frame) {
    unsigned char len_buf[4];
    
    int peek_result = SSL_peek(ssl, len_buf, 4);
    if (peek_result <= 0) {
        int err = SSL_get_error(ssl, peek_result);
        return (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
    }
    
    if (peek_result < 4) return false;
    
    uint32_t payload_len = read_u32_be(len_buf);
    if (payload_len > 1048576) return false;
    
    out_frame.resize(4 + payload_len);
    ssize_t got = tls_full_recv(ssl, out_frame.data(), out_frame.size());
    
    return got == static_cast<ssize_t>(out_frame.size());
}

inline bool tls_read_full_frame(SSL* ssl, std::vector<unsigned char>& out_frame) {
    return tls_peek_and_read_frame(ssl, out_frame);
}

#endif