#ifndef SHARED_NET_COMMON_PROTOCOL_H
#define SHARED_NET_COMMON_PROTOCOL_H

#include <Poco/Buffer.h>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

constexpr uint8_t PROTO_VERSION = 1;
constexpr size_t  MAX_USERNAME  = 64;

constexpr uint8_t ALGO_NONE       = 0;
constexpr uint8_t ALGO_KYBER512   = 1;
constexpr uint8_t ALGO_KYBER768   = 2;
constexpr uint8_t ALGO_KYBER1024  = 3;
constexpr uint8_t ALGO_DILITHIUM2 = 11;
constexpr uint8_t ALGO_DILITHIUM3 = 12;
constexpr uint8_t ALGO_MLDSA87    = 13;

constexpr size_t      MAX_PQC_PUBKEY_LEN = 8192;
constexpr size_t      MAX_PQC_SIG_LEN    = 8192;
inline constexpr char KEM_ALG_NAME[]     = "Kyber512";
inline constexpr char SIG_ALG_NAME[]     = "ML-DSA-87";

constexpr uint8_t ALGO_KEM_ALG_NAME = ALGO_KYBER512;

constexpr size_t NONCE_LEN       = 12;
constexpr size_t MAX_CIPHER      = 65535;
constexpr size_t MAX_USERS_LIST  = 255;
constexpr size_t SESSION_ID_LEN  = 60;
constexpr size_t FINGERPRINT_LEN = 32;

enum MsgType : uint8_t
{
    MSG_HELLO           = 1,
    MSG_CHAT            = 2,
    MSG_LIST_REQUEST    = 3,
    MSG_LIST_RESPONSE   = 4,
    MSG_PUBKEY_REQUEST  = 5,
    MSG_PUBKEY_RESPONSE = 6
};

inline void ensure_range(size_t idx, size_t len, size_t total,
                         const char *field)
{
    if (idx + len > total)
        throw std::runtime_error(std::string("truncated ") + field);
}

namespace proto
{

struct Parsed
{
    uint8_t                    version = PROTO_VERSION;
    uint8_t                    type    = 0;
    std::string                username;
    uint8_t                    eph_alg = 0;
    std::vector<unsigned char> eph_pk;
    uint8_t                    id_alg = 0;
    std::vector<unsigned char> identity_pk;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> encaps;
    std::string                session_id;
    std::string                from;
    std::string                to;
    uint32_t                   seq = 0;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
    std::vector<std::string>   users;
};

[[nodiscard]] inline std::vector<unsigned char>
build_frame(std::span<const unsigned char> payload);

[[nodiscard]] inline std::vector<unsigned char>
build_hello(const std::string &username, uint8_t eph_alg,
            const std::vector<unsigned char> &eph_pk, uint8_t id_alg,
            const std::vector<unsigned char> &identity_pk,
            const std::vector<unsigned char> &signature,
            const std::vector<unsigned char> &encaps,
            const std::string                &session_id);

[[nodiscard]] inline std::vector<unsigned char>
build_chat(const std::string &to, const std::string &from,
           const std::array<unsigned char, 32> &from_fingerprint, uint32_t seq,
           const std::vector<unsigned char> &nonce,
           const std::vector<unsigned char> &ciphertext);

[[nodiscard]] inline std::vector<unsigned char>
build_list_response(const std::vector<std::string> &users);

[[nodiscard]] inline std::vector<unsigned char>
build_pubkey_request(const std::string &username);

[[nodiscard]] inline std::vector<unsigned char>
build_pubkey_response(const std::string                &username,
                      const std::vector<unsigned char> &pubkey);

} // namespace proto

using Parsed = proto::Parsed;
using proto::build_chat;
using proto::build_frame;
using proto::build_hello;
using proto::build_list_response;
using proto::build_pubkey_request;
using proto::build_pubkey_response;

namespace proto_detail
{

// low-level BE conversions
[[nodiscard]] constexpr inline uint16_t
load_be16(const unsigned char *p) noexcept
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

[[nodiscard]] constexpr inline uint32_t
load_be32(const unsigned char *p) noexcept
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

constexpr inline void store_be16(unsigned char *p, uint16_t v) noexcept
{
    p[0] = static_cast<unsigned char>(v >> 8);
    p[1] = static_cast<unsigned char>(v);
}

constexpr inline void store_be32(unsigned char *p, uint32_t v) noexcept
{
    p[0] = static_cast<unsigned char>(v >> 24);
    p[1] = static_cast<unsigned char>(v >> 16);
    p[2] = static_cast<unsigned char>(v >> 8);
    p[3] = static_cast<unsigned char>(v);
}

// high-level reads
[[nodiscard]] inline uint16_t
read_u16_be(std::span<const unsigned char> payload, size_t idx) noexcept
{
    return load_be16(payload.data() + idx);
}

[[nodiscard]] inline uint32_t
read_u32_be(std::span<const unsigned char> payload, size_t idx) noexcept
{
    return load_be32(payload.data() + idx);
}

// other proto_detail helpers
[[nodiscard]] inline ptrdiff_t to_offset(size_t value) noexcept
{
    return static_cast<ptrdiff_t>(value);
}

[[nodiscard]] inline std::string_view
make_string_view(const unsigned char *data, size_t len) noexcept
{
    return {reinterpret_cast<const char *>(data), len};
}

[[nodiscard]] inline std::vector<unsigned char>
extract_bytes(std::span<const unsigned char> payload, size_t start, size_t len)
{
    return {payload.begin() + to_offset(start),
            payload.begin() + to_offset(start + len)};
}

// string / bytes readers
[[nodiscard]] inline std::string
read_string_u8(std::span<const unsigned char> payload, size_t &idx,
               size_t max_len, const char *field_name)
{
    ensure_range(idx, 1, payload.size(), "length field");
    const uint8_t len = payload[idx++];
    if (len == 0 || len > max_len)
        throw std::runtime_error(std::string("bad ") + field_name + " length");
    ensure_range(idx, len, payload.size(), field_name);
    std::string result{make_string_view(payload.data() + idx, len)};
    idx += len;
    return result;
}

[[nodiscard]] inline std::vector<unsigned char>
read_bytes_u16(std::span<const unsigned char> payload, size_t &idx,
               size_t max_len, const char *field_name, bool allow_empty)
{
    ensure_range(idx, 2, payload.size(), "length field");
    const uint16_t len = read_u16_be(payload, idx);
    idx += 2;
    if (len > max_len)
        throw std::runtime_error(std::string("bad ") + field_name + " length");
    if (len == 0 && !allow_empty)
        throw std::runtime_error(std::string("empty ") + field_name);
    ensure_range(idx, len, payload.size(), field_name);
    auto result = extract_bytes(payload, idx, len);
    idx += len;
    return result;
}

inline proto::Parsed parse_hello(std::span<const unsigned char> payload,
                                 size_t                         idx)
{
    proto::Parsed out;
    out.version  = PROTO_VERSION;
    out.type     = MSG_HELLO;
    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");
    ensure_range(idx, 1, payload.size(), "eph_alg");
    out.eph_alg = payload[idx++];
    out.eph_pk =
        read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "eph_pk", true);
    ensure_range(idx, 1, payload.size(), "id_alg");
    out.id_alg = payload[idx++];
    out.identity_pk =
        read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "identity_pk", true);
    out.signature =
        read_bytes_u16(payload, idx, MAX_PQC_SIG_LEN, "signature", true);
    out.encaps = read_bytes_u16(payload, idx, 65535, "encaps", true);
    ensure_range(idx, SESSION_ID_LEN, payload.size(), "session_id");
    out.session_id =
        std::string{make_string_view(payload.data() + idx, SESSION_ID_LEN)};
    idx += SESSION_ID_LEN;
    if (out.session_id.size() != SESSION_ID_LEN)
        throw std::runtime_error("bad session_id len");
    return out;
}

inline proto::Parsed parse_chat(std::span<const unsigned char> payload,
                                size_t                         idx)
{
    proto::Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_CHAT;
    out.to      = read_string_u8(payload, idx, MAX_USERNAME, "to");
    out.from    = read_string_u8(payload, idx, MAX_USERNAME, "from");
    ensure_range(idx, FINGERPRINT_LEN, payload.size(), "fingerprint");
    out.identity_pk = extract_bytes(payload, idx, FINGERPRINT_LEN);
    idx += FINGERPRINT_LEN;
    ensure_range(idx, 4, payload.size(), "seq");
    out.seq = read_u32_be(payload, idx);
    idx += 4;
    ensure_range(idx, NONCE_LEN, payload.size(), "nonce");
    out.nonce = extract_bytes(payload, idx, NONCE_LEN);
    idx += NONCE_LEN;
    out.ciphertext =
        read_bytes_u16(payload, idx, MAX_CIPHER, "ciphertext", true);
    return out;
}

inline proto::Parsed parse_list_response(std::span<const unsigned char> payload,
                                         size_t                         idx)
{
    proto::Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_LIST_RESPONSE;
    if (idx + 1 > payload.size())
        throw std::runtime_error("truncated user count");
    const uint8_t count = payload[idx++];
    out.users.reserve(count);
    for (uint8_t i = 0; i < count; ++i)
    {
        out.users.push_back(read_string_u8(payload, idx, MAX_USERNAME, "user"));
    }
    return out;
}

inline proto::Parsed
parse_pubkey_request(std::span<const unsigned char> payload, size_t idx)
{
    proto::Parsed out;
    out.version  = PROTO_VERSION;
    out.type     = MSG_PUBKEY_REQUEST;
    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");
    return out;
}

inline proto::Parsed
parse_pubkey_response(std::span<const unsigned char> payload, size_t idx)
{
    proto::Parsed out;
    out.version  = PROTO_VERSION;
    out.type     = MSG_PUBKEY_RESPONSE;
    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");
    out.identity_pk =
        read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "pubkey", true);
    return out;
}

} // namespace proto_detail

[[nodiscard]] inline std::vector<unsigned char>
proto::build_frame(std::span<const unsigned char> payload)
{
    const auto                 L = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> frame(4 + payload.size());
    proto_detail::store_be32(frame.data(), L);
    std::copy(payload.begin(), payload.end(), frame.begin() + 4);
    return frame;
}

[[nodiscard]] inline std::vector<unsigned char>
proto::build_hello(const std::string &username, uint8_t eph_alg,
                   const std::vector<unsigned char> &eph_pk, uint8_t id_alg,
                   const std::vector<unsigned char> &identity_pk,
                   const std::vector<unsigned char> &signature,
                   const std::vector<unsigned char> &encaps,
                   const std::string                &session_id)
{
    if (username.empty() || username.size() > MAX_USERNAME)
        throw std::runtime_error("bad username");
    if (session_id.size() != SESSION_ID_LEN)
        throw std::runtime_error("bad session_id len");
    if (eph_pk.size() > MAX_PQC_PUBKEY_LEN)
        throw std::runtime_error("bad eph pk len");
    if (identity_pk.size() > MAX_PQC_PUBKEY_LEN)
        throw std::runtime_error("bad identity pk len");
    if (signature.size() > MAX_PQC_SIG_LEN)
        throw std::runtime_error("bad signature len");
    if (encaps.size() > 65535)
        throw std::runtime_error("bad encaps len");

    const auto eph_len = static_cast<uint16_t>(eph_pk.size());
    const auto id_len  = static_cast<uint16_t>(identity_pk.size());
    const auto sig_len = static_cast<uint16_t>(signature.size());
    const auto enc_len = static_cast<uint16_t>(encaps.size());

    const size_t total_size = 2 + 1 + username.size() + 1 + 2 + eph_len + 1 +
                              2 + id_len + 2 + sig_len + 2 + enc_len +
                              SESSION_ID_LEN;

    Poco::Buffer<unsigned char> buf(total_size);
    auto                        it = buf.begin();

    *it++ = PROTO_VERSION;
    *it++ = MSG_HELLO;
    *it++ = static_cast<unsigned char>(username.size());
    it    = std::copy(username.begin(), username.end(), it);

    *it++ = eph_alg;
    *it++ = static_cast<unsigned char>((eph_len >> 8) & 0xFFU);
    *it++ = static_cast<unsigned char>(eph_len & 0xFFU);
    it    = std::copy(eph_pk.begin(), eph_pk.end(), it);

    *it++ = id_alg;
    *it++ = static_cast<unsigned char>((id_len >> 8) & 0xFFU);
    *it++ = static_cast<unsigned char>(id_len & 0xFFU);
    it    = std::copy(identity_pk.begin(), identity_pk.end(), it);

    *it++ = static_cast<unsigned char>((sig_len >> 8) & 0xFFU);
    *it++ = static_cast<unsigned char>(sig_len & 0xFFU);
    it    = std::copy(signature.begin(), signature.end(), it);

    *it++ = static_cast<unsigned char>((enc_len >> 8) & 0xFFU);
    *it++ = static_cast<unsigned char>(enc_len & 0xFFU);
    it    = std::copy(encaps.begin(), encaps.end(), it);

    it = std::copy(session_id.begin(), session_id.end(), it);

    return build_frame(std::span<const unsigned char>(buf.begin(), total_size));
}

[[nodiscard]] inline std::vector<unsigned char>
proto::build_chat(const std::string &to, const std::string &from,
                  const std::array<unsigned char, 32> &from_fingerprint,
                  uint32_t seq, const std::vector<unsigned char> &nonce,
                  const std::vector<unsigned char> &ciphertext)
{
    if (to.empty() || to.size() > MAX_USERNAME)
        throw std::runtime_error("bad to");
    if (from.empty() || from.size() > MAX_USERNAME)
        throw std::runtime_error("bad from");
    if (from_fingerprint.size() != 32)
        throw std::runtime_error("bad fingerprint len");
    if (nonce.size() != NONCE_LEN)
        throw std::runtime_error("bad nonce");
    if (ciphertext.size() > MAX_CIPHER)
        throw std::runtime_error("cipher too large");

    std::vector<unsigned char> p;
    p.reserve(2 + 1 + to.size() + 1 + from.size() + 32 + 4 + NONCE_LEN + 2 +
              ciphertext.size());
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_CHAT);
    p.push_back(static_cast<unsigned char>(to.size()));
    p.insert(p.end(), to.begin(), to.end());
    p.push_back(static_cast<unsigned char>(from.size()));
    p.insert(p.end(), from.begin(), from.end());
    p.insert(p.end(), from_fingerprint.begin(), from_fingerprint.end());
    const std::array<unsigned char, 4> seqb{
        static_cast<unsigned char>((seq >> 24) & 0xFFU),
        static_cast<unsigned char>((seq >> 16) & 0xFFU),
        static_cast<unsigned char>((seq >> 8) & 0xFFU),
        static_cast<unsigned char>(seq & 0xFFU)};
    p.insert(p.end(), std::begin(seqb), std::end(seqb));
    p.insert(p.end(), nonce.begin(), nonce.end());
    const auto clen = static_cast<uint16_t>(ciphertext.size());
    p.push_back(static_cast<unsigned char>((clen >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(clen & 0xFFU));
    p.insert(p.end(), ciphertext.begin(), ciphertext.end());
    return build_frame(std::span<const unsigned char>(p.data(), p.size()));
}

[[nodiscard]] inline std::vector<unsigned char>
proto::build_list_response(const std::vector<std::string> &users)
{
    if (users.size() > MAX_USERS_LIST)
        throw std::runtime_error("too many users");
    std::vector<unsigned char> p;
    p.reserve(2 + 1);
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_LIST_RESPONSE);
    p.push_back(static_cast<unsigned char>(users.size()));
    for (const auto &u : users)
    {
        if (u.empty() || u.size() > MAX_USERNAME)
            throw std::runtime_error("bad user");
        p.push_back(static_cast<unsigned char>(u.size()));
        p.insert(p.end(), u.begin(), u.end());
    }
    return build_frame(std::span<const unsigned char>(p.data(), p.size()));
}

[[nodiscard]] inline std::vector<unsigned char>
proto::build_pubkey_request(const std::string &username)
{
    if (username.empty() || username.size() > MAX_USERNAME)
        throw std::runtime_error("bad username");
    std::vector<unsigned char> p;
    p.reserve(2 + 1 + username.size());
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_PUBKEY_REQUEST);
    p.push_back(static_cast<unsigned char>(username.size()));
    p.insert(p.end(), username.begin(), username.end());
    return build_frame(std::span<const unsigned char>(p.data(), p.size()));
}

[[nodiscard]] inline std::vector<unsigned char>
proto::build_pubkey_response(const std::string                &username,
                             const std::vector<unsigned char> &pubkey)
{
    if (username.empty() || username.size() > MAX_USERNAME)
        throw std::runtime_error("bad username");
    if (pubkey.size() > MAX_PQC_PUBKEY_LEN)
        throw std::runtime_error("pubkey too large");
    std::vector<unsigned char> p;
    p.reserve(2 + 1 + username.size() + 2 + pubkey.size());
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_PUBKEY_RESPONSE);
    p.push_back(static_cast<unsigned char>(username.size()));
    p.insert(p.end(), username.begin(), username.end());
    const auto pklen = static_cast<uint16_t>(pubkey.size());
    p.push_back(static_cast<unsigned char>((pklen >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(pklen & 0xFFU));
    if (pklen != 0U)
        p.insert(p.end(), pubkey.begin(), pubkey.end());
    return build_frame(std::span<const unsigned char>(p.data(), p.size()));
}

inline proto::Parsed parse_payload(std::span<const unsigned char> payload)
{
    if (payload.size() < 2)
        throw std::runtime_error("payload too small");
    const uint8_t version = payload[0];
    if (version != PROTO_VERSION)
        throw std::runtime_error("version mismatch");
    const auto       msg_type    = static_cast<MsgType>(payload[1]);
    constexpr size_t header_size = 2;
    switch (msg_type)
    {
    case MSG_HELLO:
        return proto_detail::parse_hello(payload, header_size);
    case MSG_CHAT:
        return proto_detail::parse_chat(payload, header_size);
    case MSG_LIST_REQUEST:
    {
        proto::Parsed out;
        out.version = PROTO_VERSION;
        out.type    = MSG_LIST_REQUEST;
        return out;
    }
    case MSG_LIST_RESPONSE:
        return proto_detail::parse_list_response(payload, header_size);
    case MSG_PUBKEY_REQUEST:
        return proto_detail::parse_pubkey_request(payload, header_size);
    case MSG_PUBKEY_RESPONSE:
        return proto_detail::parse_pubkey_response(payload, header_size);
    default:
        throw std::runtime_error("unknown msg type");
    }
}

inline proto::Parsed parse_payload(const unsigned char *payload,
                                   size_t               payload_len)
{
    return parse_payload(std::span<const unsigned char>(payload, payload_len));
}

#endif
