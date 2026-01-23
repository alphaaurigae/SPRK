#ifndef SHARED_NET_COMMON_PROTOCOL_H
#define SHARED_NET_COMMON_PROTOCOL_H

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
// shared_net_tls_context.h (add near the top, after includes)
constexpr uint8_t ALGO_KEM_ALG_NAME = ALGO_KYBER512;

constexpr size_t NONCE_LEN      = 12;
constexpr size_t MAX_CIPHER     = 65535;
constexpr size_t MAX_USERS_LIST = 255;
constexpr size_t SESSION_ID_LEN = 60;
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

inline void ensure_range(size_t idx, size_t len, size_t total, const char* field) {
    if (idx + len > total) throw std::runtime_error(std::string("truncated ") + field);
}


namespace proto_detail
{

[[nodiscard]] inline ptrdiff_t to_offset(size_t value) noexcept
{
    return static_cast<ptrdiff_t>(value);
}

[[nodiscard]] inline std::string_view
make_string_view(const unsigned char *data, size_t len) noexcept
{
    const void *vptr = data;
    return {static_cast<const char *>(vptr), len};
}

[[nodiscard]] inline std::vector<unsigned char>
extract_bytes(std::span<const unsigned char> payload, size_t start, size_t len)
{
    return {payload.begin() + to_offset(start),
            payload.begin() + to_offset(start + len)};
}

[[nodiscard]] inline uint16_t
read_u16_be(std::span<const unsigned char> payload, size_t idx) noexcept
{
    return static_cast<uint16_t>((static_cast<uint16_t>(payload[idx]) << 8) |
                                 static_cast<uint16_t>(payload[idx + 1]));
}

[[nodiscard]] inline uint32_t
read_u32_be(std::span<const unsigned char> payload, size_t idx) noexcept
{
    return (static_cast<uint32_t>(payload[idx]) << 24) |
           (static_cast<uint32_t>(payload[idx + 1]) << 16) |
           (static_cast<uint32_t>(payload[idx + 2]) << 8) |
           static_cast<uint32_t>(payload[idx + 3]);
}

[[nodiscard]] inline std::string
read_string_u8(std::span<const unsigned char> payload, size_t &idx,
               size_t max_len, const char *field_name)
{
    ensure_range(idx, 1, payload.size(), "length field");

    const uint8_t len = payload[idx++];
    if (len == 0 || len > max_len)
        throw std::runtime_error(std::string("bad ") + field_name + " length");

    if (idx + len > payload.size())
        throw std::runtime_error(std::string("truncated ") + field_name);

    std::string result{make_string_view(payload.data() + idx, len)};
    idx += len;
    return result;
}

[[nodiscard]] inline std::vector<unsigned char>
read_bytes_u16(std::span<const unsigned char> payload, size_t &idx,
               size_t max_len, const char *field_name, bool allow_empty = false)
{
    ensure_range(idx, 2, payload.size(), "length field");
    const uint16_t len = read_u16_be(payload, idx);
    idx += 2;

    if (len > max_len)
        throw std::runtime_error(std::string("bad ") + field_name + " length");

    if (len == 0)
    {
        if (!allow_empty)
            throw std::runtime_error(std::string("empty ") + field_name);
        return {};
    }

    if (idx + len > payload.size())
        throw std::runtime_error(std::string("truncated ") + field_name);

    auto result = extract_bytes(payload, idx, len);
    idx += len;
    return result;
}

} // namespace proto_detail


inline std::vector<unsigned char>
build_frame(const std::vector<unsigned char> &payload)
{
    const auto                 L = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> frame(4 + payload.size());
    frame[0] = static_cast<unsigned char>((L >> 24) & 0xFFU);
    frame[1] = static_cast<unsigned char>((L >> 16) & 0xFFU);
    frame[2] = static_cast<unsigned char>((L >> 8) & 0xFFU);
    frame[3] = static_cast<unsigned char>(L & 0xFFU);
    std::copy(payload.begin(), payload.end(), frame.begin() + 4);
    return frame;
}

inline std::vector<unsigned char>
build_hello(const std::string &username, uint8_t eph_alg,
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

    std::vector<unsigned char> p;
    p.reserve(2 + 1 + username.size() + 1 + 2 + eph_pk.size() + 1 + 2 +
              identity_pk.size() + 2 + signature.size() + 2 + encaps.size() +
              SESSION_ID_LEN);
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_HELLO);
    p.push_back(static_cast<unsigned char>(username.size()));
    p.insert(p.end(), username.begin(), username.end());

    p.push_back(eph_alg);
    const auto eph_len = static_cast<uint16_t>(eph_pk.size());
    p.push_back(static_cast<unsigned char>((eph_len >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(eph_len & 0xFFU));
    p.insert(p.end(), eph_pk.begin(), eph_pk.end());

    p.push_back(id_alg);
    const auto id_len = static_cast<uint16_t>(identity_pk.size());
    p.push_back(static_cast<unsigned char>((id_len >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(id_len & 0xFFU));
    p.insert(p.end(), identity_pk.begin(), identity_pk.end());

    const auto sig_len = static_cast<uint16_t>(signature.size());
    p.push_back(static_cast<unsigned char>((sig_len >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(sig_len & 0xFFU));
    p.insert(p.end(), signature.begin(), signature.end());

    const auto enc_len = static_cast<uint16_t>(encaps.size());
    p.push_back(static_cast<unsigned char>((enc_len >> 8) & 0xFFU));
    p.push_back(static_cast<unsigned char>(enc_len & 0xFFU));
    if (enc_len != 0U)
        p.insert(p.end(), encaps.begin(), encaps.end());

    p.insert(p.end(), session_id.begin(), session_id.end());
    return build_frame(p);
}

inline std::vector<unsigned char>
build_chat(const std::string &to, const std::string &from,
           const std::array<unsigned char, 32> &from_fingerprint, uint32_t seq,
           const std::vector<unsigned char> &nonce,
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
    return build_frame(p);
}

inline std::vector<unsigned char>
build_list_response(const std::vector<std::string> &users)
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
    return build_frame(p);
}

inline std::vector<unsigned char>
build_pubkey_request(const std::string &username)
{
    if (username.empty() || username.size() > MAX_USERNAME)
        throw std::runtime_error("bad username");
    std::vector<unsigned char> p;
    p.reserve(2 + 1 + username.size());
    p.push_back(PROTO_VERSION);
    p.push_back(MSG_PUBKEY_REQUEST);
    p.push_back(static_cast<unsigned char>(username.size()));
    p.insert(p.end(), username.begin(), username.end());
    return build_frame(p);
}

inline std::vector<unsigned char>
build_pubkey_response(const std::string                &username,
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
    return build_frame(p);
}

namespace proto_detail
{

inline Parsed parse_hello(std::span<const unsigned char> payload, size_t idx)
{
    Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_HELLO;

    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");

    ensure_range(idx, 1, payload.size(), "eph_alg");
    out.eph_alg = payload[idx++];
    out.eph_pk = read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "eph_pk", true);

    ensure_range(idx, 1, payload.size(), "id_alg");
    out.id_alg = payload[idx++];
    out.identity_pk = read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "identity_pk", true);

    out.signature = read_bytes_u16(payload, idx, MAX_PQC_SIG_LEN, "signature", true);
    out.encaps = read_bytes_u16(payload, idx, 65535, "encaps", true);

    ensure_range(idx, SESSION_ID_LEN, payload.size(), "session_id");
    out.session_id = std::string{make_string_view(payload.data() + idx, SESSION_ID_LEN)};
    idx += SESSION_ID_LEN;

    return out;
}


inline Parsed parse_chat(std::span<const unsigned char> payload, size_t idx)
{
    Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_CHAT;

    out.to = read_string_u8(payload, idx, MAX_USERNAME, "to");
    out.from = read_string_u8(payload, idx, MAX_USERNAME, "from");

    ensure_range(idx, FINGERPRINT_LEN, payload.size(), "fingerprint");
    out.identity_pk = extract_bytes(payload, idx, FINGERPRINT_LEN);
    idx += FINGERPRINT_LEN;

    ensure_range(idx, 4, payload.size(), "seq");
    out.seq = read_u32_be(payload, idx);
    idx += 4;

    ensure_range(idx, NONCE_LEN, payload.size(), "nonce");
    out.nonce = extract_bytes(payload, idx, NONCE_LEN);
    idx += NONCE_LEN;

    out.ciphertext = read_bytes_u16(payload, idx, MAX_CIPHER, "ciphertext", true);

    return out;
}


inline Parsed parse_list_response(std::span<const unsigned char> payload,
                                  size_t                         idx)
{
    Parsed out;
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

inline Parsed parse_pubkey_request(std::span<const unsigned char> payload,
                                   size_t                         idx)
{
    Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_PUBKEY_REQUEST;

    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");

    return out;
}

inline Parsed parse_pubkey_response(std::span<const unsigned char> payload,
                                    size_t                         idx)
{
    Parsed out;
    out.version = PROTO_VERSION;
    out.type    = MSG_PUBKEY_RESPONSE;

    out.username = read_string_u8(payload, idx, MAX_USERNAME, "username");
    out.identity_pk =
        read_bytes_u16(payload, idx, MAX_PQC_PUBKEY_LEN, "pubkey", true);

    return out;
}

} // namespace proto_detail

inline Parsed parse_payload(std::span<const unsigned char> payload)
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
        Parsed out;
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

inline Parsed parse_payload(const unsigned char *payload, size_t payload_len)
{
    return parse_payload(std::span<const unsigned char>(payload, payload_len));
}

#endif