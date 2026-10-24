# SPRK-Chat

Experimental post-quantum end-to-end encrypted chat system: ML-DSA-87 signatures, ML-KEM-768 KEM,
X25519MLKEM768 hybrid TLS 1.3. Native OpenSSL 3.5+ -- no liboqs, no oqs-provider.

> See `docs/CONTINUATION_NOTES.md` for the full engineering history, every finding, every fix, and
> exact next steps. Read it before making further changes.

## Overview
Client-server relay with client-side E2E encryption. Server coordinates connections but cannot decrypt.
TOFU trust model with SHA-256 fingerprints. Auto key exchange, forward secrecy via ephemeral rotation,
replay protection, exponential backoff reconnect.

**Stack:** C++23, Asio async I/O, OpenSSL 3.5+ (native ML-KEM/ML-DSA), Poco

**Limitations:** In-memory only (no persistence), 1-to-1/group messaging over a shared relay, TOFU (no
PKI), metadata visible to server, experimental/unaudited. The C++ server is a transitional bridge; see
`docs/server_elixir_grid_plan.md` for the intended production server architecture.

## Crypto Primitives

| Layer | Algorithm | Details |
|-------|-----------|---------|
| **TLS** | X25519MLKEM768 | Hybrid KEM (X25519 + ML-KEM-768), hybrid-only, no plain-X25519 fallback |
| | AES-256-GCM, ChaCha20-Poly1305 | Cipher suites |
| **Identity** | ML-DSA-87 | 2592B pubkey, ~4627B sig, signs eph_pk\|\|session_id\|\|username |
| **KEM** | ML-KEM-768 | 1184B pubkey, 1088B ciphertext, 32B shared secret |
| **KDF** | HKDF-SHA256 | Two role-labeled directional keys per peer pair (see below) |
| **AEAD** | ChaCha20-Poly1305 | Nonce=HMAC-SHA256(key,seq)[:12], AAD=sorted(fp)\|seq, 16B tag |
| **Fingerprint** | SHA-256 | Hash of identity_pk, 64-char hex (display 10-char prefix) |

**Directional keys:** each pairwise session derives *two* keys (`send_key`/`recv_key` per side, mirrored
across the pair) via HKDF-expand with distinct labels (`SPRK-v2-initiator-to-responder` /
`SPRK-v2-responder-to-initiator`), not one shared key. This closes a critical cross-direction nonce-reuse
vulnerability present in the original prototype -- see `docs/audit_code_bestpractice.md` §1.1 and
`docs/CONTINUATION_NOTES.md` §2.

**Target-addressed KEM replies:** `MSG_HELLO` carries an explicit `target_fp` field alongside any
encapsulation ciphertext, naming exactly which peer that ciphertext is for. This is "protocol v2.1" --
see `docs/CONTINUATION_NOTES.md` §4 for why it's necessary (multi-party rekey and reconnect correctness).

## Security

**Guarantees:** Confidentiality (AEAD, direction-separated keys), authentication (ML-DSA-87 + fingerprint,
signature covers username), integrity (Poly1305 tag), forward secrecy (ephemeral rotation), replay
protection (seq validation), quantum resistance (ML-DSA-87 + ML-KEM-768).

**Limitations:** Traffic analysis visible, server logs metadata/graph, TOFU (no PKI), device compromise
fatal, forward secrecy resets at rekey, `target_fp` is not itself signed (residual: a compromised relay
could misdirect a KEM reply, causing a failed handshake -- an availability issue, not a confidentiality
break, since ML-KEM's implicit-rejection property means decapsulating with the wrong key just yields a
useless secret).

**Threat model:** Network attacker (read/modify/replay), honest-but-curious server, trusted client
software.

## References

- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- RFC 8439 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc8439
- OpenSSL 3.5 ML-KEM/ML-DSA docs: `EVP_PKEY-ML-KEM.pod`, `EVP_SIGNATURE-ML-DSA.pod` (shipped with OpenSSL)

## Build (Ubuntu 26.04 LTS -- no custom OpenSSL build needed)

```bash
sudo apt install libssl-dev libasio-dev libpoco-dev cmake build-essential tmux netcat-openbsd
./build_cmake.sh           # -> bin/client, bin/server, bin/user_keygen
./generate_pq_certs.sh     # -> sample/sample_test_cert/{server,ca,ron,beth,bob}.{crt,key}
./keygen_run.sh ron  --out-dir sample
./keygen_run.sh beth --out-dir sample
./keygen_run.sh bob  --out-dir sample
./server.sh &
./client.sh 127.0.0.1 1566 ron  sample/ron.sk.pem  sample/ron.crt # --sessionid <60-char-id>
./client.sh 127.0.0.1 1566 beth sample/beth.sk.pem sample/beth.crt --sessionid <60-char-id>
./client.sh 127.0.0.1 1566 bob sample/beth.sk.pem sample/beth.crt --sessionid <60-char-id>
```

If building on an OS without OpenSSL 3.5+ in its repositories, build OpenSSL from the `openssl-3.5`
branch yourself and pass `-DOPENSSL_ROOT_DIR=/path/to/install` to `cmake` (see
`docs/CONTINUATION_NOTES.md` §6 for the exact commands used during development).

## Runtime commands

```
list | list users         list connected users
pubk <username>           fetch user public key
<fp[,fp...]> <message>    send message to peer(s), comma-separated fingerprint prefixes for groups
q                         quit
```

## Testing

`./unit.sh` runs a full multi-party tmux integration test: connect, bidirectional messaging, a third
party joining, group messaging, one party disconnecting and reconnecting mid-session, another
disconnecting while the first two continue messaging, and a final reconnect -- this is the regression
test for the rekey-cascade and reconnect-stale-ready bugs documented in `docs/CONTINUATION_NOTES.md` §4.
Lower `REKEY_INTERVAL` in `src/client/client_peer_manager.h` temporarily to also exercise a real rekey
during that sequence; restore it to `1024` afterward.
