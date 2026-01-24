# SPRK-Chat

Experimental post-quantum end-to-end encrypted chat system: ML-DSA-87 signatures, Kyber512 KEM, X25519MLKEM768 hybrid TLS 1.3.

> AI LLM generated readme based on repo code.


## Overview
Client-server relay with client-side E2E encryption. Server coordinates connections but cannot decrypt. TOFU trust model with SHA-256 fingerprints. Auto key exchange, forward secrecy via ephemeral rotation (1024 msgs), replay protection, exponential backoff reconnect.

**Stack:** C++23, Asio async I/O, OpenSSL 3.5 + oqsprovider, liboqs 0.11+, Poco

**Limitations:** In-memory only (no persistence), 1-to-1 messaging, TOFU (no PKI), metadata visible to server, experimental/unaudited



## Crypto Primitives

| Layer | Algorithm | Details |
|-------|-----------|---------|
| **TLS** | X25519MLKEM768 | Hybrid KEM (X25519 + ML-KEM-768) |
| | AES-256-GCM, ChaCha20-Poly1305 | Cipher suites |
| **Identity** | ML-DSA-87 | 2592B pubkey, ~4595B sig, signs eph_pk\|\|session_id |
| **KEM** | Kyber512 | 800B pubkey, 768B ciphertext, 32B shared secret |
| **KDF** | HKDF-SHA256 | IKM=kyber_secret, salt=0×32, info=sorted(fp_a,fp_b)\|session_id |
| **AEAD** | ChaCha20-Poly1305 | Nonce=HMAC-SHA256(key,seq)[:12], AAD=sorted(fp)\|seq, 16B tag |
| **Fingerprint** | SHA-256 | Hash of identity_pk, 64-char hex (display 10-char prefix) |

## Security

**Guarantees:** Confidentiality (AEAD), authentication (ML-DSA-87 + fingerprint), integrity (Poly1305 tag), forward secrecy (ephemeral rotation), replay protection (seq validation), quantum resistance (ML-DSA-87 + Kyber512)

**Limitations:** Traffic analysis visible, server logs metadata/graph, TOFU (no PKI), device compromise fatal, forward secrecy resets at rekey

**Threat model:** Network attacker (read/modify/replay), honest-but-curious server, trusted client software

## References

- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- ML-KEM (Kyber): https://csrc.nist.gov/pubs/fips/203/final
- RFC 8439 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc8439
- liboqs: https://github.com/open-quantum-safe/liboqs
- oqsprovider: https://github.com/open-quantum-safe/oqs-provider



### KEYGEN
```bash
./bin/user_keygen  [--raw] [--out-dir ]
```
- Generates ML-DSA-87 keypair via OpenSSL EVP (`EVP_PKEY_keygen`)
- Outputs: `<name>.sk.pem` (PKCS#8, 4595-byte secret), `<name>.crt` (self-signed X.509, 1yr validity)
- Optional `.sk.raw` (raw secret+public bytes) with `--raw`
- No liboqs dependency, uses native OpenSSL 3.5 PQ support


```

Generates ML-DSA-87 identity keypairs and self-signed X.509 certificates using OpenSSL 3.5 EVP API.

**Technical operation:**
- Algorithm: ML-DSA-87 (FIPS 204) via `EVP_PKEY_keygen` with "ML-DSA-87" algorithm string
- Outputs:
  - `.sk.pem`: PKCS#8 private key (PEM format, ~4595-byte secret key)
  - `.crt`: Self-signed X.509 certificate (PEM format, 1-year validity, CN=base_name)
  - `.sk.raw`: Combined raw secret/public key bytes (optional, with `--raw` flag)
- Key sizes: 4595-byte secret key, 2592-byte public key
- Certificate settings: Serial=1, digitalSignature keyUsage, no password protection
- No liboqs dependency: Uses native OpenSSL 3.5 PQ support

**Example:**
```bash
./bin/user_keygen alice          # Creates alice.sk.pem, alice.crt
./bin/user_keygen bob --raw      # Creates bob.sk.pem, bob.crt, bob.sk.raw

```

### SERVER
```bash
./bin/server 
```
- **Transport:** TLS 1.3 mutual auth, X25519MLKEM768 hybrid KEM, AES-256-GCM/ChaCha20-Poly1305
- **Architecture:** Multi-threaded Asio (N=hardware threads), 4-byte BE length-prefixed frames (max 1MB)
- **Sessions:** 60-char Base58 session IDs, per-session maps: username→ClientState, fingerprint→ClientState
- **Handles:** `MSG_HELLO` (validates ML-DSA-87 sig, broadcasts to peers, strips encaps for existing), `MSG_CHAT` (relay by username/fingerprint prefix), `MSG_LIST_REQUEST`, `MSG_PUBKEY_REQUEST`
- **Validation:** Username 1-64 alphanumeric/_/-, Levenshtein <85%, signature verification
- **Does NOT:** decrypt, persist, validate sequences, enforce rate limits

```

Stateless relay server for encrypted message frames with session-based client coordination.

**Technical operation:**
- **Transport:** TLS 1.3 only with X25519MLKEM768 hybrid KEM, mutual certificate authentication
- **Architecture:** Multi-threaded Asio event loop (N threads = hardware concurrency)
- **Frame protocol:** 4-byte big-endian length prefix + payload (max 1MB)
- **Session management:** Clients grouped by 60-char Base58 session ID
  - Per-session maps: username→ClientState, fingerprint→ClientState, fingerprint→cached_HELLO
  - Tracks: ephemeral keys, identity keys, original HELLO frames
- **Message handling:**
  - `MSG_HELLO`: Validates ML-DSA-87 signature, registers client, broadcasts to session peers (strips encaps for existing clients)
  - `MSG_CHAT`: Relays encrypted frame by username or fingerprint prefix without decryption
  - `MSG_LIST_REQUEST`: Returns username list for client's session
  - `MSG_PUBKEY_REQUEST`: Returns identity public key for requested user
- **Security validation:**
  - Username: 1-64 alphanumeric/underscore/hyphen, Levenshtein similarity <85% vs existing
  - Signature: ML-DSA-87 verification of `eph_pk || session_id`
  - Session isolation: No cross-session message routing
- **No persistence:** All state in-memory, cleared on disconnect

**Key responsibilities:**
- TLS handshake and mutual authentication
- HELLO broadcast coordination for key exchange
- Message routing by fingerprint or username
- Session membership tracking
- Does NOT: decrypt messages, validate sequences, persist data, enforce rate limits

**Example:**
bash
./bin/server 1566
# Requires: server.crt, server.key, ca.crt in sample/sample_test_cert/
```

### CLIENT
```bash
./bin/client      [--sessionid ]
```
- **Identity:** ML-DSA-87 from PEM, SHA-256 fingerprint
- **Ephemeral:** Kyber512 keypair per connection (800B pubkey, 768B ciphertext)
- **Key exchange:**
  1. Send `MSG_HELLO`: username, eph_pk, identity_pk, sig(eph_pk||session_id), session_id
  2. Determine initiator: lex-lower fingerprint
  3. Initiator encapsulates → responder decapsulates
  4. Derive 32B session key: HKDF-SHA256(kyber_secret, salt=0, info=sorted(fp_a,fp_b)||session_id)
- **Encryption:** ChaCha20-Poly1305 AEAD, nonce=HMAC-SHA256(key,seq)[:12], AAD=sorted(fp_a,fp_b)||seq
- **Security:** Seq validation (gap≤100, jitter≤3), rate limit 100msg/s, 60s timeout, auto-rekey @1024 msgs
- **Commands:** `list`, `pubk <user>`, `<fp_prefix> <msg>`


```
End-to-end encrypted chat client with automatic PQ key exchange and session key derivation.

**Technical operation:**
- **Identity:** ML-DSA-87 keypair from PEM, SHA-256 fingerprint for identification
- **Transport:** TLS 1.3 with X25519MLKEM768 hybrid KEM, mutual certificate authentication
- **Ephemeral keys:** Generates Kyber512 keypair on connect (800-byte public key, 768-byte ciphertext)
- **Key exchange protocol:**
  1. Send `MSG_HELLO` with username, eph_pk, identity_pk, signature(`eph_pk || session_id`)
  2. Determine initiator role: lexicographically lower fingerprint
  3. Initiator: Encapsulate to peer's eph_pk, send ciphertext in reply `MSG_HELLO`
  4. Responder: Decapsulate received ciphertext with own eph_sk
  5. Both derive 32-byte session key via HKDF-SHA256:
     - IKM: Kyber512 shared secret
     - Info: `sorted(fp_a, fp_b) || session_id`
- **Message encryption:** ChaCha20-Poly1305 AEAD
  - Key: Derived session key
  - Nonce: `HMAC-SHA256(session_key, seq)[:12]`
  - AAD: `sorted(sender_fp, receiver_fp) || seq` (ASCII string)
  - Tag: 16 bytes appended to ciphertext
- **Security features:**
  - Replay protection: Sequence number validation (gap ≤100, jitter ≤3)
  - Rate limiting: 100 messages/second per peer
  - Message timeout: 60s inactivity threshold
  - Rekeying: Automatic after 1024 sent messages (generates new ephemeral keypair)
- **Reconnection:** Exponential backoff (1s–60s, max 10 attempts), preserves ephemeral keys within session
- **Commands:** `list` (active users), `pubk <user>` (fetch identity key), `<fp_prefix> <msg>` (send encrypted message)

**Key responsibilities:**
- Signature verification of peer HELLOs
- Automatic KEM role determination and execution
- Session key derivation with sorted fingerprint context
- AEAD encryption/decryption with sequence validation
- Ephemeral key rotation for forward secrecy
- Fingerprint-based recipient resolution

**Example:**
bash
./bin/client 127.0.0.1 1566 alice sample/alice.sk.pem sample/alice.crt --sessionid <60-char-id>

# Runtime:
list users
4f2e8a3c9d hello bob    # Send to fingerprint prefix


```
## TEST LOG

### SERVER
```
✘-INT ~/Desktop/SPRK [main|✔] 
22:23 $ ./server.sh 
Server TLS ready:
  Cert: sample/sample_test_cert/server.crt
  Key:  sample/sample_test_cert/server.key
  Using trusted CA bundle for client verification
  Hybrid KEM: X25519MLKEM768
Server listening on port 1566 with post-quantum TLS
connect ron session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
connect beth session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
connect ron session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
connect bob session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
connect ron session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
connect bob session=bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz

```

## Build Requirements

- Ubuntu 24.04 LTS (tested)
- CMake 3.20+, C++23 (GCC 13+/Clang 16+)
- OpenSSL 3.5+ with oqsprovider, liboqs 0.11+
- asio
- poco

## Quick Start
```bash
# 1. Install deps (OpenSSL 3.5 + OQS)
./openss3_liboqs_oqsprovider.sh

# 2. Build
./build_cmake.sh  # → bin/client, bin/server, bin/user_keygen

# 3. Generate server certs
./generate_pq_certs.sh  # → sample/sample_test_cert/{server.crt,server.key,ca.crt}

# 4. Generate user keys
./bin/user_keygen alice  # → alice.sk.pem, alice.crt
./bin/user_keygen bob

# 5. Run
./bin/server 1566
./bin/client 127.0.0.1 1566 alice sample/alice.sk.pem sample/alice.crt
./bin/client 127.0.0.1 1566 bob sample/bob.sk.pem sample/bob.crt

# 6. Chat (alice → bob, use fingerprint prefix from 'list users')
list users
4f2e8a3c9d hello bob
```

> Test triangular
...
### CLIENT 1
```
✘-INT ~/Desktop/SPRK [main|● 11✚ 3…3] 
00:42 $ ./client.sh ron sample/ron.sk.pem sample/ron.crt -sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug
OpenSSL: OpenSSL 3.5.5-dev  (Library: OpenSSL 3.5.5-dev )
lib path: /usr/local/openssl-3.5/lib64
Using:
  Username: ron
  Identity key: sample/ron.sk.pem
  Client cert:  sample/ron.crt

Executing: bin/client 127.0.0.1 1566 ron sample/ron.sk.pem sample/ron.crt --sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug

Loaded PEM identity key: sample/ron.sk.pem
Using provided session: bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
Client TLS context ready
  Cert: sample/sample_test_cert/ron.crt
  Key:  sample/sample_test_cert/ron_tls.key
  Hybrid KEM: X25519MLKEM768
[1768261386198] TLS handshake successful
[1768261388234] received frame, size=8100
[00:43:08] connect beth pubkey=db54386c37...9f3abd9e89
>>> INITIATOR SENDING ENCAPS! my=ron peer=beth initiator=1 already_sent=0
[1768261388234] DEBUG encaps: my=ron peer=beth context=4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8|db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c keysize=32
[1768261388234] peer beth ready
[1768261388236] received frame, size=8100
list users
[1768261398572] received frame, size=16
users:
beth [db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c]
ron [4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8]
db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c test1
[00:43:30] [beth db0c227079] "test1"
[1768261430153] received frame, size=86
[00:43:50] [beth db0c227079] test2
[1768261499000] received frame, size=8099
[00:44:59] connect bob pubkey=00beac715b...3f4a4101ab
>>> INITIATOR SENDING ENCAPS! my=ron peer=bob initiator=1 already_sent=0
[1768261499000] DEBUG encaps: my=ron peer=bob context=4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8|992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 keysize=32
[1768261499000] peer bob ready
[1768261499003] received frame, size=8099
[1768261499043] received frame, size=8100
[1768261499043] received frame, size=8867
992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 test4
[00:45:36] [bob 992ec5b63e] "test4"
[1768261544947] received frame, size=85
[00:45:44] [bob 992ec5b63e] test5


```

### CLIENT 2
```
✘-INT ~/Desktop/SPRK [main|✔] 
22:23 $ ./client.sh beth sample/beth.sk.pem sample/beth.crt -sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug
OpenSSL: OpenSSL 3.5.5-dev  (Library: OpenSSL 3.5.5-dev )
lib path: /usr/local/openssl-3.5/lib64
Using:
  Username: beth
  Identity key: sample/beth.sk.pem
  Client cert:  sample/beth.crt

Executing: bin/client 127.0.0.1 1566 beth sample/beth.sk.pem sample/beth.crt --sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug

Loaded PEM identity key: sample/beth.sk.pem
Using provided session: bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
Client TLS context ready
  Cert: sample/sample_test_cert/beth.crt
  Key:  sample/sample_test_cert/beth_tls.key
  Hybrid KEM: X25519MLKEM768
[1768261388190] TLS handshake successful
[1768261388274] received frame, size=8099
[00:43:08] connect ron pubkey=ee1fb02680...3db2858c5b
[1768261388274] INFO: awaiting encaps from ron
[1768261388275] received frame, size=8867
[00:43:08] connect ron pubkey=ee1fb02680...3db2858c5b
[1768261388275] DEBUG decaps: my=beth peer=ron context=4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8|db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c keysize=32
[1768261388275] peer ron ready
[1768261388276] received frame, size=16
users:
beth [db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c]
ron [4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8]
[1768261410812] received frame, size=86
[00:43:30] [ron 4991ed2589] test1
4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8 test2
[00:43:50] [ron 4991ed2589] "test2"
[1768261499000] received frame, size=8099
[00:44:59] connect bob pubkey=00beac715b...3f4a4101ab
[1768261499000] INFO: awaiting encaps from bob
[1768261499003] received frame, size=8867
[1768261499042] received frame, size=8867
[00:44:59] connect bob pubkey=00beac715b...3f4a4101ab
[1768261499042] DEBUG decaps: my=beth peer=bob context=992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26|db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c keysize=32
[1768261499042] peer bob ready
[1768261499043] received frame, size=20
users:
bob [992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26]
beth [db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c]
ron [4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8]
992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 test3
[00:45:24] [bob 992ec5b63e] "test3"
[1768261555460] received frame, size=86
[00:45:55] [bob 992ec5b63e] test6


```

### CLIENT 3
```
✔ ~/Desktop/SPRK [main|● 11✚ 3…3] 
00:44 $ ./client.sh bob sample/bob.sk.pem sample/bob.crt -sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug
OpenSSL: OpenSSL 3.5.5-dev  (Library: OpenSSL 3.5.5-dev )
lib path: /usr/local/openssl-3.5/lib64
Using:
  Username: bob
  Identity key: sample/bob.sk.pem
  Client cert:  sample/bob.crt

Executing: bin/client 127.0.0.1 1566 bob sample/bob.sk.pem sample/bob.crt --sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug

Loaded PEM identity key: sample/bob.sk.pem
Using provided session: bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz
Client TLS context ready
  Cert: sample/sample_test_cert/bob.crt
  Key:  sample/sample_test_cert/bob_tls.key
  Hybrid KEM: X25519MLKEM768
[1768261498957] TLS handshake successful
[1768261499040] received frame, size=8100
[00:44:59] connect beth pubkey=db54386c37...9f3abd9e89
>>> INITIATOR SENDING ENCAPS! my=bob peer=beth initiator=1 already_sent=0
[1768261499040] DEBUG encaps: my=bob peer=beth context=992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26|db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c keysize=32
[1768261499040] peer beth ready
[1768261499042] received frame, size=8099
[00:44:59] connect ron pubkey=ee1fb02680...3db2858c5b
[1768261499042] INFO: awaiting encaps from ron
[1768261499042] received frame, size=8867
[00:44:59] connect ron pubkey=ee1fb02680...3db2858c5b
[1768261499042] DEBUG decaps: my=bob peer=ron context=4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8|992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 keysize=32
[1768261499042] peer ron ready
[1768261499043] received frame, size=8100
[1768261499043] received frame, size=8099
[1768261499084] received frame, size=20
users:
bob [992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26]
beth [db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c]
ron [4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8]
[1768261524916] received frame, size=86
[00:45:24] [beth db0c227079] test3
[1768261536477] received frame, size=85
[00:45:36] [ron 4991ed2589] test4
4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8 test5
[00:45:44] [ron 4991ed2589] "test5"
db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c test6
[00:45:55] [beth db0c227079] "test6"

```

###  ./unit.sh

```
✔ ~/Desktop/SPRK [main|✔] 
19:07 $ '/home/mmmm/Desktop/SPRK/unit.sh' 
STARTING FULL SPRK TEST
RUNNING: Test_001_Client_help
Test 001: Client help
SUCCESS: Help complete
RUNNING: EXEC_002_Start_server
EXEC 002: Start Server
STATUS: >>> Sending to server: '/home/mmmm/Desktop/SPRK/server.sh 1566' (start server)
Connection to 127.0.0.1 1566 port [tcp/*] succeeded!
SUCCESS: Server listening
RUNNING: Test_003_Ron_connect
Test 003: Ron connects
STATUS: >>> Sending to ron: '/home/mmmm/Desktop/SPRK/client.sh 127.0.0.1 1566 ron /home/mmmm/Desktop/SPRK/sample/ron.sk.pem /home/mmmm/Desktop/SPRK/sample/ron.crt --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (ron login)
DEBUG: check_output target=ron pattern=TLS handshake successful timeout=2 grace=3
PASS: Ron connected
DEBUG: check_output target=server pattern=connect ron session=.* timeout=2 grace=3
PASS: Server sees ron
RUNNING: Test_004_Beth_connect
Test 004: Beth connects
STATUS: >>> Sending to beth: '/home/mmmm/Desktop/SPRK/client.sh 127.0.0.1 1566 beth /home/mmmm/Desktop/SPRK/sample/beth.sk.pem /home/mmmm/Desktop/SPRK/sample/beth.crt --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (beth login)
DEBUG: check_output target=beth pattern=TLS handshake successful timeout=2 grace=3
PASS: Beth connected
DEBUG: check_output target=beth pattern=connect ron pubkey=.* timeout=10 grace=3
PASS: Beth sees ron
DEBUG: check_output target=beth pattern=peer ron ready timeout=10 grace=3
PASS: Beth ready with ron
DEBUG: check_output target=server pattern=connect beth session=.* timeout=2 grace=3
PASS: Server sees beth
RUNNING: Test_005_Ron_Beth_messaging_and_fp_extraction
Test 005: Ron ↔ Beth messaging + extract FPs
STATUS: Extracting FPs from ron (after Ron+Beth connected)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 
FP_BOB_FROM_RON  = 
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from beth (from Beth's view)
STATUS: >>> Sending to beth: 'list users' (extract FPs)
Updated FPs after beth list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BOB_FROM_RON  = 
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: >>> Sending to ron: 'db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c hello beth from ron' (ron→beth)
DEBUG: check_output target=beth pattern=\[.*\] \[ron .*] hello beth from ron timeout=2 grace=3
PASS: Beth received from ron
STATUS: >>> Sending to beth: '4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8 hello ron from beth' (beth→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[beth .*] hello ron from beth timeout=2 grace=3
PASS: Ron received from beth
RUNNING: Test_006_Bob_connect
Test 006: Bob connects + triangular rekey
STATUS: >>> Sending to bob: '/home/mmmm/Desktop/SPRK/client.sh 127.0.0.1 1566 bob /home/mmmm/Desktop/SPRK/sample/bob.sk.pem /home/mmmm/Desktop/SPRK/sample/bob.crt --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (bob login)
DEBUG: check_output target=bob pattern=TLS handshake successful timeout=2 grace=3
PASS: Bob connected
DEBUG: check_output target=bob pattern=connect ron pubkey=.* timeout=45 grace=3
PASS: Bob sees ron
DEBUG: check_output target=bob pattern=connect beth pubkey=.* timeout=45 grace=3
PASS: Bob sees beth
DEBUG: check_output target=bob pattern=peer ron ready timeout=45 grace=3
PASS: Bob ready with ron
DEBUG: check_output target=bob pattern=peer beth ready timeout=45 grace=3
PASS: Bob ready with beth
DEBUG: check_output target=server pattern=connect bob session=.* timeout=2 grace=3
PASS: Server sees bob
RUNNING: Test_007_Extract_all_fps_after_bob
Test 007: Extract all fingerprints after Bob joined
STATUS: Extracting FPs from ron (from Ron)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BOB_FROM_RON  = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from beth (from Beth)
STATUS: >>> Sending to beth: 'list users' (extract FPs)
Updated FPs after beth list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BOB_FROM_RON  = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_BOB_FROM_BETH = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from bob (from Bob)
STATUS: >>> Sending to bob: 'list users' (extract FPs)
Updated FPs after bob list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BOB_FROM_RON  = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_BOB_FROM_BETH = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_RON_FROM_BOB  = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BETH_FROM_BOB = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
RUNNING: Test_008_Triangular_messaging
Test 008: Full triangular messaging
STATUS: >>> Sending to ron: '992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 hi bob from ron' (ron→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] hi bob from ron timeout=2 grace=3
PASS: Bob got from ron
STATUS: >>> Sending to beth: '992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 hi bob from beth' (beth→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[beth .*] hi bob from beth timeout=2 grace=3
PASS: Bob got from beth
STATUS: >>> Sending to bob: '4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8 hi ron from bob' (bob→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[bob .*] hi ron from bob timeout=2 grace=3
PASS: Ron got from bob
STATUS: >>> Sending to bob: 'db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c hi beth from bob' (bob→beth)
DEBUG: check_output target=beth pattern=\[.*\] \[bob .*] hi beth from bob timeout=2 grace=3
PASS: Beth got from bob
RUNNING: Test_009_Multi_recipient
Test 009: Multi-recipient messaging
STATUS: >>> Sending to ron: 'db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c,992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 group hello from ron' (group)
DEBUG: check_output target=beth pattern=\[.*\] \[ron .*] group hello from ron timeout=2 grace=3
PASS: Beth got group
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] group hello from ron timeout=2 grace=3
PASS: Bob got group
RUNNING: Test_010_Client_commands
Test 010: Client commands
STATUS: >>> Sending to ron: 'pubk beth' (pubk beth)
DEBUG: check_output target=ron pattern=pubkey beth timeout=5 grace=3
PASS: Ron fetched beth pubkey
STATUS: >>> Sending to ron: 'pubk bob' (pubk bob)
DEBUG: check_output target=ron pattern=pubkey bob timeout=5 grace=3
PASS: Ron fetched bob pubkey
STATUS: >>> Sending to beth: 'pubk ron' (pubk ron)
DEBUG: check_output target=beth pattern=pubkey ron timeout=5 grace=3
PASS: Beth fetched ron pubkey
STATUS: >>> Sending to beth: 'pubk bob' (pubk bob)
DEBUG: check_output target=beth pattern=pubkey bob timeout=5 grace=3
PASS: Beth fetched bob pubkey
STATUS: >>> Sending to bob: 'pubk ron' (pubk ron)
DEBUG: check_output target=bob pattern=pubkey ron timeout=5 grace=3
PASS: Bob fetched ron pubkey
STATUS: >>> Sending to bob: 'pubk beth' (pubk beth)
DEBUG: check_output target=bob pattern=pubkey beth timeout=5 grace=3
PASS: Bob fetched beth pubkey
RUNNING: Test_011_Post_Ron_reconnect_full_verification
Test 011: Full verification after Ron reconnect
STATUS: >>> Sending to ron: 'q' (quit ron)
STATUS: >>> Sending to ron: '/home/mmmm/Desktop/SPRK/client.sh 127.0.0.1 1566 ron /home/mmmm/Desktop/SPRK/sample/ron.sk.pem /home/mmmm/Desktop/SPRK/sample/ron.crt --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (ron login)
DEBUG: check_output target=ron pattern=TLS handshake successful timeout=2 grace=3
PASS: Ron reconnected
DEBUG: check_output target=ron pattern=peer beth ready timeout=45 grace=3
PASS: Ron ready with beth (post-reconnect)
DEBUG: check_output target=ron pattern=peer bob ready timeout=45 grace=3
PASS: Ron ready with bob (post-reconnect)
STATUS: Extracting FPs from ron (post-reconnect)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
FP_RON_FROM_BETH = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BOB_FROM_RON  = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_BOB_FROM_BETH = 992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26
FP_RON_FROM_BOB  = 4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8
FP_BETH_FROM_BOB = db0c227079f529113e6fbc595d8469f4dc3e579a80a88c1305eb5a749f042c3c
STATUS: >>> Sending to ron: '992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 post-reconnect hi bob from ron' (post-reconnect ron→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] post-reconnect hi bob from ron timeout=2 grace=3
PASS: Bob got post-reconnect
STATUS: >>> Sending to beth: '992ec5b63eb1aacb59839bfa8eba896d46012faee0fb21acdc157e95496aad26 post-reconnect hi bob from beth' (post-reconnect beth→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[beth .*] post-reconnect hi bob from beth timeout=2 grace=3
PASS: Bob got post-reconnect from beth
STATUS: >>> Sending to bob: '4991ed25897e7f31ac54b505114bd60ec7113d4f5610462e2f7d5acb199c4ba8 post-reconnect hi ron from bob' (post-reconnect bob→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[bob .*] post-reconnect hi ron from bob timeout=2 grace=3
PASS: Ron got post-reconnect from bob
STATUS: >>> Sending to ron: 'list users' (post-reconnect list)
DEBUG: check_output target=ron pattern=beth.*\[.*\] timeout=2 grace=3
PASS: List shows beth (post-reconnect)
DEBUG: check_output target=ron pattern=bob.*\[.*\] timeout=2 grace=3
PASS: List shows bob (post-reconnect)
ALL TESTS PASS
   ✓ Ron connected
   ✓ Server sees ron
   ✓ Beth connected
   ✓ Beth sees ron
   ✓ Beth ready with ron
   ✓ Server sees beth
   ✓ Beth received from ron
   ✓ Ron received from beth
   ✓ Bob connected
   ✓ Bob sees ron
   ✓ Bob sees beth
   ✓ Bob ready with ron
   ✓ Bob ready with beth
   ✓ Server sees bob
   ✓ Bob got from ron
   ✓ Bob got from beth
   ✓ Ron got from bob
   ✓ Beth got from bob
   ✓ Beth got group
   ✓ Bob got group
   ✓ Ron fetched beth pubkey
   ✓ Ron fetched bob pubkey
   ✓ Beth fetched ron pubkey
   ✓ Beth fetched bob pubkey
   ✓ Bob fetched ron pubkey
   ✓ Bob fetched beth pubkey
   ✓ Ron reconnected
   ✓ Ron ready with beth (post-reconnect)
   ✓ Ron ready with bob (post-reconnect)
   ✓ Bob got post-reconnect
   ✓ Bob got post-reconnect from beth
   ✓ Ron got post-reconnect from bob
   ✓ List shows beth (post-reconnect)
   ✓ List shows bob (post-reconnect)
Total successful checks: 34
CLEANUP STARTED ...
CLEANUP DONE!
✔ ~/Desktop/SPRK [main|✚ 1] 
20:01 $ 


```