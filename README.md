# SPRK-Chat

- Experimental ... 

(LLM GENERATED README)

**Post-Quantum End-to-End Encrypted Chat**

## TEMP notes ...

> Build OS Ubuntu 24 LTS


## Use flow:

### 1. DEPS
1. Install `openssl 3.5` with `oqs` support... if not present
`Ubuntu 24 LTS` script to install / clean git `OPENSSL 3.5`, `OQS`, `OQS_provider`
`./openss3_liboqs_oqsprovider.sh`
- Run from reporoot e.g `SPRK/`

### 2. BUILD
1. Client && Server && KEYGEN
`./build_cmake.sh` | 
- Runs cmake to build client && server KEYGEN bin's ... nothing else todo if DEPS setup.
find the executeables after build w `./build_cmake.sh` ...
```
✔ ~/Desktop/SPRK/bin [main|● 6✚ 4…1] 
00:28 $ ls -la
total 27868
drwxrwxr-x 2 mmmm mmmm     4096 Jan 13 00:27 .
drwxrwxr-x 9 mmmm mmmm     4096 Jan 13 00:26 ..
-rwxrwxr-x 1 mmmm mmmm 15295608 Jan 13 00:27 client
-rwxrwxr-x 1 mmmm mmmm 11518480 Jan 13 00:26 server
-rwxrwxr-x 1 mmmm mmmm  1705840 Jan 13 00:26 user_keygen
```

### 3. KEYGEN && CERTGEN
1. Generate Client user keys `tools/keygen.cpp` (needs `openssl 3.5`, use wrapper script on systems w.o)
```
✔ ~/Desktop/SPRK/bin [main|● 6✚ 4…1] 
00:27 $ ./user_keygen 
Usage: keygen <base_name> [--raw]
  --raw   also generate .sk.raw (old raw binary format)
```

2. Generate Server certs
`./generate_pq_certs.sh` | output to `sample/sample_test_cert/`

### 4. UNIT
`./unit.sh` | todo update! Supposed unit test for client and server. Run from reporoot e.g `SPRK/`
- Todo keygen unit test.

### 5. RUN
- run wrapper files... Run from reporoot e.g `SPRK/`
1. Server
```
✘-1 ~/Desktop/SPRK/bin [main|● 6✚ 4…1] 
00:27 $ ./server 
Usage: chat_server <port>
```
`./server.sh` | ip/ url harcoded in serc/server/main.cpp ; port in wrapper file `server.sh`
or 
`./bin/server 1566`
- If `openssl 3.5 w oqs support` present 

2. Client
```
✘-1 ~/Desktop/SPRK/bin [main|● 6✚ 4…1] 
00:30 $ ./client
Usage: chat_client <server_ip> <server_port> <username> <private_key_path> [--sessionid <id>] [--debug]

Runtime commands:
help                      show commands
q                         quit
list | list users         list connected users
pubk <username>           fetch user public key
<fp[,fp...]> <message>    send message to peer(s)

```
`./client.sh ron sample/ron.sk.pem sample/sample_test_key/ron.crt -sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug`
[this starts a specific sessionid or joins a specific sessionid]
or 
`./bin/client.sh ron sample/ron.sk.pem sample/sample_test_key/ron.crt -sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz --debug`
If `openssl 3.5 w oqs support` present . On systems without `openssl 3.5` for `bin/client`, `bin/server`

### 6. TIDY
`./clang-format_clang-tidy.sh src/` == output to `$(pwd)/clang_tidy_output` == Formats `C++` files with clang-format and runs clang-tidy on the original sources.

### 7. CLEAN
1. 
`./clean_cmake.sh` 
- cleanup build dirs of client and server.



## AI GENERATED TEMP README

## KEYGEN
```
keygen (native OpenSSL-based):Generates mldsa87 keypair using OpenSSL's EVP API (no liboqs needed — lighter, more future-proof since OpenSSL 3.5 has native PQ support).
Saves the private key in PEM format as .sk (compatible with your code's load_pqsig_keypair — it handles PEM).
Automatically creates a self-signed .crt using the same key (for TLS client auth).

One command: 
./keygen ron → ron.sk + ron.crt.
Throws errors if anything fails (e.g., algorithm not available).
Still PQ-safe (uses ML-DSA-87 for sig).

Key benefits:
Simpler for users: 
One tool/call generates everything needed (key for E2E protocol + cert for TLS).
No liboqs dependency: Relies on your existing OpenSSL 3.5.5 setup.

Secure by default: 
Self-signed cert is fine for TOFU (server accepts it, protocol verifies fp).

```

## CLIENT && SERVER
```
What the Program Does
This is a real-time, end-to-end encrypted chat application with a client-server architecture. 
It's designed for secure messaging using post-quantum cryptography (PQ crypto) to resist future quantum attacks. 
The server acts as a relay for messages but doesn't decrypt them—encryption is purely client-side. 

Key features include:

Multi-user sessions where clients join with usernames and public keys.
Automatic key exchanges for shared secrets, with periodic rekeying for forward secrecy.
Message encryption with replay protection, sequence numbers, and rate limiting.
Fingerprint-based sender verification (displayed in chat for trust-on-first-use).
Basic commands like listing users or fetching public keys.
Resilience to disconnects/reconnects, with timeouts and backoff.

It's not a full production app (e.g., no persistence, offline delivery, or group chats beyond broadcasting), 
but it's a solid proof-of-concept for PQ-secure comms. 
The server handles coordination, while clients manage the crypto-heavy lifting.
High-Level Flow
The app follows a classic TCP/TLS-based client-server model, 
with a custom protocol for messages (HELLO for handshakes, CHAT for messages, etc.). 

Here's the step-by-step flow:

Server Startup:
Initializes TLS context with OpenSSL, loading certs/keys and setting PQ-hybrid key exchange (X25519 + ML-KEM-768).
Creates a non-blocking TCP listen socket on a specified port.
Enters a select()-based event loop to handle incoming connections and client data.

Client Connection and Handshake:
Client loads identity keys (ML-DSA-87 private/public) from PEM files and generates ephemeral keys (Kyber512).
Establishes a TLS connection to the server (non-blocking, with retry on WANT_READ/WRITE).
Sends a HELLO message: Includes username, ephemeral public key, 
identity public key, signature, and optional session ID.
Server accepts TLS connections, peeks/reads frames, parses HELLO, validates signature/username, 
registers the client in a session (tracked by fingerprints/nicks).

Server broadcasts the new HELLO to peers (stripping sensitive encaps data for existing clients) 
and sends existing HELLOs to the newcomer.
Clients perform KEM (Kyber512): Initiator (lower fingerprint) encapsulates, 
responder decapsulates; derives shared key via HKDF.
Once shared key is established (marked "ready"), clients can chat bidirectionally.

Messaging:
Sender encrypts message with AEAD (using shared key, nonce from seq, 
AAD with fingerprints/seq).
Builds CHAT frame with ciphertext, seq, nonce, etc., and sends via TLS.
Server relays CHAT to destination (by nick or fingerprint prefix), without decrypting.
Receiver decrypts, checks seq (anti-replay/jitter), rate limits, and displays with timestamp/sender fingerprint.

Ongoing Management:
Rekey every 1024 messages: Rotate ephemeral keys, re-do KEM.
Timeouts: Drop stale peers after 60s inactivity.
Disconnects: Clean up sessions, close sockets/SSL.
Client reconnects with backoff (up to 10 attempts, exponential delay).
Commands: LIST_REQUEST for user list, PUBKEY_REQUEST to fetch keys.

Shutdown:
Graceful TLS shutdown, free resources, unload providers.


The flow emphasizes security: All transport is TLS-protected, app-layer crypto is PQ-safe, 
and there's no server trust for message content.

Technologies Used

Language/Standards: C++23 (uses ranges, noexcept, structured bindings; modern containers like unordered_map/set).
Networking: POSIX sockets (TCP, non-blocking with fcntl/select), Arpa/inet for addressing.
Crypto Libraries:
OpenSSL 3.5 (with oqsprovider for PQ support): Handles TLS 1.3, hybrid KEM (X25519MLKEM768), 
ciphers like AES-256-GCM.
liboqs (via OpenSSL provider): PQ algos like Kyber512 (ML-KEM) for key encapsulation, 
ML-DSA-87 (Dilithium) for signatures.

Custom utils: HKDF for key derivation, AEAD for encryption, SHA256 for fingerprints, Base58 for session IDs.

Build/Tools: CMake for compilation, shell scripts for testing 
(e.g., client.sh/server.sh).
Other: STL for data structures/algorithms, chrono for timings, 
mutex/atomic for threading (reader/writer threads in client).

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