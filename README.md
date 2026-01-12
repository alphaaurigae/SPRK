# SPRK-Chat

- Experimental ... 

(LLM GENERATED README)

**Post-Quantum End-to-End Encrypted Chat**


## REPO / scripts, helper tools NEED TIDY UP ....

# AI GENERATED TEMP README

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