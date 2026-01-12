
the new keygen (native OpenSSL-based):Generates mldsa87 keypair using OpenSSL's EVP API (no liboqs needed — lighter, more future-proof since OpenSSL 3.5 has native PQ support).
Saves the private key in PEM format as .sk (compatible with your code's load_pqsig_keypair — it handles PEM).
Automatically creates a self-signed .crt using the same key (for TLS client auth).
One command: ./keygen ron → ron.sk + ron.crt.
Throws errors if anything fails (e.g., algorithm not available).
Still PQ-safe (uses ML-DSA-87 for sig).

Key benefits:Simpler for users: One tool/call generates everything needed (key for E2E protocol + cert for TLS).
No liboqs dependency: Relies on your existing OpenSSL 3.5.5 setup.
Secure by default: Self-signed cert is fine for TOFU (server accepts it, protocol verifies fp).
Compatible with your code: .sk is loadable as before; .crt is PEM for SSL_CTX_use_certificate_file.

Compile the new one with:


clang++ -o keygen keygen.cpp -I/usr/local/openssl-3.5/include -L/usr/local/openssl-3.5/lib64 -lssl -lcrypto

Test: ./keygen ron → check ron.sk (PEM private key) and ron.crt (self-signed cert).

for clients, a self-signed cert is sufficient because:Server can accept self-signed client certs (change to SSL_VERIFY_PEER without FAIL_IF_NO_PEER_CERT and no CA load — see code below).
TOFU security comes from protocol: Client hello signed with ML-DSA-87 key (from .sk), server verifies fp — no need for CA-signed client cert.
This keeps mass-user simple: No CA dependency for clients.

User generates keys/cert (one command):./keygen <username> → gets <username>.sk (for protocol/E2E) + <username>.crt (for TLS auth).
Stores in ~ or app dir.

Server admin sets up (one-time):Run cert gen script: Generates CA.crt, server.crt, server.key.
Server code uses them (hardcoded paths OK for server).

User runs client (simple command):./client.sh <server> <port> <username> <path/to/username.sk> <path/to/username.crt>
Or wrapper auto-fills paths based on username.

Connection:TLS: Client presents self-signed .crt (server accepts), verifies server with hardcoded CA.crt.
Protocol: Hello signed with .sk key — TOFU on fp for E2E trust.

Security: PQ TLS (hybrid KEM/sig) + PQ E2E (ML-DSA-87 sig, Kyber KEM, AEAD encrypt). TOFU prevents MITM.
Easy for mass users: Keygen once, then chat. No CA manual trust.

. Why This Is Mass-User Ready & SecureWorkflow: User runs keygen → gets .sk + .crt. Copies to device. Runs client with paths. Done.
Security: TLS protects transport (PQ). Protocol E2E with TOFU fp (user checks fp once).
No cert script for users: Only server admin runs it for CA/server cert.
Scale: Millions can generate unique keys/certs locally — no central CA bottleneck.

Test the new keygen, then client/server with self-signed. If handshake works, you have the app!

./client 127.0.0.1 1566 ron ./ron.sk ./ron.crt