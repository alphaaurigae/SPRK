# SPRK-Chat Client & Keygen — C++23 Implementation Plan (Ubuntu 26.04)

Companion to `audit_code_bestpractice.md`, `guidiance.md`, and `server_elixir_grid_plan.md`. This is the
prototype-phase plan for hardening `src/client/*` and `src/user_keygen/*` in place (C++23, staying in this
language per your stated preference and per `guidiance.md`'s recommendation that the client does not have the
server's structural concurrency problem), targeting Ubuntu 26.04 LTS, and making the specific, evaluated call on
whether keygen should merge into the client for a large-scale deployment.

---

## 1. Target stack on Ubuntu 26.04

| Layer | Choice | Why |
|---|---|---|
| Compiler | Clang (project default, `USE_CLANG=ON`) or GCC 15.2 | Ubuntu 26.04 ships GCC 15.2 by default and current LLVM/Clang in the archive; both comfortably exceed the CMakeLists' Clang≥14/GCC≥11 floor, and both have full C++23 support — re-verify the floor in `CMakeLists.txt` can be raised now that 26.04 is the baseline (no need to support GCC 11/Clang 14 as a minimum any more if 26.04 is the only target) |
| Language standard | C++23, unchanged | already your default |
| TLS/PQC crypto | **System `libssl-dev` (OpenSSL 3.5.5, native ML-KEM/ML-DSA/SLH-DSA), `apt install libssl-dev`** | Ubuntu 26.04 ships this by default (verified: `openssl 3.5.5-1ubuntu3.3` in `resolute`) — this retires `openss3_liboqs_oqsprovider.sh` entirely: no custom OpenSSL build, no liboqs, no oqs-provider, matching your stated "available Ubuntu package > source" priority exactly |
| Async I/O | Asio (standalone), `apt install libasio-dev`, or vendor the header-only release if a newer minor than the archive's is needed | unchanged from current project; per your library priority this stays below Poco |
| Utility/data | Poco (`apt install libpoco-dev`) | unchanged; verify the exact Poco version 26.04 ships and whether it meets project needs before deciding to build from source — check with `apt-cache policy libpoco-dev` on the actual 26.04 system rather than assuming, since this document cannot see the real package version at time of writing |
| Build | CMake ≥ 3.28 (already required), Ninja generator recommended for iteration speed | |
| Static/dynamic analysis | `clang-tidy` (checks already specified in your standing instructions: `modernize-*, performance-*, bugprone-*, readability-*, cert-*`), `cppcheck`, `clang --analyze` | wire into CI, not just local runs |
| Sanitizers | Full ASan+UBSan+LeakSan build (already in `CMakeLists.txt`) run as a CI job against the promoted `audit_code_bestpractice.md` §6 tests, plus a **separate** TSan build (cannot combine with ASan) for anything touching shared client-side state | this is the concrete fix for "sanitizers are configured but nothing runs them in CI" (audit §4, last bullet) |
| Fuzzing | `libFuzzer` (ships with Clang) harness for `shared_net_common_protocol.h::parse_payload` and any future S2S/grid-aware parsing | this is the single most attacker-facing code path (parses untrusted bytes straight off the network) and currently has zero fuzz coverage; highest security ROI per engineering hour of anything in this table |
| Secure key storage | OpenSSL secure heap (`CRYPTO_secure_malloc_init`) or a `mlock`-backed allocator for identity secret keys in memory; at-rest passphrase-based encryption of `*.sk.pem` evaluated for a later phase (see §6) | direct fix for audit §2.3 |
| Packaging | `CPack` → `.deb` for Ubuntu 26.04; optional minimal container image for headless test/bot clients used in the server's `docker-compose` integration tests (`server_elixir_grid_plan.md` §8) | |

---

## 2. What does *not* change

- The wire protocol (`shared_net_common_protocol.h`), except for the additive "protocol v2" fields agreed with the
  server plan (`server_elixir_grid_plan.md` §2/§5 Phase C): AEAD key derivation gets a direction label, and the
  `MSG_HELLO` signature payload gains `username`. Both are changes to *what bytes get hashed/derived*, not to the
  frame layout itself.
- The overall client architecture (TLS session → `MSG_HELLO` exchange → KEM encaps/decaps → AEAD chat) — this
  project's protocol design is sound; the audit's findings are implementation bugs in it, not indictments of the
  design shape.
- Ubuntu 26.04's OpenSSH already ships PQC-by-default (OpenSSH 10.2, PQC hybrid key exchange on by default per
  26.04.1) — cited here only as external validation that "PQC as the unremarkable default" is exactly the
  direction the wider ecosystem is moving, which is the same direction this plan takes the client.

---

## 3. Hardening/refactor plan, in dependency order

This sequence exists so each step leaves the client in a buildable, testable state — do not skip ahead to §3.5
before §3.1–§3.4 are done and tested, since later steps assume the earlier fixes are in place.

### 3.1 Apply the five empirically-confirmed critical fixes (`audit_code_bestpractice.md` §1)

- §1.1 nonce/key direction split — implement as HKDF `info` labels keyed by initiator/responder role (the
  existing `bool initiator = my_fp_hex() < peer_fp_hex;` convention already used for KEM-role selection is the
  natural place to source the direction bit from — reuse it, don't invent a second convention).
- §1.2 remove the double-lock in `rotate_ephemeral_if_needed`.
- §1.3 is server-side (already covered in `server_elixir_grid_plan.md`) — no client change needed, but the
  client-side symptom (peer appears to "hang" mid-conversation because the server's stale-registry bug swallowed a
  rename) should be added as a client-side integration test once talking to the new server, so a regression there
  is caught from the client's perspective too.
- §1.4 is server-side — same note as above, add an integration test, no client code change required.
- §1.5 seq/jitter window — decide alongside the server (`server_elixir_grid_plan.md` §5 Phase C) whether the full
  window is honoured or the constant/documentation is shrunk to match; implement whichever was decided, on the
  client's `handle_sequence`/`is_sequence_gap_valid` equivalents, identically to the server's choice.

### 3.2 Collapse the crypto layer onto native OpenSSL 3.5 EVP calls (retire liboqs/oqs-provider)

This is the client-side half of `guidiance.md` §2/Phase 1, and it directly removes audit §2.1/§2.2/§2.7:

- **KEM:** replace `shared_common_crypto.h`'s `OQS_KEM_*` calls with `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate`
  against an `EVP_PKEY` created via `EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)` (or `ML-KEM-1024`
  — see §3.3 for the parameter-set decision). This also resolves the security-level mismatch (audit §2.1) and the
  algorithm-name breakage risk (audit §2.2) in one change, since `"ML-KEM-768"`/`"ML-KEM-1024"` are the current,
  native, standardized OpenSSL names — no liboqs alias table to fall out of sync with.
- **Signatures:** replace `pqsig_sign`/`pqsig_verify`'s `OQS_SIG_*` calls with `EVP_PKEY_sign`/`EVP_PKEY_verify` or
  `EVP_DigestSign`/`EVP_DigestVerify` against the **same `EVP_PKEY` object** that `shared_net_key_util.h` already
  parses from the PEM file via `PEM_read_bio_PrivateKey` — deleting the `EVP_PKEY_get_raw_private_key`/
  `get_raw_public_key` raw-byte extraction step entirely. This is the change that makes audit §2.7's "two
  independent PQC implementations must agree on byte layout" risk **structurally absent** rather than merely
  untested: there is only one library (OpenSSL) and one `EVP_PKEY` object touching the key material from parse to
  sign, ever.
- **Ephemeral KEM keypairs:** generate via `EVP_PKEY_keygen` against the same `"ML-KEM-768"`/`"ML-KEM-1024"` name,
  matching what `user_keygen` already does for the identity key's `"ML-DSA-87"` — the whole project now generates
  every PQC keypair the same way, through the same API.
- **Delete:** `openss3_liboqs_oqsprovider.sh`'s liboqs and oqs-provider build steps; the `USE_LIBOQS` CMake
  option and its `#ifdef` branches in `shared_common_crypto.h`/`shared_net_key_util.h`; the `oqs/oqs.h` include
  and `OQS_KEM_new`/`OQS_SIG_new` calls project-wide. `CMakeLists.txt`'s `find_library(OQS_LIB ...)` block and
  `target_compile_definitions(... PRIVATE USE_LIBOQS)` line go away with it — the build now only needs
  `find_package(OpenSSL 3.5 REQUIRED)`, which is already present.
- **Verify, don't assume:** after this change, run `openssl list -kem-algorithms | grep -i mlkem` and
  `openssl list -signature-algorithms | grep -i mldsa` against the Ubuntu 26.04 system OpenSSL before wiring any
  code to it, exactly as `guidiance.md` §1 item 4 asked for the old liboqs path — the same discipline applies to
  confirming the *new* path resolves correctly on the real target OS before building on top of it.

### 3.3 Fix the KEM/signature security-level mismatch (audit §2.1)

Move from `ML-KEM-512` (Kyber512-equivalent Category 1) to **`ML-KEM-768`** at minimum, evaluate **`ML-KEM-1024`**
to match `ML-DSA-87`'s Category 5 if the larger wire size (a few hundred extra bytes per `MSG_HELLO`) is
acceptable — for a global platform where `MSG_HELLO` is not the hot path (it happens once per session plus once
per 1024-message rekey, not per chat message), the larger, better-matched parameter set is the recommended
default rather than a size-optimized compromise. Update `ALGO_KEM_ALG_NAME`/`KEM_ALG_NAME` accordingly and bump
the protocol's `PROTO_VERSION`/capability negotiation together with the §3.1 wire-affecting fixes, in the same
release, so there is exactly one "protocol v2" cutover to test rather than several staggered ones.

### 3.4 Fix the remaining audit findings that are cheap and purely additive

- §2.3 — replace every `std::vector<unsigned char>(secure_vector.begin(), secure_vector.end())` copy-for-a-span
  call site with a direct `std::span<const unsigned char>(secure_vector)` construction (no copy; the function
  signatures that need this already exist). Consider making `secure_vector`'s copy constructor `= delete` (move-only)
  specifically so any *future* accidental copy is a compile error instead of a silent hygiene regression — this is
  a cheap, permanent guardrail once the current call sites are fixed.
- §2.4 — extend the HELLO signature payload to include `username` (coordinate with the server plan's Phase C, see
  §2 above).
- §2.5 — add the TLS-cert-CN-equals-claimed-username check (this one is entirely server-side enforcement; no
  client change beyond making sure the client's TLS certificate's CN is actually provisioned to equal its
  username, which is a keygen/provisioning concern — see §5).
- §3.1 (protocol header) — switch `ensure_range`'s check to the overflow-safe form.
- §3.2 — give `Parsed` (or its client-side equivalent after any refactor) a real discriminated type per message
  kind instead of overloading `identity_pk` to mean "pubkey" or "fingerprint" depending on context.
- §3.3 — drop the plain-`X25519` fallback from the client's TLS group list; require the hybrid group only (both
  ends are project-controlled, so there's no interop reason to allow the downgrade).
- §3.6 — either wire the CLI's `<client_cert.crt>` argument through for real, or remove it from the usage string;
  unify the two inconsistent argument-count checks in `client_cmdline_util.h`/`main.cpp` into one, checked before
  any file I/O happens.
- All of §4 (style/clang-tidy items) — clear these opportunistically while touching the surrounding code in the
  steps above; they are not worth a dedicated pass, but a `secure_vector`-inherits-from-`std::vector` composition
  rewrite is worth doing in the same commit as §3.4's `secure_vector` copy-constructor change, since you're
  already touching that type.

### 3.5 Promote the audit's reproduction tests into real CI

Move the six programs from `audit_code_bestpractice.md` §6 into `tests/` as real CTest targets: the protocol
round-trip and seq/jitter tests are pure logic and port directly; the nonce-reuse, deadlock, and
cleanup-ordering reproductions become **regression tests that must now assert the fixed behaviour** (e.g., the
nonce-reuse test should now assert `nonce_from_alice != nonce_from_bob` and fail the build if that ever regresses)
rather than assert the bug — this is the mechanism that keeps §3.1–§3.4 fixed permanently instead of
"fixed until someone touches that code again."

---

## 4. Grid-awareness on the client side (kept deliberately minimal)

Per `server_elixir_grid_plan.md` §4, federation is a server-to-server concern; the client's job is much smaller
than it might first appear:

- **Multi-endpoint failover.** Provision the client with more than one entry point for its home grid unit (a
  small ordered list, or a DNS lookup returning several addresses for the unit's load-balancer/anycast VIP) and
  extend the existing `run_reconnect_loop`/backoff logic to try the next known endpoint after exhausting retries
  against the current one, before giving up. This is a small, additive change to `main.cpp`'s reconnect loop, not
  a redesign.
- **Identity stays a plain fingerprint; add a human-readable home-unit hint for the prototype.** Keep the fingerprint
  as the portable, grid-wide identity (unchanged). For the username namespace, adopt a lightweight,
  Matrix-`@user:server`-style convention **within the existing plain-string `username` field** for the prototype
  phase — e.g. `alice@eu1` — parsed structurally later if/when the protocol grows a dedicated field; this avoids a
  wire-format change while still letting `list users`/`pubk <user>` disambiguate people across grid units in
  practice.
- **No client-side routing logic for cross-unit delivery.** The client always talks to its own home unit; a
  message addressed to a fingerprint homed elsewhere is the home unit's S2S problem to solve
  (`server_elixir_grid_plan.md` §4.2), not the client's. This is the direct payoff of keeping the wire format
  stable across the whole migration — the client's conversion plan does not grow in proportion to the server's
  federation complexity.
- **Directory/bootstrap lookup (evaluate, don't build yet).** A production global platform eventually needs a way
  for a fresh client to discover "which grid unit is my account's home" without hardcoding it — analogous to
  Matrix's server-discovery well-known file or a simple signed directory service. Flag this as an explicit,
  named, not-yet-built dependency for anything past the prototype phase (§6), so it isn't silently assumed to
  already exist when planning a real launch.

---

## 5. Keygen merge evaluation — recommendation

**Question asked:** should `user_keygen` be merged into the `client` binary for a large-scale chat application?

**Recommendation: merge the *code*, keep both *entry points*.**

- **Merge the code** into a shared static library (e.g. `libsprk_identity`: key generation, PEM load/parse,
  fingerprint computation, the now-unified OpenSSL-native EVP_PKEY handling from §3.2) linked by **both** the
  standalone `user_keygen` executable and a new `client --provision`/first-run auto-provisioning path inside the
  `client` binary. This directly fixes a real risk in *not* merging: two separate implementations of "parse a
  ML-DSA-87 key and compute its fingerprint" is exactly the kind of duplicated, drift-prone crypto plumbing this
  audit already found once (audit §2.7) — don't recreate that pattern deliberately while fixing it elsewhere.
- **Keep the standalone `user_keygen` executable** as a thin CLI wrapper over the shared library, because a
  large-scale deployment needs it for use cases the interactive client should not silently perform on its own:
  automated/fleet provisioning (issuing keys for many accounts at once, e.g. enterprise or bot accounts), key
  rotation and recovery tooling, scripted testing/CI (this project's own `unit.sh` needs exactly this today), and
  any headless/server-adjacent provisioning workflow. Folding all of that into the interactive chat client's
  binary would either bloat it with functionality most end users never touch, or force those operational
  workflows to reverse-engineer the client's provisioning flags — neither is a good trade for "large scale."
- **Add, inside `client`, a first-run auto-provisioning path** (`libsprk_identity`'s keygen called automatically
  when no identity key is found at the expected path, prompting for a username, generating the keypair and
  self-signed identity cert locally) as the **default onboarding UX** for end users — this is the part of "merge"
  that actually matters for a consumer-facing global platform: nobody signing up for a global chat app should have
  to separately run a `keygen` tool before their first launch. This is additive to the client, not a removal of
  the standalone tool.
- **Net effect:** one implementation of identity-key handling (`libsprk_identity`), two front doors to it — a
  silent, first-run path inside `client` for ordinary users, and the explicit `user_keygen` CLI for every
  operational/bulk/scripted use case that a platform actually serving millions of accounts will need on day one of
  real operations, even though the prototype phase itself may only ever exercise the CLI path via `unit.sh`.

---

## 6. Explicitly deferred (name it, don't lose track of it)

These are legitimate "not for the prototype" decisions, listed here so they are deferred on purpose rather than
forgotten:

- **At-rest protection for `*.sk.pem`.** Prototype phase: unchanged (plain PEM on disk, matching today).
  Pre-launch requirement: passphrase-derived encryption of the private key at rest (OpenSSL's own encrypted PKCS#8
  output, or an OS keychain/Secret-Service integration) — plain, unencrypted long-term identity secret keys on
  disk are not an acceptable end-state for a platform carrying millions of real users' identities, even though
  they are a reasonable prototype-phase simplification matching the project's current scope.
- **Grid directory/bootstrap service** (§4, last bullet) — needed before real multi-operator federation is
  user-facing, not needed for the Phase A–E validation in `server_elixir_grid_plan.md`, which can hardcode two
  known grid units' addresses for testing.
- **Mobile/desktop packaging beyond `.deb`** — out of scope for this document, which is scoped to the Ubuntu
  26.04 development/reference-implementation target; a real global platform will eventually need native
  mobile/desktop builds of the same `libsprk_identity` + protocol/crypto core, which is a strong argument for
  keeping that core as a portable library (already true of the shared/ directory's design) rather than something
  that grows Ubuntu-specific or Poco/Asio-specific assumptions baked in at a low level.

---

## 7. Validation matrix against the server plan

| Server plan phase (`server_elixir_grid_plan.md` §5) | Corresponding client-side check |
|---|---|
| Phase A (TLS + framing skeleton) | Fixed client connects, completes `x25519mlkem768` + ML-DSA mutual TLS handshake, frame echo round-trips |
| Phase B (HELLO, single node) | Client's `list users`/registration flow works unchanged against the new server |
| Phase C (chat relay + protocol v2 crypto fixes) | Full `unit.sh`-equivalent triangular messaging scenario passes with **both** sides running the direction-split nonce/username-signed HELLO fixes; nonce-reuse regression test (§3.5) stays green |
| Phase D (single-cluster horizontal scale) | Client's reconnect/backoff logic recovers a connection when its current node is killed under load |
| Phase E (S2S federation) | Two clients on different grid units complete a full triangular-style conversation across the federation boundary |
| Phase F (capacity) | Headless client build (§1 packaging) used as the synthetic load generator |
