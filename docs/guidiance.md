# SPRK-Chat — Path Forward Guidance

Companion to `audit_code_bestpractice.md`. That document is the "what's wrong, proven"; this one is "what to do
about it, in what order, and in which language/runtime." Read §1 first regardless of anything else decided below —
it is independent of any C++/Rust/Elixir decision.

---

## 1. Urgent, do-before-anything-else fixes

These are ordered by how much damage they cause if left in place, not by how much effort they take (most are
small, targeted patches — the actual redesign work is in §3/§4).

1. **Fix the nonce derivation (`audit` §1.1).** This is a full break of the E2E channel's confidentiality and
   authenticity as shipped. Nothing else in this list matters if this isn't fixed — every other improvement is
   protecting a channel that currently leaks plaintext to any two-way conversation partner pair. Minimum viable
   fix: derive `K_send`/`K_recv` (or fold a direction bit into the nonce HMAC input) so the two directions never
   share a nonce space. Do this before writing a single line of Rust/Elixir/anything else — it must be correct in
   whichever language ships next, and it's cheap to fix now to validate the approach.
2. **Fix the `rotate_ephemeral_if_needed` double-lock (`audit` §1.2).** One-line-scope fix; without it the client
   hangs forever at message 1024 to any peer, which will make every other test you run after this audit look
   flaky/broken for an unrelated reason.
3. **Fix `cleanup_old_nickname`'s ordering bug (`audit` §1.3).** Also small; without it every load/stress test of
   the server will show unbounded memory growth that has nothing to do with real traffic volume and everything to
   do with this bug, which will otherwise waste time being mis-diagnosed as a scaling problem.
4. **Verify the `Kyber512` algorithm-name breakage (`audit` §2.2) before doing a fresh build.** Run
   `openssl list -kem-algorithms` (with the built provider stack loaded) and confirm whether `Kyber512` or
   `ML-KEM-512` is what actually resolves against the pinned `liboqs_tag=0.15.0`. If `Kyber512` fails, the whole
   client is currently non-functional out of the box against its own documented build instructions — this needs
   to be known before investing further engineering time in the current C++ codebase, and before any Rust/Elixir
   rewrite decision, since it changes how much of the *existing* crypto plumbing is worth porting versus how much
   should be replaced outright with OpenSSL-native calls (§2 below makes the case that it should all be replaced
   anyway, but this tells you whether "replace" is optional or already forced).
5. **Serialize or strand-protect the server's shared state (`audit` §1.4).** Simplest immediate fix: run the
   server's `io_context` with a single thread until the rest of this document's recommendations are acted on. That
   trades away some throughput headroom you are not currently using safely anyway (the current multi-threaded
   config is unsafe, not merely "not yet optimized").
6. **Do not reuse the committed keys (`audit` §2.6) past this audit.** Treat `sample/sample_test_cert/ca.key` and
   every `*.sk.pem`/`*_tls.key` in the repository as burned. Regenerate everything before any test that leaves this
   machine, and add key material to `.gitignore` going forward.

None of the above require deciding anything about C++ vs. Rust vs. Elixir. Do them first, in the current codebase,
so there is a *correct* prototype to either keep hardening in C++ or to port from — porting a codebase with a live
crypto break just moves the bug to a new language.

---

## 2. What changed in the ecosystem since this project's crypto architecture was designed (2026 state of the art)

This project's build pipeline (`openss3_liboqs_oqsprovider.sh`: patch-build OpenSSL from source with
`enable-fips enable-ml-dsa`, then build liboqs from source, then build oqs-provider from source, three separate
repositories tracked by tag/branch) was the *correct* way to get ML-KEM/ML-DSA in 2023–2024, when OpenSSL itself
had no PQC support at all. That is no longer the situation, and it materially changes the recommended path
forward, independent of which language the project ends up in:

- **OpenSSL 3.5 (released April 8, 2025, LTS) ships ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205)
  natively**, with a real `EVP_PKEY` KEM API (`EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate`, added in 3.2/3.5) and
  ordinary `EVP_PKEY_sign`/`EVP_DigestSign` support for ML-DSA. No provider plugin is required for any of the three
  algorithm families this project uses or would want to use.
- **oqs-provider itself has been moving away from being necessary for these algorithms.** Starting at
  oqs-provider 0.9.0 (aligned with liboqs 0.13.0, May 2025), legacy pre-standard `Kyber`/`Dilithium` names are
  **disabled by default** in favour of the standardized `ML-KEM-*`/`ML-DSA-*` names — the project's own pinned
  `liboqs_tag=0.15.0` already post-dates this. liboqs 0.16.0 (July 2026) removed SPHINCS+ entirely. The direction
  of travel for the whole Open Quantum Safe project is "prototype the algorithms NIST hasn't standardized yet, and
  otherwise get out of the way of native OpenSSL/BoringSSL/wolfSSL support" — wolfSSL, for one data point, publicly
  deprecated its liboqs dependency in February 2025 in favour of shipping Kyber/Dilithium natively for exactly this
  reason.
- **Practical conclusion for this project, regardless of language:** stop building a custom OpenSSL fork and
  linking liboqs + oqs-provider for ML-KEM/ML-DSA. Use a stock, unpatched OpenSSL 3.5+ (available as an upstream
  release tarball, and this is exactly the kind of dependency the user's own stated priority order — "available
  Ubuntu package > source" — argues for as soon as a 24.04-compatible 3.5+ package or PPA is available; until then,
  a vanilla `./Configure && make` of stock OpenSSL 3.5 is still a single build instead of three, with no patches).
  This removes an entire repository (liboqs), an entire repository (oqs-provider), and the custom `enable-fips
  enable-ml-dsa` OpenSSL patch build from the toolchain, collapsing `openss3_liboqs_oqsprovider.sh` to
  "install/build one upstream OpenSSL." It also resolves `audit` §2.2 and §2.7 at the same time: there is no
  longer a second, independent PQC implementation (liboqs) whose raw-key byte layout has to agree with OpenSSL's
  for identity keys, because signing goes through the *same* OpenSSL EVP_PKEY object that parsed the PEM file, and
  the KEM ops go through the *same* library's native KEM API instead of a hand-rolled `OQS_KEM_new("Kyber512")`
  call to a name that may not even resolve any more (`audit` §2.2).
- **On the transport (TLS) side, this project is already aligned with 2026 best practice**: `X25519MLKEM768` is
  the exact hybrid group name OpenSSL 3.5+, rustls/aws-lc-rs, and Erlang/OTP 29's `ssl` app all standardized on,
  and OTP 29 made it the **default-preferred** TLS 1.3 group in 2026. Nothing needs to change about the choice of
  group; only the fallback-to-plain-`X25519` entry (`audit` §3.3) needs tightening.

---

## 3. Should the project move to Elixir (server) / Rust (client)? — Direct answer

**Short answer: for the server, yes, and the 2026 ecosystem now makes this a genuinely low-risk move, not just an
academic "Erlang is nice for concurrency" argument. For the client, Rust is defensible but less urgent, and the
honest answer is that C++23 is *also* viable for the client if — and only if — the specific defects in this audit
are fixed and the project adopts the process discipline (sanitizers-in-CI, code review for lock/ownership
patterns) that would have caught them. Below is the reasoning, not just the verdict.**

### 3.1 Why the server case for Elixir/OTP is strong, specifically because of what this audit found

Every one of the server-side critical/high findings in the audit — §1.3 (stale-state accumulation because
per-connection mutable state is shared and mutated by more than one code path), §1.4 (data races because
per-connection state is shared across OS threads with no isolation) — is a bug *category*, not just an instance,
that the actor/process model Erlang/OTP is built around eliminates structurally rather than by discipline:

- In an OTP design, each client connection is its own **process** with its **own isolated heap**. There is no
  `sessions` map shared by reference across worker threads for multiple connections to race on, because there is
  no shared mutable memory between processes at all — communication is by message passing. §1.4 (the
  ThreadSanitizer-confirmed data race) cannot occur in the equivalent OTP design; it is not "handled more
  carefully," it is a class of bug the runtime does not offer a way to create.
- OTP's supervision trees give "let it crash" isolation: if a single connection's handler process hits a bug
  (which will always happen, in any language), it terminates and gets restarted by its supervisor **without
  affecting any other connection or the rest of the server**. The current C++ server has no such isolation — an
  uncaught exception or corrupted shared state from one connection's handling (see §1.4) can bring down the
  process serving every other connected user. For a relay server whose entire job is "stay up and keep routing,"
  this is close to the single most load-bearing property you can ask a runtime to give you for free.
- **The specific cryptography is no longer a reason to avoid Elixir.** As of Erlang/OTP 28.1 (2025), the `crypto`
  application added `crypto:sign/4`/`crypto:verify/5` for `mldsa44`/`mldsa65`/`mldsa87` and
  `crypto:encapsulate_key/2`/`crypto:decapsulate_key/3` for `mlkem512`/`mlkem768`/`mlkem1024` — **directly backed
  by the same OpenSSL 3.5 this project already targets**, with no NIF/FFI risk beyond what Erlang's `crypto` app
  has always carried (it has always been an OpenSSL binding). As of OTP 29 (2026), the `ssl` application supports
  ML-DSA certificates and ML-KEM key exchange groups in TLS 1.3 directly, and **`x25519mlkem768` is now the
  default-most-preferred key-exchange group** — i.e. the exact hybrid group this project already uses is now the
  *out-of-the-box default* in Erlang's TLS stack. This means an Elixir server could get bit-identical cryptographic
  primitives to the current C++ server (same OpenSSL engine underneath), while gaining process isolation, with
  essentially zero custom crypto-glue code — no liboqs, no oqs-provider, no hand-written OQS_KEM/OQS_SIG wrappers,
  no PEM-parsing-then-raw-key-extraction dance (`audit` §2.7). `crypto:sign(mldsa87, none, Msg, PrivKey)` and
  `ssl:connect(..., [{versions, ['tlsv1.3']}, {supported_groups, [x25519mlkem768]}, ...])` replace essentially all
  of `shared_common_crypto.h`, `shared_net_tls_context.h`, and `shared_net_key_util.h` combined.
- Ranch/Cowboy or a hand-rolled `gen_statem`-per-connection design maps almost mechanically onto the current
  protocol's shape (one process per TLS connection, a registry keyed by fingerprint/username instead of the
  hand-rolled `unordered_map<string, ClientState>` + manual mutex discipline this audit found broken), and
  distribution/clustering (multi-node BEAM) is a natural, low-effort extension if the project ever needs to shard
  the relay across more than one node — not a requirement today, but worth knowing it's "free" later rather than a
  future rewrite.

**This is not "rewrite it because Erlang is fashionable."** It is: five of this audit's findings are exactly the
bug categories BEAM's process model was designed to make structurally impossible, and the 2026 native-crypto
landscape means adopting Elixir no longer means giving up parity with the C++ implementation's crypto stack or
adding new FFI/NIF risk to get PQC. That combination — bug-class elimination *and* crypto parity with no new
dependency risk — is a genuinely strong, not just theoretical, argument specifically for **this** project, at
**this** point in time (this would have been a much weaker argument in 2023, when Erlang's PQC story required a
third-party NIF).

### 3.2 Why the client case for Rust is real but less clear-cut

- **Transport-layer PQC in Rust is production-grade today**: rustls + aws-lc-rs supports `X25519MLKEM768` as a
  hybrid TLS 1.3 group, and it is **enabled and preferred by default** in current rustls (the `prefer-post-quantum`
  feature, on by default, reorders `aws_lc_rs::DEFAULT_KX_GROUPS` to put it first). This is at least as mature as
  the current C++ project's own TLS layer.
- **App-layer ML-DSA signing in the Rust TLS stack is explicitly still "unstable"/experimental** (aws-lc-rs's
  `aws-lc-rs-unstable` feature gate, as surfaced by `rustls-post-quantum`). A Rust client would, like the current
  C++ client, likely keep its E2E identity-signing logic **outside** the TLS crate, in a dedicated crate — the
  `ml-dsa`/`ml-kem` RustCrypto crates or `pqcrypto`/liboqs-rust bindings are the realistic choices there, and this
  is a very similar shape of "two libraries need to agree on key material" situation as the current project has
  today (`audit` §2.7), just with (mostly) memory-safe glue code holding it together instead of raw
  `EVP_PKEY_get_raw_*` extraction.
- **Rust's ownership/borrow-checker model would have caught, or made much harder to write, some but not all of
  this audit's client-side bugs**: the double-lock deadlock (§1.2) is *not* prevented by Rust's type system by
  itself (Rust's `std::sync::Mutex` is also non-reentrant, and re-locking it from the same thread also
  deadlocks — Rust prevents *data races*, not deadlocks, by design). What Rust *would* structurally prevent is the
  `secure_vector`-bypassed-by-copy pattern (§2.3) being invisible — a `Zeroizing<Vec<u8>>` (the `zeroize`/`secrecy`
  crate ecosystem) that is `!Copy` and consumed-by-value at API boundaries makes "oops, I copied the secret into a
  container that doesn't zero itself" a compile error rather than a silent runtime hygiene bug, which is a
  meaningful, specific win directly traceable to a finding in this audit. It would *not*, by itself, have prevented
  §1.1 (nonce reuse) or §1.5 (dead acceptance window) — those are protocol-design bugs, not memory-safety bugs, and
  no language prevents them; only a design review or a test suite does.
- **Practical verdict for the client:** Rust is a reasonable, forward-looking choice, and the ecosystem has matured
  enough (2025–2026) that it is no longer a risky bet purely on PQC library maturity grounds for the transport
  layer. But unlike the server case, the argument is "meaningfully better for some specific bug classes, and a more
  modern, actively-growing ecosystem," not "eliminates entire categories of what this audit actually found." A
  well-audited, sanitizer-clean C++23 client (i.e., this project's client with §1's fixes applied, plus the process
  discipline in §5 below) is a defensible thing to keep, especially given the user's own stated stack preferences
  (C++23 as default, specific library ordering, Poco/Asio already in use) and the fact that the *client* — unlike
  the server — does not have the multi-connection shared-mutable-state problem that makes the server case so
  clear-cut (a chat client is fundamentally single-session-at-a-time from its own perspective; there is far less
  concurrent shared state to get wrong than in the relay).

### 3.3 Recommendation

- **Server: migrate to Elixir/OTP.** The combination of (a) process-per-connection isolation eliminating this
  audit's two worst structural bug classes by construction, (b) OTP 28/29's native, OpenSSL-3.5-backed ML-KEM/
  ML-DSA support removing what used to be the main objection (no mature PQC story), and (c) "let it crash"
  supervision giving free fault isolation this project currently has none of, makes this the highest-confidence
  recommendation in this document.
- **Client: keep C++23 for now, with the fixes in §1 applied and the process changes in §5 adopted; treat a Rust
  client as a good *second-phase* target, not a blocker.** The client doesn't have the server's structural
  concurrency problem, C++23 with sanitizers-in-CI can genuinely reach a defensible security bar for a
  single-session interactive client, and it matches the user's stated toolchain preferences. Revisit Rust once the
  server migration has proven out the Elixir-side crypto interop (same wire protocol, same OpenSSL primitives) —
  at that point a Rust client is a comparatively low-risk follow-on, not a leap.
- **Either way, do §2's crypto-architecture simplification first, in whichever language ends up doing the crypto**
  — native OpenSSL 3.5 EVP calls for ML-KEM/ML-DSA, no liboqs/oqs-provider — because it is the correct move
  independent of the C++/Rust/Elixir decision, and it removes the specific breakage risk in `audit` §2.2 no matter
  which path is chosen next.

---

## 4. Concrete target architecture

```
┌─────────────────────────┐        TLS 1.3, X25519MLKEM768 (default)        ┌──────────────────────────────┐
│   Client (C++23 now /    │ ───────────────────────────────────────────▶  │   Relay server (Elixir/OTP)   │
│   Rust candidate later)  │ ◀───────────────────────────────────────────  │                               │
│                          │                                                │  - Ranch/Cowboy or gen_statem │
│  - OpenSSL 3.5 EVP_PKEY  │        MSG_HELLO / MSG_CHAT / MSG_LIST /      │    per-connection process     │
│    (ML-DSA-87 sign/verify│         MSG_PUBKEY_* frames (fixed, unchanged │  - Registry (fingerprint,     │
│    ML-KEM-768/1024       │         wire format from shared_net_common_   │    username) via :ets or a    │
│    encapsulate/decapsulate)        protocol.h, with §1.1/§2.4 fixes)     │    Registry, NOT shared mutable│
│  - Direction-separated    │                                                │    state across OS threads    │
│    AEAD keys (§1.1 fix)  │                                                │  - crypto:sign/verify(mldsa87)│
│  - zeroize-on-drop for    │                                                │    for any server-side signing│
│    secret material        │                                                │  - Supervisor tree: one crash │
└─────────────────────────┘                                                │    = one connection restarted │
                                                                             └──────────────────────────────┘
```

The wire protocol (`shared_net_common_protocol.h`'s frame format) does not need to change to make this migration
work — it is a reasonable, already-implemented, versioned binary protocol, and keeping it stable is what lets the
migration be done **server-first, client-second** (an Elixir server can talk to the existing, fixed C++ client
while the client-side rewrite is still just a "maybe, later" item), which is the lowest-risk sequencing.

---

## 5. Phased roadmap

**Phase 0 — Stop the bleeding (days, in the current C++ codebase).**
Apply `audit` §1.1–§1.5 fixes. Add the five reproduction tests from `audit` §6 into a real `tests/` directory and
wire them into `unit.sh`/CI, specifically so §1.1/§1.2/§1.3/§1.5 cannot silently reappear during the next phase.
Rotate every key in `sample/`. Confirm §2.2 (does `Kyber512` still resolve) against a real build.

**Phase 1 — Crypto architecture simplification (1–2 weeks, still C++, or done directly in Elixir if Phase 2 is
started in parallel).**
Replace liboqs+oqs-provider KEM/SIG calls with native OpenSSL 3.5 `EVP_PKEY_encapsulate`/`decapsulate` (ML-KEM-768
or -1024) and `EVP_PKEY_sign`/`EVP_DigestSign`/`EVP_DigestVerify` (ML-DSA-87), operating on the *same* `EVP_PKEY`
object end-to-end (no raw-byte round-trip). Delete `openss3_liboqs_oqsprovider.sh`'s liboqs/oqs-provider build
steps; keep only a stock OpenSSL 3.5+ build (or package, once available). This directly resolves `audit`
§2.1/§2.2/§2.7 and removes two of the three custom-build repositories from the toolchain.

**Phase 2 — Server port to Elixir/OTP (the main effort).**
Reimplement `server_session.h`/`server_handlers.h`/`server_connection.h`'s logic as OTP processes: one
`gen_statem`/`gen_server` per TLS connection, session membership via `Registry` or `:ets` (with correctly-scoped
concurrent access, i.e. actually using OTP idioms rather than hand-rolled locking), TLS via `:ssl` with
`x25519mlkem768` (already default-preferred in OTP 29) and ML-DSA server/client certs via `:public_key`, app-layer
sign/verify via `:crypto`. Keep the exact wire format from `shared_net_common_protocol.h` so the existing (now
Phase-0/1-fixed) C++ client needs zero changes to talk to it. Validate against the existing `unit.sh` scenario
(ron/beth/bob triangular messaging, reconnect, rekey) before considering this phase done.

**Phase 3 — Client evaluation (Rust vs. hardened C++), decided after Phase 2 data exists.**
With a stable, correct Elixir server and a fixed C++ client both known-good, evaluate whether the specific,
already-identified wins of a Rust client (§3.2 — mainly `zeroize`-style secret hygiene, and riding the
now-mature rustls/aws-lc-rs PQC transport stack) justify the port, informed by real interop testing against the
Phase 2 server rather than by assumption.

**Not recommended:** rewriting client and server simultaneously in different new languages before Phase 0/1 are
done. That would port today's crypto break (§1.1) into two new codebases at once and make it harder, not easier,
to tell whether a bug in the new system is a genuine regression or an inherited one.

---

## 6. Summary decision table

| Question | Answer |
|---|---|
| Is the current crypto safe to use as-is? | **No** — §1.1 is a full break; do not deploy until fixed, in any language |
| Is C++23 viable for this project going forward? | Yes, for the **client**, once §1's fixes and §5's test discipline are in place |
| Is C++23 the best choice for the **server**? | No — the concurrency bug class found here (§1.4) is structurally what Erlang/OTP processes prevent |
| Does moving to Elixir mean losing PQC maturity/parity? | No, as of OTP 28.1 (2025)/29 (2026) — native `crypto`/`ssl` support for ML-KEM/ML-DSA, same OpenSSL backend |
| Does the wire protocol need to change for this migration? | No — keep it, and use it to sequence server-first, client-second |
| Is liboqs/oqs-provider still needed? | No, not for ML-KEM/ML-DSA/SLH-DSA, as of OpenSSL 3.5 (April 2025) — drop the custom build pipeline |
| Biggest single risk if nothing else in this document is acted on? | Every two-way conversation this system has ever carried was encrypted under a reused nonce (§1.1) |
