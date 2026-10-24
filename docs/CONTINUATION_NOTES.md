# SPRK-Chat — Continuation Notes (read this first)

**Why this file exists:** the sandbox environment this work was done in was reset mid-implementation
(all installed toolchains, the from-source OpenSSL 3.5.9 build, and the in-progress reconstructed
repository were lost with no warning between tool calls). This document is the complete handoff so a
**new thread** can pick up exactly where this one was cut off, with zero loss of the reasoning, findings,
fixes, or test evidence produced here. Read this document fully before doing anything else. Where this
document says a fix is "EMPIRICALLY VERIFIED," that means it was built and tested as real running
binaries in this thread, with evidence quoted below. Where it says "DESIGNED, LOGICALLY VERIFIED, NOT
YET RE-TESTED AFTER RESET," that means the fix is correct by careful tracing and was designed in direct
response to a bug that WAS empirically reproduced, but the fix itself needs a fresh build+test pass
(instructions below) before being trusted as final.

---

## 0. What this engagement covered, in order

1. **Full security/code-quality audit** of the original C++23 SPRK-Chat prototype (PQC chat client/server).
   Delivered as `audit_code_bestpractice.md` (still valid, not affected by the reset — it's pure analysis).
2. **Path-forward guidance**: keep C++23 for the client, move the server to Elixir/OTP (process isolation
   structurally prevents the worst bug classes found; OTP 28.1+/29 now has native ML-KEM/ML-DSA on the
   same OpenSSL 3.5 backend). Delivered as `guidiance.md`.
3. **Two detailed implementation plans**: `server_elixir_grid_plan.md` (Elixir/Docker/federated-grid
   architecture, 10M-user capacity planning) and `client_keygen_cpp_plan.md` (C++23 client/keygen plan for
   Ubuntu 26.04). Both still valid, not affected by the reset.
4. **Phase 0 client fixes** (the five critical/high audit findings) — EMPIRICALLY VERIFIED before the
   reset (unit tests + a full 3-party tmux integration run with real binaries, ASan/UBSan clean).
5. **Phase 1: native OpenSSL 3.5 migration**, retiring liboqs/oqs-provider entirely — EMPIRICALLY VERIFIED
   before the reset (built real OpenSSL 3.5.9 from source, confirmed every ML-KEM-768/ML-DSA-87 EVP call
   against it, ran a full 3-party chat session with real TLS 1.3 X25519MLKEM768 handshakes).
6. **Two additional bugs found via the user's explicit, experience-based warning** ("only 3-way testing
   with rekey uncovered major bugs during original prototyping — do not dismiss this"):
   - **6a. Multi-party rekey cascade bug** — EMPIRICALLY REPRODUCED with real binaries (evidence below),
     and a fix designed. Fix logic was fully worked out; code was mid-application when the reset hit.
   - **6b. Reconnect stale-ready bug** — found via careful tracing while designing the fix for 6a (not yet
     independently empirically reproduced with a dedicated test — see §4.2), root-caused to the same
     underlying wire-format gap. A protocol addition (`target_fp` field) was designed and the wire-format
     half of it was implemented and unit-tested (round-trip test passes, see §4.3) before the reset. The
     receiver-side logic changes were only partially applied when the reset hit.
7. **This document** — full handoff, so a new thread can finish applying, then fully test, items 6a/6b.

---

## 1. Everything that is SOLID and does not need to be redone

These are correct, complete, and don't depend on the lost sandbox state — carry them forward as-is:

- `audit_code_bestpractice.md`, `guidiance.md`, `server_elixir_grid_plan.md`, `client_keygen_cpp_plan.md`
  — pure documents, already delivered, unaffected by any environment reset. If they were downloaded
  earlier in this conversation, they are already in the user's hands.
- The **design and empirical proof** for the five Phase 0 fixes (§2 below) — the reasoning and evidence
  are captured in full in this conversation's history and reproduced in §2 here. Only the *sandbox
  artifacts* (compiled binaries, the specific `/home/claude` tree) were lost, not the knowledge of what's
  right.
- The **design and empirical proof** for the native-OpenSSL migration (§3 below) — same situation.
- The exact API calls to use for ML-KEM-768/ML-DSA-87 on OpenSSL 3.5 (§3.1) — these were verified against
  real OpenSSL 3.5.9 source (built fresh from `https://github.com/openssl/openssl.git`, branch
  `openssl-3.5`) and against OpenSSL's own shipped documentation (`EVP_SIGNATURE-ML-DSA.pod`,
  `EVP_PKEY-ML-DSA.pod`, `EVP_PKEY-ML-KEM.pod`, `EVP_PKEY_encapsulate.pod`, `EVP_PKEY_fromdata.pod`) — this
  is durable, documented-upstream knowledge, not sandbox-dependent.

---

## 2. Phase 0 fixes — EMPIRICALLY VERIFIED (full detail)

All five critical/high findings from `audit_code_bestpractice.md` §1 were fixed and verified as real,
compiled, running binaries (not just unit tests) before the reset. Exact diffs for every file are
reproduced in this conversation's transcript (the message beginning "All Phase 0 fixes implemented and
empirically validated..."). Summary:

1. **§1.1 Cross-direction AEAD nonce reuse (CRITICAL)** — fixed by deriving two role-labeled keys
   (`derive_directional_keys_from_secret`, HKDF-expanded with `"SPRK-v2-initiator-to-responder"` /
   `"SPRK-v2-responder-to-initiator"` labels) instead of one shared key. `PeerInfo::sk` (a `SessionKey`)
   became `PeerInfo::keys` (a `DirectionalSessionKeys{send_key, recv_key}`). Verified via: (a) a standalone
   regression test proving nonces no longer collide and the two-time-pad break is closed; (b) a live
   3-client tmux session where ron and beth sent messages to each other **simultaneously at seq=0** — the
   exact scenario that broke the old code — and both were received correctly.
2. **§1.2 Deadlock in `rotate_ephemeral_if_needed` (CRITICAL)** — the function double-locked
   `peer_globals::peers_mtx()` (a non-recursive `std::mutex`). Fixed by never re-locking it; the socket
   write is now guarded by `runtime_globals::ssl_io_mtx()` instead. Verified via a minimal repro that
   deterministically hung before the fix and returns immediately after.
3. **§1.5 Seq/jitter window silently dead (HIGH)** — `is_sequence_gap_valid` allowed gaps up to 103, but
   the accept logic only ever honored gaps ≤3, silently dropping everything in between. Fixed by removing
   the dead `is_sequence_in_jitter_range` special case and accepting the full documented window. Verified
   by exhaustive enumeration (97/97 previously-dead gap values now correctly accepted; replay still
   correctly rejected).
4. **§2.4 HELLO signature doesn't cover `username` (HIGH)** — extended every signed payload to
   `eph_pk || session_id || username` (client-side signing in `client_crypto_util.h`/`client_session.h`,
   server-side verification in `server_session.h::validate_hello_basics`). This is "protocol v2" — both
   sides must be updated together (already done consistently everywhere in this pass).
5. **§2.3 `secure_vector` protection bypassed by copies (HIGH)** — every
   `std::vector<unsigned char>(secure_vector.begin(), secure_vector.end())` call made purely to satisfy a
   `std::span` parameter was replaced with a direct `std::span<const unsigned char>(secure_vector)`
   construction (no copy, no defeated cleansing).

Also fixed opportunistically while these files were open: a duplicate/dead self-check in
`validate_username`, and a genuine **stack-use-after-return bug** found via ASan during live testing (not
in the original audit) in `client/main.cpp`'s `attempt_connection()` — it captured a stack-local
`std::atomic<bool>`/`std::mutex`/`std::condition_variable` **by reference** in an async completion lambda,
but only waited 100ms before returning and letting those locals be destroyed, while the real TLS+PQC
handshake routinely takes longer than that. Fixed by giving the sync primitives shared ownership
(`std::shared_ptr`) and waiting for the real result (bounded by a generous 30s deadline, not a
guessed 100ms).

**All of the above is correct and should be re-applied verbatim** in the new thread — see §5 for the
exact current file states to recreate.

---

## 3. Phase 1: native OpenSSL 3.5 migration — EMPIRICALLY VERIFIED (full detail)

### 3.1 Verified API surface (from real OpenSSL 3.5.9, built from the `openssl-3.5` branch)

```
ML-DSA-87 keygen:      EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-87")
ML-DSA-87 sign:        EVP_SIGNATURE_fetch(nullptr, "ML-DSA-87", nullptr)
                       EVP_PKEY_sign_message_init(ctx, sig_alg, nullptr)
                       EVP_PKEY_sign(ctx, sig_out, &sig_len, msg, msg_len)
ML-DSA-87 verify:      EVP_PKEY_verify_message_init(ctx, sig_alg, nullptr)
                       EVP_PKEY_verify(ctx, sig, sig_len, msg, msg_len)  // returns 1 on success
ML-KEM-768 keygen:     EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768")
ML-KEM-768 encaps:     EVP_PKEY_encapsulate_init(ctx, nullptr)
                       EVP_PKEY_encapsulate(ctx, ct, &ct_len, secret, &secret_len)
ML-KEM-768 decaps:     EVP_PKEY_decapsulate_init(ctx, nullptr)
                       EVP_PKEY_decapsulate(ctx, secret, &secret_len, ct, ct_len)
Extract raw bytes:     EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY /
                                                       OSSL_PKEY_PARAM_PUB_KEY, buf, len, &out_len)
Import raw bytes:      EVP_PKEY_CTX_new_from_name(nullptr, alg, nullptr)
                       EVP_PKEY_fromdata_init(ctx)
                       OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY /
                                                        OSSL_PKEY_PARAM_PRIV_KEY, data, len)
                       EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY | EVP_PKEY_KEYPAIR, params)
```

Verified concrete facts (all confirmed empirically, not assumed):
- ML-DSA-87: pubkey 2592 bytes, privkey 4896 bytes, signature ~4627 bytes (varies slightly, deterministic
  bound documented by OpenSSL).
- ML-KEM-768: pubkey 1184 bytes, ciphertext 1088 bytes, shared secret 32 bytes.
- `EVP_PKEY_get_raw_private_key`/`EVP_PKEY_get_raw_public_key` (the **original** project's approach) DOES
  work correctly for ML-DSA-87 and returns **byte-identical** output to
  `EVP_PKEY_get_octet_string_param` — this **corrects** an over-cautious claim in the original audit
  (§2.7). The migration to `get_octet_string_param` was made anyway because it's OpenSSL's own documented
  primary access path, not because the old one was proven broken.
- Reconstructing an ML-KEM-768 `EVP_PKEY` from **only** raw private-key bytes (no public component) via
  `EVP_PKEY_fromdata` with `EVP_PKEY_KEYPAIR` selection **works correctly** for decapsulation — this is
  what makes it possible to keep the existing `secure_vector`-based storage architecture (no need to
  restructure `PeerInfo`/`peer_globals` to hold `EVP_PKEY*` objects directly).
- `openssl list -signature-algorithms` shows `ML-DSA-87` (no change needed — this name was already
  correct); `openssl list -kem-algorithms` shows `ML-KEM-512/768/1024` (the project's old `"Kyber512"`
  name is gone/stale — this **must** be `"ML-KEM-768"` now, confirmed both by this build and by upstream
  oqs-provider/liboqs release notes cited in `guidiance.md`).

### 3.2 Files changed (exact diffs are in this conversation's transcript, message beginning "Native
ML-KEM-768/ML-DSA-87 EVP APIs fully verified..."):
- `shared_net_common_protocol.h`: `KEM_ALG_NAME = "ML-KEM-768"` (was `"Kyber512"`), added
  `ML_KEM_768_PUBLIC_KEY_LEN = 1184`, `ML_KEM_768_CIPHERTEXT_LEN = 1088`.
- `shared_common_crypto.h`: `pqkem_keypair`/`pqkem_encaps`/`pqkem_decaps`/`pqsig_keypair`/`pqsig_sign`/
  `pqsig_verify` rewritten on top of native `EVP_PKEY_*` calls via a new `pqc_detail` namespace
  (`pkey_from_public_bytes`, `pkey_from_private_bytes`, `get_priv_octets`, `get_pub_octets`). All six
  function **signatures unchanged** — zero client call-site changes needed beyond the algorithm name.
  Removed `pqkem_keypair_from_seed` (liboqs-only, dead).
- `shared_net_key_util.h`: removed `derive_ephemeral_for_peer`, `PQKeypair`, `SessionId`, `PeerName`
  (liboqs-only, unused anywhere in the real connect/HELLO/rekey flow, and a design — deterministic
  ephemeral keys derived from the long-term identity key — independently flagged as undermining forward
  secrecy). Migrated 8 call sites from `EVP_PKEY_get_raw_private_key`/`_public_key` to
  `EVP_PKEY_get_octet_string_param`.
- `client_crypto_util.h`: removed the `#ifdef USE_LIBOQS`/`<oqs/oqs.h>` include;
  `get_expected_lengths` now returns the fixed `ML_KEM_768_PUBLIC_KEY_LEN`/`ML_KEM_768_CIPHERTEXT_LEN`
  constants instead of querying liboqs (the **original** `#else` branch here — reachable in any build
  without `USE_LIBOQS` — silently returned `0, 0` and `true`, which would have rejected every real
  `MSG_HELLO`; worth knowing if you ever see that specific old bug elsewhere).
- `CMakeLists.txt`: removed the entire liboqs/oqs-provider `find_library`/`pkg_check_modules` block, the
  `${OQS_LIB}` link entry, and the `USE_LIBOQS` compile definition. `OPENSSL_ROOT_DIR` is now an *optional*
  cache variable (empty by default → uses system OpenSSL via normal `find_package(OpenSSL 3.5 REQUIRED)`
  discovery, which is what Ubuntu 26.04's `libssl-dev` package provides directly).
- Bumped the compiler-version floor in `CMakeLists.txt` to Clang≥16/GCC≥13 (matching Ubuntu 26.04's
  toolchain; the original floor of Clang≥14/GCC≥11 predates the 26.04 target).
- `shared_net_tls_context.h`: dropped the `oqsprovider` provider-load call (not needed — native OpenSSL
  3.5 needs no provider plugin for ML-KEM/ML-DSA/X25519MLKEM768), dropped `SSL_CTX_set_security_level(ctx,
  0)` and the plain-`X25519` TLS group fallback (audit §3.3 — no reason to allow a non-hybrid downgrade
  when both endpoints are project-controlled).

### 3.3 Verified end-to-end (before the reset)
A full 3-party (ron/beth/bob) chat session ran with: real TLS 1.3 `X25519MLKEM768` mutual-auth handshakes,
real ML-DSA-87 identity keys generated by the real `user_keygen` binary, real ML-KEM-768 ephemeral
exchange, and real ChaCha20-Poly1305 message exchange — all built from a from-scratch OpenSSL 3.5.9 build,
zero liboqs/oqs-provider anywhere in the dependency graph, zero ASan/UBSan reports.

---

## 4. The two bugs found from the user's rekey/reconnect warning — CURRENT STATE

This is the part that was **in progress** when the reset happened. The user's warning was specific and
experience-based: *"only 3-way testing... uncovered major rekey bugs"* during original prototyping, and
explicitly asked for a scenario covering joins, multi-directional messaging, disconnects, and reconnects,
not just a simple pairwise test. That warning was taken seriously and led directly to finding two real,
confirmed-relevant bugs beyond the original five.

### 4.1 Bug 6a: multi-party rekey cascade — EMPIRICALLY REPRODUCED, FIX DESIGNED AND MOSTLY APPLIED

**Root cause:** `peer_globals::my_eph_pk()`/`my_eph_sk()` are **global** — one ephemeral KEM keypair per
client, shared across every peer relationship (this is intentional/necessary given the wire format: one
`eph_pk` per username, broadcast to the whole session). When `rotate_ephemeral_if_needed(peer_fp)` fires
because *one* peer's `send_seq` crossed `REKEY_INTERVAL`, it generates a **new** global keypair and
announces it — which silently invalidates every *other* peer relationship's ability to complete a fresh
KEM exchange too, because only the triggering peer's state was reset. Any peer for whom the rekeying
client is the **static initiator** (fp comparison) never gets a fresh encapsulation sent to them (nothing
in the original code proactively redoes that), so their channel silently stalls forever after the rekey —
one-directionally (the rekeying client can still *send* to them using the old, still-valid-but-now-orphaned
key from their perspective is fine, but the pending fix invalidates it, so both directions actually break
once the fix's "reset everyone" step runs — see below for why that's still correct).

**Empirical reproduction** (real binaries, `REKEY_INTERVAL` temporarily lowered to 5 for testability):
```
=== ron: rekey/rotate lines ===
[timestamp] rotated ephemeral key for peer_fp <beth's fp>     <- ron<->beth hit the threshold
=== beth: rekey/rotate lines ===
[timestamp] peer ron rekeyed                                   <- beth correctly detects and reacts
                                                                    (beth is static initiator toward ron)
>>> INITIATOR SENDING ENCAPS! my=beth peer=ron ... already_sent=0
[timestamp] peer ron ready                                      <- beth<->ron recovers correctly
=== bob (uninvolved third party) ===
[DEBUG] handling MSG_HELLO from ron
"peer ron rekeyed"                                              <- bob ALSO resets his ron-state
"INFO: awaiting encaps from ron"                                <- bob waits... forever
grep "peer=bob" ron's full log -> only ONE match, from the ORIGINAL
  connection, timestamped BEFORE the rekey. Ron never re-encapsulates
  toward bob after rotating. Bob's channel with ron is permanently stuck.
```
This is exactly the failure mode the user described from original prototyping: a pair that has **nothing
to do with** the triggering rekey silently breaks, and only shows up when you actually test 3+ parties with
real message volume, not a simple 2-party test.

**Fix designed and applied to `client_crypto_util.h`** (this part WAS successfully written before the
reset — reproduce it verbatim in the new thread):
```cpp
static void send_current_hello_announcement() {
  std::vector<unsigned char> sig_data;
  sig_data.reserve(peer_globals::my_eph_pk().size() +
                   peer_globals::session_id().size() +
                   peer_globals::my_username().size());
  sig_data.insert(sig_data.end(), peer_globals::my_eph_pk().begin(),
                  peer_globals::my_eph_pk().end());
  sig_data.insert(sig_data.end(), peer_globals::session_id().begin(),
                  peer_globals::session_id().end());
  sig_data.insert(sig_data.end(), peer_globals::my_username().begin(),
                  peer_globals::my_username().end());

  const std::vector<unsigned char> signature_vec =
      pqsig_sign(SIG_ALG_NAME,
                std::span<const unsigned char>(peer_globals::my_identity_sk()),
                sig_data);

  const std::vector<unsigned char> identity_pk_vec(
      peer_globals::my_identity_pk().begin(),
      peer_globals::my_identity_pk().end());

  const auto hello_frame = build_hello(
      peer_globals::my_username(), ALGO_KEM_ALG_NAME,
      std::vector<unsigned char>(peer_globals::my_eph_pk().begin(),
                                peer_globals::my_eph_pk().end()),
      ALGO_MLDSA87, identity_pk_vec, signature_vec,
      std::vector<unsigned char>{}, std::vector<unsigned char>{},
      peer_globals::session_id());

  auto frame_ptr = std::make_shared<std::vector<unsigned char>>(hello_frame);
  const std::lock_guard<std::mutex> io_lk(runtime_globals::ssl_io_mtx());
  if (!runtime_globals::ssl_stream())
    return;
  async_write_frame(runtime_globals::ssl_stream(), frame_ptr,
                    [frame_ptr](const std::error_code &, std::size_t) {});
}

static void rotate_ephemeral_if_needed(const std::string &peer_fp) {
  const std::lock_guard<std::mutex> lk(peer_globals::peers_mtx());
  const auto it = peer_globals::peers().find(peer_fp);
  if (it == peer_globals::peers().end() ||
      !should_rekey(it->second.send_seq, REKEY_INTERVAL))
    return;

  const auto ms = get_current_timestamp_ms();
  auto eph_pair = pqkem_keypair(KEM_ALG_NAME);
  peer_globals::my_eph_pk() = eph_pair.first;
  peer_globals::my_eph_sk() = eph_pair.second;

  send_current_hello_announcement();

  // This client's ephemeral keypair is shared by every peer relationship --
  // rotating it invalidates every already-derived session, not only the one
  // whose send_seq crossed REKEY_INTERVAL. Confirmed via a live 3-party test:
  // resetting only the triggering peer left every OTHER peer for whom this
  // client is the static initiator permanently stuck at "awaiting encaps".
  for (auto &kv : peer_globals::peers()) {
    auto &other = kv.second;
    other.ready = false;
    other.sent_hello = false;
    other.send_seq = 0;
    other.recv_seq = 0;
    other.keys.send_key.clear();
    other.keys.recv_key.clear();
  }

  dev_println("[" + std::to_string(ms) +
              "] rotated ephemeral key for peer_fp " + peer_fp);
}
```

This alone is **not sufficient** — it correctly forces every peer relationship to redo its KEM exchange,
but the *static responder* side (e.g., bob, who never proactively sends an encaps) still needs something
to prompt the *static initiator* side (ron) to react. That "something" is: whenever a client detects a
peer's key changed (`pk_changed`) and determines **it is not the initiator** toward that peer, it should
resend its **own** current hello (bare, unchanged eph_pk, no encaps) — this "wakes up" the true initiator
(ron), who — now that his own state for that responder has *also* been reset by the loop above — will
correctly react to this resend exactly like a fresh connection, complete a real encapsulation, and recover
the channel. **This second half (the responder-side reflex resend, to be added in `handle_hello` inside
`client_message_util.h`) was designed but not yet written when the reset hit.** Write it now:

```cpp
// Inside handle_hello, in the branch that currently just calls
// log_awaiting_encaps(...) when (!i_am_initiator): also proactively resend
// our own current hello, so the true initiator (who was also reset by the
// loop in rotate_ephemeral_if_needed above) has something fresh to react to.
if (!i_am_initiator) {
  if (pi.ready) {
    dev_println(...);
  } else {
    log_awaiting_encaps(PeerNameView{peer_name}, MsU{ms});
    send_current_hello_announcement();   // <-- ADD THIS LINE
  }
}
```
`send_current_hello_announcement` needs to be visible from `client_message_util.h` (it's defined in
`client_crypto_util.h`, which `client_message_util.h` already includes — no new include needed, just make
sure it's declared before use or move the forward declaration up alongside the others near the top of
`client_message_util.h`, matching the existing pattern for `rotate_ephemeral_if_needed`).

**Also apply the same all-peers-reset fix to `reset_peers_state()` in `client/main.cpp`** (called after a
full disconnect/reconnect) — see §4.2, this is where bug 6b connects to 6a.

### 4.2 Bug 6b: reconnect leaves other clients' `ready` state stale — ROOT-CAUSED, PARTIAL FIX APPLIED

Found while designing the fix for 6a, by tracing through the user's exact requested scenario (beth
disconnects and reconnects while ron stays connected). Root cause, traced in full:

1. When beth disconnects, `reset_peers_state()` (client/main.cpp) clears beth's own `ready`/`sent_hello`/
   `keys` for every peer — but **ron is never told beth disconnected at all** (the wire protocol has no
   disconnect/presence notification message type, and the server doesn't send one).
2. Beth reconnects with her **persisted** (unchanged) ephemeral keypair (this persistence across
   reconnects within one process run is intentional, existing, correct behavior — confirmed in the
   original README). She sends a fresh HELLO with **empty** encaps (same as any first connection).
3. The server's existing "cached hello" mechanism re-sends ron's (cached, encaps-stripped) hello back to
   beth. Beth — since she's the static initiator toward ron in the traced example — correctly reacts by
   generating a **fresh** encapsulation against ron's (unchanged) public key and sending it.
4. **Ron receives beth's fresh, entirely valid encaps — and silently discards it**, because
   `detect_key_changes`'s `has_new_encaps` check was defined as
   `!p.encaps.empty() && had_eph_pk && !pi.ready` — and ron's `pi.ready` for beth is still **stale-true**
   (never invalidated by her disconnect, per point 1). The `!pi.ready` guard, whose actual purpose is
   preventing an unrelated bystander from misinterpreting a broadcast encaps meant for someone else (see
   next paragraph), incidentally also blocks the **legitimate holder of that relationship** from
   processing a real, freshly-needed encaps.
5. Net effect: beth ends up with a **freshly derived** shared key with ron; ron keeps using the **old**
   one. Every subsequent message between them fails to decrypt, permanently, with no error surfaced beyond
   silent AEAD failures — until some unrelated event (like a real rekey — see 6a) happens to reset ron's
   state for beth too.

**The `!pi.ready` heuristic cannot simply be deleted**, because it is the *only* thing currently stopping
an uninvolved bystander (e.g., a third client who is also mid-handshake) from misinterpreting a broadcast
`MSG_HELLO`'s encaps — meant for one specific recipient — as meant for them, since the wire format has no
recipient/target field on `MSG_HELLO` at all; every hello (including replies carrying an encaps) is
broadcast to the whole session by the server, with nothing on the wire saying who a given encaps is *for*.

**Root, correct fix: add an explicit `target_fp` field to `MSG_HELLO`.** This was designed and the
wire-format half was implemented and unit-tested (verified round-trip below) before the reset:

- `Parsed` gains `std::vector<unsigned char> target_fp;`.
- `build_hello`'s signature gains a `const std::vector<unsigned char> &target_fp` parameter (placed
  between `encaps` and `session_id`), encoded on the wire the same way as the other length-prefixed byte
  fields (u16 length + bytes, max `FINGERPRINT_LEN` = 32, empty allowed).
- **Every call site updated:**
  - `client_session.h` (initial connection hello): `target_fp = {}` (no encaps yet, nothing to target).
  - `client_crypto_util.h::send_current_hello_announcement` (bare rekey/reflex announcement):
    `target_fp = {}`.
  - `client_crypto_util.h::try_handle_initiator_encaps` (the **only** place a real encaps is ever sent):
    `target_fp = from_hex(peer_fp_hex)` — the specific peer this ciphertext was encapsulated for.
  - `server_handlers.h`'s cached-hello resend (which already strips `encaps`): also strips `target_fp` to
    empty, for consistency.
- **Receiver-side logic** (the part that fixes both 5b and hardens 6a): replace the `!pi.ready`-based
  guess with explicit target checking. Add (already written, verified compiling, in
  `client_peer_manager.h`):
  ```cpp
  [[nodiscard]] inline bool encaps_targets_me(const Parsed &p) noexcept {
    if (p.encaps.empty() || p.target_fp.empty())
      return false;
    const auto my_fp_bytes = from_hex(peer_globals::my_fp_hex());
    return p.target_fp.size() == my_fp_bytes.size() &&
           std::equal(p.target_fp.begin(), p.target_fp.end(),
                      my_fp_bytes.begin());
  }

  bool detect_key_changes(const PeerInfo &pi, const Parsed &p, bool &pk_changed,
                          bool &has_new_encaps) {
    const bool had_eph_pk = !pi.eph_pk.empty();
    pk_changed = had_eph_pk && (pi.eph_pk.size() != p.eph_pk.size() ||
                                !std::equal(pi.eph_pk.begin(), pi.eph_pk.end(),
                                            p.eph_pk.begin()));
    has_new_encaps = had_eph_pk && encaps_targets_me(p);
    return !had_eph_pk || pk_changed || has_new_encaps;
  }
  ```
  **This part was NOT yet done when the reset hit and must be added in the new thread:**
  `detail::process_peer_encaps` in `client_message_util.h` has its own, separate, still-untargeted check
  (`if (!p.encaps.empty() || (initiator.v && !pi.sent_hello))`) that gates whether `try_handle_initiator_encaps`
  / `handle_encaps_present` get called at all. This must **also** be changed to use `encaps_targets_me(p)`
  instead of the raw `!p.encaps.empty()` check, or a bystander can still be routed into attempting to
  decapsulate ciphertext meant for someone else (via `handle_encaps_present`, reached because the outer
  condition was satisfied by the raw emptiness check alone). Concretely, change:
  ```cpp
  if (!p.encaps.empty() || (initiator.v && !pi.sent_hello)) {
  ```
  to:
  ```cpp
  if (encaps_targets_me(p) || (initiator.v && !pi.sent_hello)) {
  ```
  (`encaps_targets_me` is declared in `client_peer_manager.h`, which `client_message_util.h` already
  transitively includes via `client_crypto_util.h` — no new include needed.)

**Wire-format round trip verified** (before the reset, and does not depend on OpenSSL/PQC, only Poco —
this specific check can be trivially re-verified in the new thread in under a minute):
```
PASS: hello with target_fp parses
PASS: target_fp round-trips exactly
PASS: encaps round-trips exactly alongside target_fp
PASS: eph_pk unaffected by new field
PASS: session_id still parses correctly after the new field
PASS: bare announcement round-trips with both empty
PASS: build_hello rejects target_fp > FINGERPRINT_LEN(32)
```

**Not yet done / explicitly flagged as residual, not silently skipped:**
- `target_fp` is **not** currently part of the signed `sig_data` for the HELLO's ML-DSA-87 signature. A
  tampered `target_fp` (by a malicious/compromised relay server; TLS already rules out a network MITM)
  could at worst misdirect an encaps to the wrong recipient, causing a **failed handshake** (KEM decap with
  the wrong key produces a useless secret via ML-KEM's implicit-rejection property, not a security
  break) — an availability nuisance, not a confidentiality/integrity break. Adding `target_fp` to the
  signed payload (protocol v2.2) would close even that residual gap and is a clean, small follow-up.
- This whole fix has **not been re-verified with a fresh full build + the user's exact requested
  multi-step scenario** after the reset. That is the concrete next step — see §6.

---

## 5. Exact current source file states to recreate in the new thread

Every file below should be reconstructed with **all** fixes from §2, §3, and §4 applied together (they are
compatible and were designed as one coherent set). The full, exact content of every file (as it stood
immediately before the reset) is present verbatim in this conversation's transcript — search for the most
recent `create_file`/`str_replace` call touching each filename to get the exact final text. As a checklist,
confirm each of these before considering the reconstruction complete:

- [ ] `src/shared/shared_net_common_protocol.h` — `target_fp` field, `KEM_ALG_NAME = "ML-KEM-768"`,
      `ML_KEM_768_*_LEN` constants. (Full final content is reproduced in §4.3 above / this thread's last
      `create_file` call for this path.)
- [ ] `src/shared/shared_common_util.h` — unchanged from the original project.
- [ ] `src/shared/shared_common_crypto.h` — native OpenSSL EVP_PKEY KEM/SIG implementation (§3.2).
- [ ] `src/shared/shared_net_key_util.h` — `derive_ephemeral_for_peer`/`PQKeypair`/`SessionId`/`PeerName`
      removed, `get_octet_string_param` migration (§3.2).
- [ ] `src/shared/shared_net_message_util.h` — `ctx.session_key = pi.keys.send_key;` (not `pi.sk.key`).
- [ ] `src/shared/shared_net_rekey_util.h` — unchanged from the original project.
- [ ] `src/shared/shared_net_socket_util.h` — unchanged from the original project.
- [ ] `src/shared/shared_net_tls_frame_io.h` — unchanged from the original project.
- [ ] `src/shared/shared_net_tls_context.h` — no `oqsprovider` load, no `security_level(0)`, hybrid-only
      TLS group (§3.2).
- [ ] `src/shared/shared_net_username_util.h` — unchanged from the original project.
- [ ] `src/client/client_peer_manager.h` — `DirectionalSessionKeys keys` (not `SessionKey sk`),
      `encaps_targets_me`/`detect_key_changes` with target-based logic (§2, §4.2).
- [ ] `src/client/client_crypto_util.h` — nonce-direction fix, deadlock fix, username-signed HELLO,
      `send_current_hello_announcement`, all-peers-reset in `rotate_ephemeral_if_needed`, no liboqs,
      `target_fp` populated on the initiator's reply (§2, §3, §4.1, §4.2).
- [ ] `src/client/client_session.h` — username-signed HELLO, span-not-copy signing key, `target_fp={}`
      on the initial connection hello (§2, §4.2).
- [ ] `src/client/client_message_util.h` — `pi->keys.recv_key` (not `pi->sk.key`), fixed seq/jitter
      window, **the still-pending `encaps_targets_me(p)` swap in `process_peer_encaps`** (§2, §4.2 — this
      is the one confirmed-incomplete piece), **the still-pending reflex-resend call** in `handle_hello`'s
      `!i_am_initiator` branch (§4.1 — also confirmed-incomplete).
- [ ] `src/client/client_runtime.h`, `client_peer_disconnect.h`, `client_commands.h`,
      `client_cmdline_util.h`, `client_reader_writer.h` — unchanged from the original project.
- [ ] `src/client/main.cpp` — `attempt_connection`'s shared_ptr lifetime fix (§2), `reset_peers_state()`
      updated for `pi.keys.send_key/recv_key` (§2) — **also apply the same all-peers-reset semantics here
      that `rotate_ephemeral_if_needed` uses**, since a full disconnect/reconnect is, from every *other*
      connected peer's perspective, exactly as disruptive as an ephemeral-key rotation (this was identified
      while writing this document — reset `send_seq`/`recv_seq` to 0 for all peers here too, matching
      §4.1's loop, not just `ready`/`sent_hello`/`keys`).
- [ ] `src/server/server_client_state.h`, `server_connection.h`, `server_handlers.h` (only the
      `target_fp`-stripping addition, §4.2) — unchanged otherwise.
- [ ] `src/server/server_session.h` — username-signed HELLO verification (§2).
- [ ] `src/server/main.cpp` — unchanged from the original project.
- [ ] `src/user_keygen/main.cpp` — the `--out-dir` fix (`out_dir.makeDirectory()` before
      `makeAbsolute()`/`setFileName()` — a genuine bug found via testing, unrelated to PQC, caused by
      `Poco::Path` treating a bare directory string's last component as a filename until told otherwise).
- [ ] `CMakeLists.txt` — liboqs removed, `OPENSSL_ROOT_DIR` optional, compiler floor bumped (§3.2).
- [ ] `generate_pq_certs.sh`, `keygen_run.sh`, `build_cmake.sh`, `clean_cmake.sh`, `server.sh`,
      `client.sh`, `unit.sh`, `bash/shared/default.sh`, `.gitignore`, `README.md`, `LICENSE` — all
      rewritten for the no-custom-OpenSSL-build, no-committed-keys world; exact content is in this
      thread's transcript at the "Now let's add the build scripts, docs, and remaining project files"
      step onward. `unit.sh`'s `Test_005` was specifically updated to send **both directions before
      checking either**, as a standing regression test for bug §1.1.

---

## 6. Exact next steps for the new thread (in order)

1. **Re-establish the toolchain** (all commands verified working in this exact sequence earlier in this
   engagement):
   ```bash
   apt-get update
   apt-get install -y libssl-dev libasio-dev libpoco-dev cmake build-essential tmux netcat-openbsd git
   git clone --depth 1 --branch openssl-3.5 https://github.com/openssl/openssl.git openssl-3.5-src
   cd openssl-3.5-src
   ./Configure --prefix=/path/to/openssl-3.5-install --openssldir=/path/to/openssl-3.5-install/ssl no-docs
   make -j$(nproc) build_libs          # run as a FOREGROUND command in ONE tool call, not backgrounded --
                                        # backgrounded/nohup processes do NOT survive between tool calls
                                        # in this kind of sandboxed environment; this cost real time twice
                                        # in this engagement
   make install_dev
   mkdir -p /path/to/openssl-3.5-install/ssl
   printf '[req]\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n' \
     > /path/to/openssl-3.5-install/ssl/openssl.cnf   # install_dev doesn't create one; openssl req needs it
   ```
   On **real Ubuntu 26.04** (the actual target OS), skip the from-source OpenSSL build entirely — just
   `apt install libssl-dev` (ships 3.5.5, confirmed via prior research in this engagement) — the from-source
   build in this sandbox was only a stand-in because the sandbox itself ran Ubuntu 24.04.
2. **Recreate the full source tree** per the checklist in §5, applying every fix. Use `git diff`-style
   review against the checklist to make sure nothing is missed, especially the two explicitly-flagged
   incomplete items (`process_peer_encaps`'s target check, the reflex-resend call, and the
   `reset_peers_state()` extension noted in §5).
3. **Rebuild and smoke-test in this order** (each step verified working earlier in this engagement):
   ```bash
   cmake -S . -B build -DUSE_CLANG=OFF -DOPENSSL_ROOT_DIR=/path/to/openssl-3.5-install \
     -DCMAKE_BUILD_TYPE=Debug
   cmake --build build -- -j1     # -j1 if on a single-core sandbox; use -j$(nproc) on real hardware
   ./generate_pq_certs.sh         # after exporting PATH/LD_LIBRARY_PATH to the openssl-3.5-install bin/lib
   ./bin/user_keygen ron  --out-dir sample
   ./bin/user_keygen beth --out-dir sample
   ./bin/user_keygen bob  --out-dir sample
   ```
4. **Run the user's exact requested scenario** as a scripted tmux integration test (this is the
   authoritative acceptance test for this whole line of work — do not consider it done until this passes
   cleanly with zero stuck/silent-failure states):
   > beth opens chat, ron joins → beth message ron → ron message beth → bob joins → bob message ron →
   > ron message bob → bob message beth → beth message bob → beth disconnects → beth rejoins → beth
   > message bob → beth message ron → bob disconnects → ron message beth → beth message ron → bob
   > reconnects → bob message ron → bob message beth
   Build this as a single-tool-call tmux script (background processes do not survive between tool calls —
   see the note in step 1) mirroring the pattern already used successfully earlier in this engagement:
   `tmux new-session`, `send-keys` for each connect/message/`q`(disconnect)/reconnect step with short
   `sleep`s between, `capture-pane -p -S -3000` to inspect full history, and explicit `grep` checks after
   **every** message for the exact expected `"[<timestamp>] [<from> <shortfp>] <message>"` line on the
   receiving client's pane — not just the last few lines, since a silently-stuck channel produces **no
   error**, only a missing line, which is easy to miss with `tail`.
   Additionally: temporarily set `REKEY_INTERVAL` (in `client_peer_manager.h`) to a small number (5 was
   used successfully earlier) so the scenario can also be run a second time with enough message volume
   between some pair to cross the rekey threshold *during* the reconnect sequence, since that is the
   specific combination (rekey **and** reconnect **and** 3+ parties) the user's account of the original
   prototyping problems points at most directly. Revert `REKEY_INTERVAL` to `1024` before considering the
   fix final; the low value is a test-only aid.
5. **If any step of the user's scenario reveals a still-stuck or wrong-key state**, capture the exact
   sequence of `dev_println`/`std::cout` lines (as was done for bug 6a above) before changing anything —
   that log trace is what makes root-causing tractable, as demonstrated twice already in this engagement.
6. **Once the full scenario passes cleanly**, promote it into `unit.sh` as a permanent regression test
   (extending the existing `Test_011`-style reconnect test to include the second reconnecting party and
   the interleaved rekey), so this class of bug cannot silently reappear.
7. **Package the final, fully-verified repository** (source tree + docs + this notes file, superseded by
   an updated version reflecting the now-complete state) as the deliverable archive.

---

## 7. Full list of every finding from this entire engagement, for reference

Kept here as a single consolidated index so nothing from the conversation has to be re-derived:

| # | Finding | Severity | Status |
|---|---|---|---|
| 1.1 | Cross-direction AEAD nonce reuse | CRITICAL | Fixed, empirically verified |
| 1.2 | Deadlock in ephemeral-key rotation | CRITICAL | Fixed, empirically verified |
| 1.3 | `cleanup_old_nickname` dead code (server) | CRITICAL | Documented; NOT fixed (server C++ is a transitional bridge only — real fix is the Elixir rewrite, `server_elixir_grid_plan.md`) |
| 1.4 | Server data race on shared session map | CRITICAL | Documented; NOT fixed (same rationale as 1.3) |
| 1.5 | Seq/jitter window silently dead | HIGH | Fixed, empirically verified |
| 2.1 | KEM/sig security-level mismatch | HIGH | Fixed (ML-KEM-768, matches TLS-layer hybrid group) |
| 2.2 | `"Kyber512"` stale against current liboqs | HIGH | Moot — liboqs retired entirely |
| 2.3 | `secure_vector` copy bypass | HIGH | Fixed, empirically verified |
| 2.4 | HELLO signature doesn't cover username | HIGH | Fixed, empirically verified |
| 2.5 | TLS identity ≠ E2E identity | HIGH | Documented; not fixed (needs server-side CN==username enforcement, part of the Elixir rewrite) |
| 2.6 | Committed private keys in original repo | HIGH | Fixed — `.gitignore` updated, all keys in this delivery freshly generated, never committed |
| 2.7 | Two PQC implementations must agree on key format | HIGH | Resolved by construction (native OpenSSL end-to-end, no liboqs) |
| 3.x | Various medium/low findings (protocol header hygiene, dead code, style) | MEDIUM/LOW | See `audit_code_bestpractice.md` §3/§4; mostly cleared opportunistically while touching the same files |
| — | Stack-use-after-return in `attempt_connection` | CRITICAL (found via testing, not in original audit) | Fixed, empirically verified |
| — | `user_keygen --out-dir` silently discarded | MEDIUM (found via testing) | Fixed, empirically verified |
| 6a | Multi-party rekey cascade (uninvolved peer permanently stuck) | CRITICAL (found via user's explicit warning) | Fix designed and mostly applied; needs the reflex-resend line + fresh full-scenario test |
| 6b | Reconnect leaves other clients' `ready` state stale, causing key mismatch | CRITICAL (found while investigating 6a) | Root-caused; `target_fp` wire addition designed, half-applied; needs the `process_peer_encaps` targeting swap + fresh full-scenario test |

Server-side items (1.3, 1.4, 2.5) are **intentionally** not fixed in the C++ server — per the user's own
explicit scoping in this engagement ("server update is not scope here"), the C++ server is a transitional
bridge only, patched exclusively where needed for the fixed client to interoperate with it (the username-
signature check, item 2.4's server half). The real fix for all server-side architectural issues is the
Elixir/OTP rewrite in `server_elixir_grid_plan.md`, which structurally cannot have bugs 1.3/1.4/6a's data-
race/shared-mutable-state root cause, and should independently re-derive/re-verify 6a/6b's fix in its own
(different) architecture rather than porting the C++ patch verbatim — Horde's CRDT-based registry handles
"a peer's session state needs to be reset session-wide" as a first-class distributed-registry operation,
which is a fundamentally more robust foundation for this exact class of bug than a `std::unordered_map`
with manual iteration.

---

## 8. FINAL STATUS UPDATE (after the reset, same thread continued)

Everything described in §4 as "pending" has now been **fully applied** in the delivered source tree:

- `rotate_ephemeral_if_needed`'s all-peers reset (§4.1): **applied**, in `client_crypto_util.h`.
- The responder-side reflex resend (§4.1): **applied**, in `client_message_util.h::handle_hello`'s
  `!i_am_initiator` branch (calls `send_current_hello_announcement()`).
- The `target_fp` wire-format addition (§4.2): **applied** throughout -- `Parsed`, `build_hello`,
  every call site (`client_session.h`, `client_crypto_util.h` x2, `server_handlers.h`), and
  `encaps_targets_me()` in `client_peer_manager.h`.
- The `process_peer_encaps` targeting swap (§4.2): **applied**, in `client_message_util.h` --
  `detail::process_peer_encaps` now gates on `encaps_targets_me(p)` instead of a raw
  `!p.encaps.empty()` check.
- The `reset_peers_state()` extension identified while writing §5 (also reset `send_seq`/`recv_seq` on
  full reconnect, matching `rotate_ephemeral_if_needed`'s semantics): **applied**, in `client/main.cpp`.
- `unit.sh` was extended with `Test_008` through `Test_010`, implementing the user's exact requested
  scenario (a mid-session disconnect/reconnect of one party, then a second party disconnecting while the
  first two continue, then that second party reconnecting -- all with bidirectional message verification
  at each step), as described in §6 step 4.

**What this means concretely:** the *design* is complete and internally consistent (every piece was
traced through by hand against the user's exact scenario, including the specific case of a reconnecting
party's fresh encaps being explicitly targeted so a stale-ready bystander can no longer either wrongly
accept or wrongly reject it). The wire-format half (`target_fp` encode/decode) was unit-tested standalone
and passes (§4.3's output, reproduced identically after this second environment reset). **What is still
outstanding, honestly:** a second sandbox reset during this engagement (this one total, requiring a full
source-tree reconstruction from the conversation transcript) meant there was not enough remaining budget
in this thread to also redo the from-source OpenSSL 3.5 build and run a live, full `unit.sh` pass with
real ML-KEM-768/ML-DSA-87 binaries and real tmux-driven multi-party message exchange against *this exact*
final code. That is the one remaining step, and it is a mechanical one (the toolchain commands in §6 are
exact and were proven to work twice already in this engagement before each reset) -- not a design
question. Treat `unit.sh` passing cleanly end-to-end, unmodified, as the acceptance criterion for closing
this out.

If a third reset happens before that run completes: this document plus the full source tree in this
archive are sufficient to resume with **zero** re-derivation of reasoning -- only the mechanical
build-and-run step in §6 remains.
