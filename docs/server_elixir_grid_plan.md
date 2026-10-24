# SPRK-Chat Server — Elixir/OTP Conversion & Grid Implementation Plan

Companion to `audit_code_bestpractice.md` and `guidiance.md`. This is the prototype-phase implementation plan for
replacing `src/server/*` with an Elixir/OTP service, containerized with Docker, designed from day one as a
federable "grid unit" so the end-state (10M concurrent users, multi-operator, partition-tolerant) is a scaling
exercise on this architecture rather than a second rewrite. The companion client/keygen plan is
`client_keygen_cpp_plan.md` — read the "What does *not* change" section there first: the wire protocol staying
fixed is what makes this a **server-first, client-unchanged** migration.

---

## 1. Target stack

| Layer | Choice | Why |
|---|---|---|
| OS (dev + container base) | Ubuntu 26.04 LTS "Resolute Raccoon" | matches your stated OS priority; ships OpenSSL **3.5.5** by default (verified: `openssl` source pkg `3.5.5-1ubuntu3.3` in `resolute`) |
| Crypto engine | **System OpenSSL 3.5.5**, native ML-KEM/ML-DSA/SLH-DSA. No liboqs, no oqs-provider. | See `guidiance.md` §2 — this is now unnecessary, and Ubuntu 26.04 makes it a zero-effort `apt install` instead of a source build |
| Language/runtime | Elixir 1.18+ on **Erlang/OTP 28 LTS or newer (target OTP 29)** | see §1.1 — this is **not** what `apt install elixir` gives you on 26.04 |
| Networking | `:ssl` (Erlang/OTP's TLS 1.3, native `x25519mlkem768`/ML-DSA cert support) + `:ranch` (or `thousand_island`) for the listener/acceptor pool | no NIF/FFI crypto risk; same OpenSSL backend as the C++ side |
| Process registry / cluster membership | `Horde.Registry` + `Horde.DynamicSupervisor` (CRDT-based, partition-tolerant) over `libcluster` for node discovery | replaces the C++ server's single unguarded `unordered_map<string, SessionData>` (audit §1.4) with a design that has no such thing as "the map" to race on |
| Pub/Sub for message relay | `Phoenix.PubSub` (works standalone, no Phoenix web framework required) with the PG2/PG adapter for single-cluster, custom S2S bridge for cross-grid (§4) | topic-per-fingerprint / topic-per-session-id routing instead of manual per-socket `async_write_frame` fan-out |
| Consistent routing (grid) | `libring` (consistent hashing) for "which cluster owns this fingerprint" lookups | avoids a global lock/registry across the whole grid |
| Build/release | `mix release` (self-contained OTP release, no Elixir/Erlang install needed at runtime in the image) | standard, reproducible, small final image |
| Containerization | Multi-stage Dockerfile, Ubuntu 26.04 builder → Ubuntu 26.04 (or `distroless`-style minimal) runtime | matches your OS priority; keeps OpenSSL 3.5.5 identical between build and run stages |
| Observability | `:telemetry` + `PromEx` (Prometheus) + Grafana; `Logger` with structured (JSON) backend | operational visibility from day one, not bolted on later |
| Tests | `ExUnit` + `StreamData` (property-based, good fit for protocol-framing edge cases) + a Common-Test-free integration harness reusing the existing `unit.sh` tmux scenario against the new server | keep the existing acceptance scenario as the migration's ground truth |

### 1.1 The one place "just apt-get it" is wrong, and why

Ubuntu 26.04's `elixir` package (`1.18.3.dfsg-1build1`) depends on `erlang-base (>= 1:27.3.4.6+dfsg)` — that is
**Erlang/OTP 27**. The native `ML-DSA`/`ML-KEM` support in `:crypto` (`crypto:sign/4`, `crypto:verify/5` for
`mldsa44/65/87`; `crypto:encapsulate_key/2`, `crypto:decapsulate_key/3` for `mlkem512/768/1024`) landed in
**OTP 28.1** (2025), and `:ssl`'s native ML-DSA certificate support plus `x25519mlkem768` becoming the
**default-preferred** TLS 1.3 group landed in OTP 29 (2026). **Installing Elixir via `apt-get install elixir` on
Ubuntu 26.04 as-is will silently give you an OTP 27 runtime with none of this project's required PQC primitives** —
this is exactly the kind of assumption this document should not let slide, so it is flagged explicitly rather than
glossed over.

**What to actually do:** build the Docker image's Erlang/OTP from source (or from Erlang Solutions' `esl-erlang`
packages, which track current OTP releases faster than Ubuntu's archive) at a pinned OTP 28 LTS-or-later version,
**configured against the same system OpenSSL 3.5.5** Ubuntu 26.04 already ships (`./configure
--with-ssl=/usr --with-ssl-lib-subdir=lib/x86_64-linux-gnu` or via `kerl`/`asdf` with the equivalent flags), so
the Elixir server's `:crypto`/`:ssl` and the (fixed) C++ client's OpenSSL-native ML-KEM/ML-DSA calls are drawing
on **the exact same OpenSSL implementation** — this is what makes the earlier "two libraries must agree on key
format" risk (audit §2.7) not just mitigated but structurally absent on the Elixir side: there is only ever one
OpenSSL doing the math, whichever side of the connection you're on.

Verify before building anything else: `erl -eval 'io:format("~p~n",[crypto:supports(public_keys)])' -s init stop`
should list `mldsa87`/`mlkem768` etc. on the OTP version you actually ship. Do not proceed to §3 until this passes
in the base image.

---

## 2. What does *not* change (and why that's the point)

- **The wire format.** `shared_net_common_protocol.h`'s frame layout (4-byte BE length prefix,
  `MSG_HELLO/CHAT/LIST_REQUEST/LIST_RESPONSE/PUBKEY_REQUEST/PUBKEY_RESPONSE`, field encodings) is kept
  byte-for-byte identical. This is what lets the (fixed) C++ client connect to the new Elixir server with **zero
  client-side changes**, and lets you cut over gradually (§5) instead of a big-bang rewrite.
- **The E2E crypto model.** Client-side ML-KEM/ML-DSA key exchange and per-message AEAD stay entirely
  client-to-client; the server never sees plaintext and never needs client identity secret keys. This project's
  "server cannot decrypt" design goal is preserved and, if anything, strengthened (Horde-based process isolation
  removes the shared-mutable-state bugs that plaintext-adjacent bookkeeping had in the C++ server).
- **What *does* change inside that model:** the specific bug fixes from `audit_code_bestpractice.md` §1 are
  implemented as the *correct*, *original* behaviour in the new server/client, not ported as-is. In particular:
  the AEAD nonce/key derivation gets the direction split (audit §1.1), and `MSG_HELLO`'s signature is extended to
  cover `username` (audit §2.4). These are wire-**compatible, additive** changes (new HKDF labels, one more field
  in the signed payload) that both the fixed C++ client and the new Elixir server must agree on — treat this as
  "protocol version 2" internally even though the frame format is unchanged, and gate it behind a capability the
  two sides negotiate (§5, Phase C) so the migration can be tested against an unfixed reference client too if
  needed for A/B comparison.

---

## 3. Elixir/OTP module map (1:1 mental model against the current C++ files)

This mapping exists so the conversion can be done piece by piece and checked off, not to imply the Elixir code
should structurally mirror C++ idioms.

| C++ source | Elixir/OTP replacement | Notes |
|---|---|---|
| `server/main.cpp` (accept loop, thread pool) | `Sprk.Server.Application` (OTP `Application`) + `Sprk.Server.Listener` (`:ranch` listener, `num_acceptors` tuned, `:ssl` transport) | BEAM's scheduler replaces the hand-rolled `hardware_concurrency()` thread pool; no manual thread management |
| `server/server_client_state.h` (`ClientState`) | `Sprk.Server.Connection` — a `GenServer`/`gen_statem` process, one per TLS connection | the process **is** the connection's state; no shared struct reachable from other connections |
| `server/server_session.h` (`SessionData`, `register_client`, `check_username_conflicts`, `cleanup_old_nickname`) | `Sprk.Server.Session` (a `Horde.Registry`-backed lookup: `{session_id, username}` → connection pid, `{session_id, fingerprint}` → connection pid) | registry entry lifecycle (register/replace/deregister) is a single atomic Horde operation — the audit §1.3 ordering bug has no equivalent to write, because there's no "read the old value from a struct I already overwrote" step; registering a new identity under an existing pid is just "update the registry entry for this pid," which Horde does correctly by construction |
| `server/server_handlers.h::handle_hello_message` | `Sprk.Server.Connection.handle_hello/2` | signature verification via `:crypto.verify(:eddsa \| :mldsa87, ...)` (exact primitive name per §1.1's `crypto:supports/1` check), Levenshtein/LCS-similarity check ported as a pure function with actual edit-distance (fixing audit §3.7 while we're here) |
| `server/server_handlers.h::handle_chat_message` | `Sprk.Server.Connection.handle_chat/2`, delivery via `Phoenix.PubSub.broadcast!(Sprk.PubSub, "fp:" <> recipient_fp, {:frame, bytes})` | no more manual `async_write_frame` to a `shared_ptr<ssl_socket>` reached through someone else's session map; delivery is "publish to this fingerprint's topic," and the recipient's own connection process is the only subscriber, so there is nothing for two threads to race on (audit §1.4 has no analogue) |
| `server/server_handlers.h::handle_list_request` | `Sprk.Server.Session.list_users(session_id)` reading the Horde registry | |
| `server/server_handlers.h::handle_pubkey_request` | `Sprk.Server.Session.lookup_pubkey/2` | |
| `server/server_connection.h::cleanup_disconnected_client` | `Sprk.Server.Connection.terminate/2` callback + Horde registry auto-cleanup on process exit | supervision + registry monitor does this for free; no explicit "did I remember to erase every map" checklist |
| `shared_net_tls_context.h` (server side) | `:ssl.listen/2` opts: `versions: ['tlsv1.3']`, `supported_groups: [:x25519mlkem768]` (no fallback group — closes audit §3.3), `signature_algs: [:mldsa87 \| ...]`, `verify: :verify_peer`, `fail_if_no_peer_cert: true`, `cacertfile:` | |
| `shared_net_rekey_util.h` (seq/gap/jitter, rate limit) | `Sprk.Server.Connection`'s internal state machine + a token-bucket module (`Sprk.RateLimiter`, backed by `:ets` counters or a proper library) | fix audit §1.5 (either honour the 100-message window for real, or shrink the documented window to match — decide explicitly, don't inherit the dead branch) |
| `user_keygen` (server-side use, if any — currently none) | n/a, keygen stays client-side | server never generates or holds E2E identity keys |

---

## 4. The "grid": cluster vs. federation, and why the distinction matters at 10M users

Two different distributed-systems problems are being asked for here, and conflating them is the single most
common mistake in this kind of design, so they are named explicitly:

- **Cluster** = a set of BEAM nodes you operate as one logical service, joined by (real, single-vendor) Erlang
  distribution, sharing one Horde registry and one `Phoenix.PubSub` fabric. Typically one datacenter/region, one
  operator, low-latency links between nodes (same DC or same cloud region). This is where you get horizontal
  scale-out for a single operator's user base.
- **Grid unit** = one such cluster, addressable from the outside as a single federation peer with its own TLS/
  ML-DSA server identity. **"The grid" is a federation of grid units**, potentially run by different operators,
  talking to each other over an explicit, versioned server-to-server (S2S) protocol over PQC-TLS — not joined by
  raw distributed-Erlang connections. This is deliberate: distributed Erlang's full-mesh, all-nodes-know-all-nodes
  model degrades badly past a few hundred nodes and over WAN links with real jitter/partition behaviour; it is the
  right tool *inside* a cluster/DC, and the wrong tool for *inter-operator, inter-region, "assume the network will
  partition"* federation. Treat inter-grid-unit traffic the way Matrix/XMPP treat server-to-server traffic: signed,
  authenticated, store-and-forward-tolerant messages between independently-operated services — not shared memory.

```
                                   ┌───────────────────────────────────────────┐
                                   │              GRID (federation)             │
                                   │                                            │
        ┌───────────────────┐  S2S (PQC-mTLS, signed)   ┌───────────────────┐  │
        │   Grid unit "eu1"  │◀─────────────────────────▶│   Grid unit "us1"  │  │
        │  (one BEAM cluster)│                            │ (one BEAM cluster) │  │
        │                    │  S2S                       │                    │  │
        │  N1  N2  N3 ... Nk │◀───────────────┐            │  N1  N2 ... Nm     │  │
        └─────────┬──────────┘                │            └─────────┬──────────┘  │
                   │ Erlang distribution        └── S2S ──▶ Grid unit "ap1" ────────┘
                   │ + Horde (CRDT registry)                (another operator, e.g.)
                   │ + Phoenix.PubSub
        clients ───┘
   (TLS-mTLS, x25519mlkem768, ML-DSA-87)
```

### 4.1 Inside one grid unit (cluster) — how "a server going down" is survived

- **Node loss inside the cluster:** `libcluster` (e.g. `Cluster.Strategy.Kubernetes` or `Cluster.Strategy.Gossip`
  for non-k8s deployments) detects the node leaving; `Horde.Registry`/`Horde.DynamicSupervisor` redistribute
  registry ownership and can restart supervised processes on a surviving node per your configured distribution
  strategy. **Live TCP connections terminated on the dead node are gone** (you cannot migrate a live kernel socket
  to another machine) — but the client's existing exponential-backoff reconnect logic (already implemented,
  correctly, in `client_session.h`/`main.cpp`'s `run_reconnect_loop`) reconnects to the cluster's virtual
  IP/load-balancer, lands on a *surviving* node, and re-establishes the E2E session exactly as it already does for
  the `unit.sh` "Ron reconnects" scenario today — no client-visible change needed for this case.
- **Presence/session directory survives the node loss** because it lives in Horde's CRDT-replicated registry
  (replicated across a configurable set of member nodes), not in one process's private map — this is the direct,
  structural fix for what the C++ server's single unguarded `unordered_map` could never survive.
- **In-flight, undelivered messages on the dead node are lost in the prototype phase** (this project is
  documented as in-memory-only today, and that is an acceptable, explicitly-scoped prototype limitation — see
  §7 for the hardening step once you're past prototype). Document this trade-off in the same place the README
  documents "in-memory only (no persistence)" today, rather than silently changing the guarantee.
- **Load balancing / entry point:** a TLS-terminating-or-passthrough L4 load balancer (or, for full E2E-preserving
  passthrough, an SNI-routing TCP proxy so client↔server TLS stays a single unbroken PQC handshake — do **not**
  terminate the client's TLS at a proxy and re-originate a second TLS hop to the node, since that reintroduces a
  server-side plaintext-adjacent hop this project's design explicitly avoids) with active health checks removes
  dead nodes from rotation within seconds.

### 4.2 Across grid units — how "a whole datacenter/operator goes down" is survived

- Each grid unit publishes (out of band, e.g. DNS + a small signed manifest, analogous to Matrix's
  `.well-known/matrix/server` + server keys, or an XMPP-style federation directory) its **S2S TLS endpoint and
  ML-DSA server public key**. Clients are provisioned with (or discover via that same directory) more than one
  grid-unit entry point for their home realm, so a client whose home unit is fully down can, per your product
  decision, either (a) queue locally and retry the same home unit (simplest, matches "eventually consistent chat"
  expectations most users already have), or (b) fail over to a designated secondary unit for the same realm if you
  operate active-active pairs — (a) is the recommended **prototype-phase** answer; (b) is a §7 hardening item once
  real multi-region active-active replication of identity/session state exists.
- **Cross-unit messaging (Alice on `eu1`, Bob on `us1`):** the S2S protocol carries the *same* `MSG_CHAT` frame
  the clients already exchange, wrapped in an S2S envelope (`from_unit`, `to_unit`, delivery metadata, S2S-layer
  signature by the sending unit's ML-DSA server key) — the receiving unit's `eu1`/`us1` boundary node verifies the
  S2S signature (trust: "did this really come from a unit I federate with"), then delivers the inner, still
  client-E2E-encrypted `MSG_CHAT` frame to Bob's connection process exactly as if it had originated locally. **The
  federating server never gains any additional decryption capability** — S2S signing authenticates *server
  origin*, not message content, preserving the "server cannot decrypt" property across the whole grid, not just
  within one unit.
- **A whole grid unit being down does not affect other units**: by construction, there is no cross-unit shared
  state (no cross-DC distributed-Erlang mesh, no cross-DC Horde registry) — only asynchronous, retryable S2S
  messages between independently-supervised services. This is the actual answer to "if one server goes down, the
  chat system continues operation" at the scale where "one server" means "one entire operator's cluster," not just
  one machine.

---

## 5. Stepwise conversion plan

Each phase is validated against the existing `unit.sh` scenario (or an extended version of it) **before** moving
to the next, and each phase after Phase A can run side-by-side with the still-live C++ server for comparison
testing (different port).

**Phase A — TLS + framing skeleton, no protocol semantics.**
`:ranch` + `:ssl` listener that accepts the same mutual-TLS handshake (`x25519mlkem768`, ML-DSA server/client
certs against the same `sample/sample_test_cert/ca.crt`), reads/writes the 4-byte-length-prefixed frame format,
and echoes frames back. Validates: TLS interop between OTP's `:ssl` and the C++ client's OpenSSL-based TLS stack
(this is the first real-world checkpoint for §1.1's OTP/OpenSSL version requirement), and the frame codec module
(`Sprk.Protocol` — an Elixir port of `shared_net_common_protocol.h`'s encode/decode, with `StreamData`-based
property tests fuzzing the same boundary conditions `audit_code_bestpractice.md` §6's `proto_test.cpp` already
exercises: oversized username, truncated frame, session_id length, empty vs. populated optional fields).

**Phase B — Session registration (`MSG_HELLO`), single node.**
Implement `Sprk.Server.Session`'s Horde-backed registry, `handle_hello` including signature verification and the
(correct, edit-distance) username-similarity check. Validate against `unit.sh`'s Ron/Beth/Bob connect + `list
users` scenario, single node, no clustering yet.

**Phase C — Chat relay + rekey + protocol-v2 crypto fixes.**
Implement `MSG_CHAT` relay via `Phoenix.PubSub`, port the sequence/replay logic with the audit §1.5 decision made
explicitly (recommend: honour the full jitter/gap window for real this time), and land the "protocol v2" crypto
fixes from §2 above (direction-split AEAD keys, username-covered HELLO signature) **on both the fixed C++ client
and this server simultaneously** — this is the natural point to do it, since you are already touching both sides'
`MSG_HELLO` handling. Validate against `unit.sh`'s full triangular-messaging + multi-recipient + reconnect
scenario end to end against the new server.

**Phase D — Single-cluster horizontal scale.**
Add `libcluster` + multi-node Horde/PubSub, run 3+ nodes in `docker-compose` behind a local load balancer
(`haproxy`/`nginx` stream mode, or `envoy` for SNI passthrough), and specifically **test node-kill-under-load**:
connect N synthetic clients, kill one node, assert survivors' Horde registry entries redistribute and killed
node's clients reconnect and resume messaging within the client's existing backoff window. This is the direct,
executable proof of §4.1.

**Phase E — S2S federation (two grid units).**
Stand up a second independent `docker-compose` cluster ("unit B") with its own CA/ML-DSA server identity, define
and implement the S2S envelope + boundary-node verification from §4.2, and test cross-unit messaging plus
"kill unit B entirely, unit A keeps serving its own users uninterrupted" as an explicit test scenario. This is
where the "grid" claim gets an actual test, not just a diagram.

**Phase F — Load/capacity validation toward the 10M target.**
See §6. Do this after F, not before — capacity numbers on an unfinished protocol implementation are not
meaningful.

**Phase G — Operational hardening.**
See §7 (secrets, durability, rate limiting, observability, chaos testing as a standing CI job, not a one-off).

Sequencing note: Phases A–C can be done by one engineer in the current single-server C++ mental model; Phases D–E
are where the "grid" design actually needs to exist as running code, not just a diagram, before any capacity
claims in §6 can be trusted.

---

## 6. Capacity plan toward "10 million concurrent users"

Numbers below are sizing methodology, not a guarantee — validate every assumption against Phase F's actual load
tests on your real hardware/cloud instances before committing to a production capacity plan.

- **Per-connection cost, BEAM side:** a `GenServer`/`gen_statem` process holding a TLS-terminated connection plus
  this protocol's per-peer state (a handful of binaries and small maps — comparable in shape to the C++
  `PeerInfo`/`ClientState` structs) is realistically tens of KB per connection including the TLS session state,
  not counting socket buffers. This is the same regime BEAM-based systems have run at multi-million-connection
  scale in production for over a decade (this is Erlang's original design target — telecom-scale concurrent
  sessions — and is well-trodden ground, not a novel claim being made for this project specifically).
- **Per-connection cost is higher here than for classical TLS** because of PQC handshake/material sizes: ML-DSA-87
  certificates/signatures (~2.6 KB pubkey, ~4.6 KB signature) and ML-KEM-768/1024 hybrid key shares are larger
  on-wire than ECDHE, and the *first* `MSG_HELLO` per session involves an ML-DSA-87 sign/verify (measured
  elsewhere in the ~0.3–1 ms per-operation range on modern x86_64 — verify this on your actual target hardware in
  Phase F, do not take a third-party benchmark as your production number) plus, on rekey, another such
  sign/verify per peer pair every 1024 messages. **Budget CPU for signature operations, not just socket I/O**;
  Erlang's `:crypto` NIFs run these as "dirty CPU" scheduled operations specifically so they don't block the BEAM
  schedulers handling everyone else's message relay — confirm this is still the case for whichever OTP/crypto
  version you pin (§1.1) rather than assuming it.
- **Sizing math (illustrative, re-derive from your own Phase F numbers):** if a tuned node comfortably holds
  200,000–500,000 concurrent idle-ish connections (a conservative band for this workload shape; validate, don't
  assume), 10,000,000 concurrent users needs on the order of **20–50 nodes per grid unit** if concentrated in one
  unit, or fewer per unit if the 10M is spread across several grid units/regions (which is also the more realistic
  real-world deployment shape, and the one this architecture is actually designed for — see §4). Either way, size
  in terms of "how many grid units, how many nodes per unit," not "one giant cluster," because a single Horde/
  distributed-Erlang mesh spanning dozens of nodes across multiple regions is exactly the WAN full-mesh anti-pattern
  §4 argues against; keep individual clusters regional and let the grid do the geographic spread.
- **OS/kernel tuning required regardless of language:** raise `ulimit -n` and `net.core.somaxconn`, enable
  `SO_REUSEPORT` with multiple acceptor processes per node (`:ranch`'s `num_acceptors` plus, if needed, multiple
  listen sockets), tune `net.ipv4.tcp_*` buffer/backlog settings, and give BEAM's `+P` (max processes) and `+Q`
  (max ports/sockets) generous headroom above your target connections-per-node — these are the same knobs any
  C10M-class service needs (this is not Elixir-specific), and are exactly the kind of thing that must be measured
  on your real container/VM/bare-metal target in Phase F, not assumed from a blog post.
- **The message-relay steady state is cheap** relative to connection/handshake cost: once a session is
  established, relaying an already-AEAD-encrypted `MSG_CHAT` frame is a `PubSub.broadcast!` plus a socket write —
  no additional cryptographic work happens on the server for message relay, by design (the server never decrypts).
  This means steady-state capacity is dominated by connection count and handshake/rekey rate, not by message
  throughput — plan load tests accordingly (stress connection churn and rekey cadence, not just messages/sec).

---

## 7. Operational security for a global platform (beyond prototype, sequence explicitly)

These are called out separately from §5's functional phases because they are cross-cutting and easy to
under-invest in during a "get it working" migration — put dates/owners on these before declaring the migration
"production-ready," not just "feature-complete":

1. **Secrets management.** No CA/server/identity private key ever goes in the Docker image, a git repo, or an env
   var dumped to logs (this is the direct fix for audit §2.6). Use Docker/Kubernetes secrets, or better, a real
   secrets manager (HashiCorp Vault, cloud KMS) with short-lived credentials for anything the server itself needs
   (its own ML-DSA server identity for S2S/TLS) — the server never needs, and must never be given, a client's E2E
   identity secret key.
2. **Rate limiting and abuse resistance, enforced this time.** Audit §1.3/§3.8 exist partly *because* the C++
   server has no rate limiting at all (documented as a known gap). Implement per-connection and per-source-IP
   token buckets before Phase D's multi-node test, since a single abusive connection now has more surface (federated
   HELLO fan-out, cross-unit S2S) to amplify against if left unbounded.
3. **Durability, decided explicitly, not left in ambiguous "prototype" (as in-memory today, one line, silently
   accepted).** Before any production commitment, decide and document: does an offline recipient's message wait
   somewhere (a durable outbox — Mnesia with disc_copies for small scale, or a proper distributed store —
   PostgreSQL, FoundationDB, or a Kafka-style log — for real scale) or is undelivered-while-offline defined as
   "lost, by design" (a valid product choice for some chat systems, invalid for others)? This decision changes
   the Phase E/§4.2 federation design (a durable outbox needs retry/ack semantics on the S2S link; fire-and-forget
   does not), so make it before, not after, building S2S.
4. **Observability without leaking secrets.** Structured logs and Telemetry/Prometheus metrics must never include
   key material, plaintext usernames-to-fingerprint mappings beyond what operational necessity requires, or
   anything that would turn "the server can't decrypt messages" into "the server's logs are a side channel that
   reconstructs who talked to whom, when, and how much" — decide a metadata-minimization policy explicitly (this
   is a privacy/zero-trust requirement, not just an infra nicety, for a platform whose entire pitch is
   confidentiality).
5. **Supply chain.** Pin `mix.lock`, run `mix hex.audit`/`mix deps.audit`-equivalent tooling in CI, build
   reproducible Docker images (pinned base image digest, not `:latest`), and generate an SBOM for both the Elixir
   release and the OTP build baked into the image (relevant given §1.1's "don't just trust the distro package"
   finding — track exactly which OTP source/commit you built, not just "whatever was in the container").
6. **Chaos testing as a standing job, not a one-time demo.** Turn Phase D/E's node-kill and unit-kill tests into a
   recurring CI/staging job (kill a random node or a random grid unit on a schedule against a staging deployment
   under synthetic load) so a regression in Horde configuration, S2S retry logic, or client reconnect behaviour is
   caught automatically rather than rediscovered during a real incident.

---

## 8. Minimal Docker/dev-environment skeleton (illustrative structure, not a final Dockerfile)

```
docker/
  Dockerfile.otp-builder      # builds Erlang/OTP (pinned commit/tag, >= 28.1) against Ubuntu 26.04's OpenSSL 3.5.5
  Dockerfile.server           # multi-stage: FROM otp-builder AS build (mix release) -> FROM ubuntu:26.04 AS runtime
  docker-compose.dev.yml      # N=3 server nodes + haproxy/envoy front + a headless C++ test-client image, one network per "grid unit"
  docker-compose.grid.yml     # two docker-compose "grid unit" stacks + an S2S bridge network between only their boundary nodes
apps/
  sprk_protocol/              # Sprk.Protocol - frame codec, StreamData property tests (Phase A)
  sprk_session/               # Sprk.Server.Session - Horde registry wrapper (Phase B)
  sprk_relay/                 # Sprk.Server.Connection, PubSub relay (Phase C)
  sprk_federation/            # S2S envelope, boundary-node verification (Phase E)
  sprk_server/                # Application/Supervisor wiring, :ranch/:ssl listener, releases config
```

Keep each `apps/*` as its own umbrella app from the start (even though the prototype only needs `sprk_server` to
run) — it is what makes Phase E's federation code addable without restructuring Phases A–D's work, and it gives
you natural ExUnit test boundaries matching the phase list in §5.
