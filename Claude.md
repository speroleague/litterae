# Self-Hosted Mail Server — Implementation Handoff

**Audience:** Claude Code, building from scratch.
**Status:** Design locked for v1. This document is the source of truth. When something here conflicts with a habit or a tutorial, this wins.
**One-line goal:** A single Rust binary that is a complete, modern, privacy-respecting mail server (SMTP in/out + JMAP + storage + encryption-at-rest) for one operator's domain(s) and a handful of hosted accounts. Replaces Stalwart. JMAP-first, no IMAP in v1.

---

## 0. Read this first: what we are and are not building

**The crypto defends exactly one threat: offline seizure of powered-off or locked storage** (theft, subpoena, cloud-disk imaging, a curious VPS provider peeking at rest). That is a real and worthwhile threat. It is the *only* thing the at-rest hierarchy defeats.

It does **not** defend against: a live attacker with code execution on the running host, RAM disclosure while the mailbox is unlocked, or the brief plaintext window every message passes through at ingest. Do not write code, comments, or docs that imply otherwise. Honesty in the threat model is a feature.

**Non-negotiable guardrails (violating these is a bug):**
- Do **not** advertise or implement "post-quantum at rest" in v1. Use classical X25519 HPKE. The crypto-agility header (below) is what makes PQ a later drop-in. (Reason: no audited PQ-HPKE Rust crate exists as of mid-2026; `aws-lc-rs` HPKE is classical-only.)
- Do **not** build per-thread / per-label / per-contact **cryptographic** keys in v1. Categories are *metadata*, not separate keypairs. The only cryptographic isolation boundary is the **account** (tenant). See §4.
- Do **not** claim "zeroize on lock" as a guarantee. It is best-effort defense-in-depth. See §9.
- Inbound port 25 must **never** require TLS. Opportunistic STARTTLS only. Requiring it silently loses mail.
- Every credential-bearing auth path (submission, JMAP) is **TLS-only, no exceptions**.
- Never let a `<form>`-style unauthenticated path reach private network ranges (SSRF). Blob fetch, push targets, autoconfig — all must refuse RFC1918/loopback/link-local.

---

## 1. Architecture: one binary, many listeners

At personal + small-tenant scale, resist microservices. One tokio runtime, several listener tasks, one storage layer, shared over internal channels. One systemd unit, one config file, one process to reason about.

```
crates/
  common       # config, error types, tracing, the crypto-agility header, shared types
  crypto       # all cryptographic operations live here and NOWHERE else (see §3)
  store        # content-addressed blob store + SQLite metadata + FTS index mgmt
  dns          # hickory wrappers: MX, SPF, DKIM DNS, DANE/TLSA, MTA-STS fetch
  auth         # SASL mechanisms, argon2id, session tokens, account/tenant model
  smtp-in      # inbound MTA state machine (port 25)
  submission   # 587/465: SASL auth -> validate -> enqueue
  queue        # outbound: SQLite-backed durable queue, worker, retry/backoff, DSN
  delivery     # internal delivery: classify -> seal -> blob write + metadata
  jmap         # axum HTTP: JMAP core (8620) + mail (8621), SSE push
  audit        # hash-chained append-only encrypted audit log
  server       # THE BINARY: config load, runtime, wire listeners, graceful shutdown
web/           # SvelteKit + Phosphor icons frontend (separate deploy, talks JMAP)
```

**Rule:** `crypto` is the only crate that imports a cipher/KEM/KDF. Everything else calls typed helpers (`seal_dek`, `open_dek`, `wrap_amk`, `derive_pk`, …). This keeps the agility header enforced in one place and makes the eventual PQ migration a one-crate change.

**Concurrency shape:** async I/O everywhere; **synchronous crypto and SQLite on a blocking pool** (`spawn_blocking`), passing *references into pinned secret memory*, never owned copies of secrets, across the boundary. See §9.

---

## 2. Crate selection (pinned intent, verify versions at build time)

These are decisions, not suggestions. Re-verify exact versions and advisory status before committing `Cargo.lock`.

| Concern | Crate | Notes |
|---|---|---|
| Async runtime | `tokio` | full features |
| TLS | `rustls` + `tokio-rustls`, provider `aws-lc-rs` | aws-lc-rs gives FIPS-track primitives + the PQ **TLS** key exchange X25519MLKEM768 for submission/JMAP |
| MIME / RFC 5322 parse | `mail-parser` | Stalwart's crate. Do NOT hand-roll MIME. Track its advisories (see §8). |
| Email auth | `mail-auth` | SPF, DKIM sign+verify, DMARC, ARC. |
| Message build | `mail-builder` | outbound + DSN construction |
| Outbound SMTP client | `mail-send` | used by the queue worker |
| DNS | `hickory-resolver` | MX, TXT (SPF/DKIM/DMARC/MTA-STS), TLSA (DANE) |
| HTTP / JMAP | `axum` + `serde_json` | SSE via axum's response stream |
| SQLite | `rusqlite` on blocking pool | queue + metadata. NOT `sqlx` (async layer is slower/heavier for SQLite here). |
| HPKE | `hpke-rs` **or** `rust-hpke` | **classical X25519 DHKEM only in v1.** Whichever is better maintained at build time. |
| AEAD | `chacha20poly1305` (XChaCha20-Poly1305) | per-message DEKs |
| KDF | `argon2` | Argon2id |
| Committing AEAD helper | implement in `crypto` | zero-prefix padding fix, see §3.4 |
| Secret hygiene | `zeroize` (+ `Zeroizing`) | best-effort; understand its limits (§9) |
| Supply chain | `cargo-vet` + `cargo-audit` in CI | pin, vendor, deny on advisory |

**The irony to embrace, not fight:** we replace Stalwart-the-*server* (to escape its paywalled features) while standing on Stalwart-the-*crates* (`mail-parser`, `mail-auth`, `mail-send`) for the miserable, dangerous-to-hand-roll standards work. That is correct. Writing our own MIME parser would be weeks of malformed-real-world-mail edge cases and a fresh RCE surface.

---

## 3. Cryptographic design (v1)

### 3.1 The one principle everything derives from
**The locked server is a pure producer.** With no password in memory, it can *only seal to public keys*. Nothing it does at rest can decrypt anything. Accepting mail, writing blobs, appending audit entries — all are public-key seals. Every read requires the password. Hold this and the rest follows.

### 3.2 Key hierarchy (COLLAPSED from the original per-category fan-out)

```
password ──Argon2id(salt, params)──▶  PK   (password-derived key; never stored, never at rest)
                                       │ committing-wrap
                                       ▼
                                  AMK  (Account Master Key — random 256-bit symmetric)
                    stored on disk as  commit_wrap(PK, AMK)   ← the ONLY thing PK touches
                                       │ wraps
                    ┌──────────────────┼───────────────────┬─────────────────┐
                    ▼                  ▼                   ▼                 ▼
              account HPKE        index_priv           audit_priv      (recovery path:
              keypair (priv)      (search)             (log read)       commit_wrap(RK, AMK))
              wrap(AMK, priv)     wrap(AMK, priv)      wrap(AMK, priv)
                    │
   account.pub is CLEARTEXT (server seals inbound mail to it while locked)
                    │
                    ▼
              per-message DEK  (random 256-bit, XChaCha20-Poly1305)
              blob = AEAD(DEK, plaintext_message)
              dek_wrap = HPKE_seal(account.pub, DEK)      ← classical X25519 DHKEM in v1
```

**Why AMK indirection** (do not skip it): password change = re-wrap *one* 32-byte blob, not re-encrypt the mailbox. It also lets multiple unlock paths (password, recovery key, future second device) each independently wrap the same AMK.

**What changed from the design conversation and why:** the original plan gave every domain/contact/thread/label its own HPKE keypair with OR-semantics (a message readable via any of its category keys). Research verdict: this multiplies key management and rotation cost (rotation becomes O(messages in category)), builds a rich cleartext "which keys sealed this" metadata graph, is done by *no* production system, and its benefit evaporates the instant the account unlocks (AMK opens everything anyway). **v1 uses a single account keypair.** Category compartmentalization is preserved at the *metadata* layer (§4) and left as a clearly-marked crypto extension point (§10) for the one case that justifies it: true multi-tenant isolation, where the **tenant/account is the crypto boundary**.

### 3.3 Ingest while locked (the subtle part, still needed)
Inbound mail arrives 24/7 while the mailbox is locked. Because `account.pub` is cleartext, the fully-offline path is trivial: fresh DEK → `AEAD(DEK, msg)` → `HPKE_seal(account.pub, DEK)` → write blob + metadata. No AMK needed. Done.

Because we collapsed to one account key, **the provisioning channel for minting new category keypairs while locked is NOT needed in v1.** (It was only necessary because new categories needed private keys wrapped under an absent AMK.) This removes an entire subsystem and two ambient keypairs. Keep the pattern documented in §10 for if/when per-tenant keys arrive — a *new tenant* is provisioned by an authenticated admin action (unlocked), so even then the locked-mint channel may be unnecessary.

Two ambient inbound-only pubkeys remain, each with its private half wrapped under AMK and drained on unlock:
- `index_pub` — search fragments written while locked (§5).
- `audit_pub` — audit entries appended while locked (§6).

### 3.4 Key commitment (REQUIRED on password-derived wraps)
XChaCha20-Poly1305 and HPKE's AEAD are **not key-committing**. Partitioning-oracle attacks (Len–Grubbs–Ristenpart, USENIX 2021) exploit this *when keys are low-entropy* — i.e. exactly the **password-derived** layers. Per-message DEKs are full-entropy 256-bit and safe as-is.

So: the `PK → AMK` wrap and the `RK → AMK` (recovery) wrap **must use a committing construction.** Implement in `crypto`:
- Prepend a fixed all-zero prefix (≤ 512 bits / 4 blocks) to the plaintext before AEAD; on decrypt, verify the prefix is intact in constant time before accepting. (Albertini et al., USENIX 2022, ePrint 2020/1456.)
- Alternative: Encrypt-then-HMAC-SHA-256.
- Reference RFC 9771 for the formal property.

Do not skip this because it "seems fine." It is the difference between a password-guess oracle existing or not.

### 3.5 Primitives (stated so they are never silently swapped)
- **AEAD (message blobs & wraps):** XChaCha20-Poly1305. 192-bit nonce → random nonces are collision-safe with no counter coordination, which matters because DEKs are minted concurrently across the delivery path. Fresh random DEK per message means cross-message nonce reuse is a non-issue regardless.
- **KDF:** Argon2id. **Params floor: m = 64 MiB, t = 3, p = 4** (RFC 9106 second-recommended). Tune upward toward ~0.5–1.0 s wall-clock for unlock on the target host. The OWASP 19 MiB minimum is too low for a master-key unlock.
- **Public-key seal:** HPKE (RFC 9180) base mode, **classical X25519 DHKEM** in v1. Base mode is unauthenticated — that is fine (anyone may write to your inbox; that is email), but it means the seal proves nothing about *who* wrote it. Carry DKIM/ARC verification results and sender identity as separate authenticated metadata, never inferred from the seal.

### 3.6 The crypto-agility header (make PQ a drop-in)
Every wrapped/sealed blob on disk starts with a fixed header: `magic | version:u8 | alg_id:u16 | key_id:u16 | nonce…`. `crypto` dispatches on `alg_id`. This is cheap now and is the *entire* reason migrating DEK sealing to X-Wing HPKE (X25519+ML-KEM-768) later touches no plaintext and no other crate. Get this right in week one.

### 3.7 Rotation / revocation / recovery (with the honest caveats)
- **Password change:** re-wrap AMK under new PK. One blob. Trivial.
- **Account key rotation:** mint new account keypair; for each message, `open_dek(old_priv)` → `seal_dek(new_pub)`; replace wraps. O(messages) but single-key, scriptable. Keep old priv marked decrypt-only until done. **Must be crash-safe** (§7): a crash mid-rotation must never leave a message with no valid wrap.
- **Revocation = rotation**, with the caveat stated in code comments and docs: anything already sealed to the old pub *and already exfiltrated* stays readable to whoever holds the old copy. Inherent, not a flaw. Say it out loud.
- **Recovery:** generate a random recovery secret, store `commit_wrap(RK, AMK)`, print once at setup. It is a second standing path to AMK — treat with the same committing-AEAD care; document it as escrow-shaped. Losing both password and recovery key = mailbox is unrecoverable **by construction**. That is the point; there is no backdoor.
- **AMK compromise = catastrophic but recoverable:** full re-key (new AMK, unwrap+rewrap every dependent priv, rewrap under PK). Build and test this path early while data is small.

---

## 4. Categories as metadata (not crypto) — grouping, threads, filters

Everything the user experiences as "all mail from Kristine / on the ETT domain / this thread / this label" is a **membership lookup**, not search, and not a separate key.

- `message ↔ category_id` table: **cleartext integer IDs**, plus a **separately-encrypted `category_id → identity` map** (sealed to the account key). At rest an attacker sees an opaque graph ("msg 41 ∈ {7,12,30}") but not what 7/12/30 *are*. Mild cluster-structure leakage; acceptable.
- This serves **all** structured filtering, sorting, and grouping **while the body index is still sealed** — because it needs no plaintext bodies.
- **Threads:** JMAP has a native `Thread` object (RFC 8621). Thread by `References` / `In-Reply-To`, normalized-subject fallback. The same classifier that assigns thread membership feeds the category table.
- **Groupings:** Mailboxes (folders) + Keywords (labels), standard JMAP.

**Design consequence to enforce:** any "auto-file by body keyword" rule needs plaintext, so it runs **at ingest** (in the plaintext window) or not at all — never as a background job over a locked mailbox. Filters over headers/sender/domain can run anytime (no body needed).

---

## 5. Search (encryption-vs-search, resolved)

Split into two problems:
1. **Structured filters** → §4, free, works while locked.
2. **Full-text body search** → the actual crux, below.

**v1 approach: session-scoped in-RAM plaintext index.**
- At rest: the index is an **opaque AEAD blob** — zero queryable structure, leaks only its size.
- On unlock: decrypt into RAM, run a **real plaintext index** (start with **SQLite FTS5 in `:memory:`**; interface kept small so it can be swapped for **tantivy** later for better ranking). Full phrases/stemming/ranking for the session.
- On lock / idle-timeout: drop it (best-effort zeroize, §9).

**Indexing while locked:** at ingest (plaintext briefly in RAM anyway), tokenize the body, build that message's posting contribution, `HPKE_seal(index_pub, contribution)`, store as a **pending fragment** (write-only; the locked server can add to the corpus but cannot query it). On unlock, `open` fragments with `index_priv`, merge into the in-RAM index, delete fragments.

**Why not SSE/ORAM/PIR:** those defend a *continuously-untrusted server observing every query* — a cloud you don't own. You own the box; that model doesn't apply, and persistent encrypted indexes keep falling to leakage-abuse attacks (2024–2026 literature). Correct to reject them. Document that you are choosing *not* to use them, so it reads as a decision, not an oversight.

**KNOWN LEAK to mitigate, not ignore:** the *set* of pending fragments leaks volume metadata (fragment count ≈ message count, size ≈ length, timing ≈ arrival) — the same leakage class SSE attacks exploit. **Mitigation: fixed-size buckets + padding** for fragments. If that proves annoying in practice, the fallback is to drop the locked-indexing channel entirely and only index on unlock from the already-sealed message blobs (simpler, at the cost of "search misses mail that arrived while locked until next unlock-merge"). Decide during Phase 4; default to bucketing.

**Honest residual (put in user-facing docs):** full-text search is a *present-and-unlocked* operation. No searching a locked mailbox.

---

## 6. Audit log

Append-only, tamper-evident, encrypted.
- Each entry: `prev_hash` (hash chain) over the entry, so retroactive edits are detectable.
- **Chain over a keyed hash of the plaintext, then seal the detail to `audit_pub`.** This way integrity is verifiable while locked, but entry *contents* only become readable after unlock. (If you chain over ciphertext instead, you can't read your own log during incident response while locked — avoid that.)
- Periodically **sign the chain head.**
- **Log the control plane heavily, the data plane minimally:** every auth, session open/close, key unwrap, JMAP object read, admin action, config change, outbound send. Do **not** log plaintext bodies, and give originating IPs a short TTL. On a single-operator server the audit trail is *your* forensic capability, not surveillance — that framing keeps it consistent with the privacy goal.
- **Extension point (§10):** witness cosigning (Sigsum-style) or external anchoring (OpenTimestamps) if you ever need to defend against the *host itself* rewriting its log (split-view/equivocation). Overkill for v1.

---

## 7. Storage & crash-safety

- **Blobs:** content-addressed (hash → dedup + integrity check), AEAD under per-message DEK. Maildir-style **write-to-tmp then atomic rename** for crash-safe writes.
- **Metadata + queue + category tables:** SQLite (WAL mode). One file, trivially inspectable, durable.
- **Crash-safe key operations (easy to get wrong):** rotation/re-key rewrites many wraps; a crash mid-operation must leave *every* message with at least one valid wrap. Use SQLite transactions for the wrap-swap; keep old key material decrypt-only until the new wraps are committed and fsync'd.
- **Crypto-erase reality:** deleting a DEK row from SQLite does **not** erase it from SSD (wear-leveling). True erase-by-deletion requires the whole store under a single rotatable master — i.e. run the filesystem on **LUKS**, and treat LUKS + AMK-rotation as the actual "make it unrecoverable" mechanism. Document this; don't imply row-deletion shreds data.

---

## 8. Network listeners & hardening

### 8.1 Inbound SMTP (port 25)
State machine: connect → EHLO → **opportunistic STARTTLS** → MAIL FROM → RCPT TO → DATA. On arrival run SPF / DKIM-verify / DMARC (via `mail-auth`), score spam (rspamd out-of-process, or a simple internal scorer to start), then hand to `delivery`. **Bound parser memory** and reject oversized DATA early.

### 8.2 Submission (587 STARTTLS / 465 implicit TLS)
**TLS mandatory.** SASL auth (PLAIN/LOGIN over TLS only; SCRAM later). On success → validate sender identity against the authed account → enqueue. Prevent open relay: authed accounts may only send as identities they own.

### 8.3 Outbound queue (the piece everyone underestimates — design carefully)
Durable SQLite-backed queue with a worker:
- MX lookup (hickory) → connect (opportunistic STARTTLS; enforce DANE if a TLSA record is present) → send via `mail-send`.
- **Retry with backoff.** Distinguish **4xx (transient → retry with increasing delay, cap attempts/age)** from **5xx (permanent → stop, generate DSN)**.
- **DSN / bounce generation** via `mail-builder`.
- **DKIM-sign every outbound message** (non-negotiable post-2024; see §8.5).
- This is also the **reminder/scheduler engine** (§8.6) — same durable wakeup mechanism.

### 8.4 JMAP (axum, HTTPS) — hardening checklist (learn from Stalwart CVEs)
- **TLS-only; TLS-only auth.** Restrict PLAIN/LOGIN to TLS sessions.
- **Separate admin from user.** Admin principals must never reach user JMAP/mail objects.
- **Per-endpoint ACLs.** The HTTP listener also fronts `.well-known`, autoconfig, metrics, SSE — expose only what's served.
- **SSRF protection.** Blob download, push/webhook targets, autoconfig fetch: refuse loopback/RFC1918/link-local. (Apache James defaults this on; we implement it explicitly.)
- **Bound and fuzz parsers.** Stalwart shipped CVE-2025-61600 (parser memory-exhaustion) and CVE-2025-59045 (recurrence-expansion 2GB blowup). We reuse `mail-parser` — **track its advisories in `cargo-audit`** and cap request/object sizes and expansion counts.
- Upload quotas, max object sizes, scoped **application passwords**, **TOTP/MFA for admin**.
- Implement JMAP's method-batching model yourself (no server framework exists) — this is the *fun* from-scratch part, low-risk.

### 8.5 Deliverability (2025-2026 requirements — mandatory, not optional)
For Gmail/Yahoo/Microsoft acceptance:
- **SPF + DKIM both present**; **DKIM 2048-bit**, overlapping-selector rotation; consider Ed25519 (RFC 8463) as a second signature.
- **DMARC** at least `p=none` with alignment; move toward enforcement.
- **PTR / forward-confirmed reverse DNS** matching the sending hostname.
- **MTA-STS + DANE (TLSA) + TLS-RPT** — deploy **all three** (MTA-STS reaches DANE-blind senders like Google/Yahoo; DANE needs a DNSSEC-signed chain, DANE-EE SPKI SHA2-256).
- **One-click unsubscribe (RFC 8058)** for any bulk/list mail, honored ≤ 2 days.
- Spam rate < 0.3% (aim < 0.1%). TLS in transit. Strict RFC 5322.
- **Architect DKIM signing so DKIM2 can slot in** (WG-adopted draft, provider deployment forecast ~end 2026). Keep ARC (still requested by forwarders) but know it's being reclassified Historic.
- **Confirm the host's port 25 outbound isn't blocked and the IP has clean reputation** — warm a fresh IP; monitor Spamhaus/UCEPROTECT.

### 8.6 Reminders / scheduled events
Reuse the queue worker. Add a `scheduled_events` table (snooze-until, remind-at, "nudge if no reply by T"). Worker's next-wakeup query fires them; delivery is a push over the **same SSE channel** JMAP already uses. Snooze = hide until T then resurface; follow-up nudge = a watcher checking thread reply-state at fire time.

---

## 9. Secret hygiene under async Rust (be honest about limits)

**"Zeroize on lock" is best-effort, NOT a guarantee.** Reasons, and what to do:
- Rust **move semantics copy bytes**; tokio moves futures across threads at every `.await`. A secret held across `.await` may be memcpy'd, leaving an un-zeroized copy. `spawn_blocking` copies args onto another stack.
- `zeroize`'s `Vec`/`String` impls "cannot guarantee copies weren't made by prior reallocation." → **Never let secret buffers realloc.** Pre-size, or use fixed `[u8; N]` inside `Zeroizing`.
- **Rules:**
  - Keep long-lived secrets (AMK, account priv, index/audit priv) in a **single pinned, `mlock`'d, `Zeroizing` allocation**, accessed only by `&`-reference, never moved by value across `.await`.
  - Do crypto in **synchronous** helpers (or `spawn_blocking` passing *references into pinned memory*, not owned secret copies).
  - **Disable swap and hibernation on the host** regardless of mlock (mlock has small default `RLIMIT_MEMLOCK`; needs raised limit / `CAP_IPC_LOCK` for a multi-MB index — and doesn't stop the move-copies anyway).
  - Accept and document that the **decrypted search index cannot be reliably zeroized or fully mlock'd** — another reason to keep it minimal and consider dropping the locked-indexing channel if it grows hairy.
- Treat all of the above as **defense-in-depth**, and say so in comments. The real protection is that secrets are *absent at rest*; RAM hygiene only narrows the live-exposure window.

---

## 10. Explicitly deferred (extension points, not v1 scope)

Build the seams for these; do not build the features.
- **PQ-at-rest:** migrate DEK sealing to **X-Wing HPKE (X25519+ML-KEM-768)** — pull in when a maintained, audited Rust crate ships and draft-ietf-hpke-pq / X-Wing reach RFC. The agility header (§3.6) is the seam. Consider ML-KEM-1024 given the decades-long at-rest horizon.
- **Per-tenant crypto isolation:** when real multi-tenancy is needed, the **tenant/account is the crypto boundary** — each account a fully independent tree (own AMK, own keys); **no key ever wraps across the account boundary** (the single invariant that makes isolation auditable). Still *not* per-thread/label keys.
- **The locked-mint provisioning channel** (seal new keypair's priv to an ambient `provision_pub`, rewrap under AMK on unlock) — only if a future feature must create keys while locked. v1 doesn't.
- **IMAP** — only if Apple Mail / legacy-client interop is ever required. It's a nasty stateful protocol; add late, isolated.
- **SCRAM-SHA-256** SASL (v1 ships PLAIN-over-TLS).
- **Audit witness cosigning / external anchoring** (§6).
- **tantivy** search backend swap (v1 ships FTS5-in-memory).
- **PGP/Autocrypt** opt-in per-correspondent E2E — the *only* real end-to-end confidentiality, and the only thing that defends against a live/operator adversary. Cannot be globally required (you'd stop receiving Gmail). Offer per-contact.

---

## 11. Build phases (each phase is independently testable and motivating)

**Phase 0 — skeleton & crypto core.** Workspace, config, tracing, the `crypto` crate with agility header, committing-wrap, HPKE classical seal/open, Argon2id unlock, AMK hierarchy, `store` blob+SQLite scaffolding. *Acceptance:* unit tests for wrap/unwrap round-trips, committing-wrap rejects tampered prefix, crash-safe blob write.

**Phase 1 — inbound.** `smtp-in` (port 25, STARTTLS, SPF/DKIM/DMARC verify) → `delivery` (classify → seal to account.pub → blob + metadata). *Acceptance:* real mail from an external account lands, decrypts on unlock, DKIM result stored.

**Phase 2 — JMAP read + minimal frontend.** `jmap` read-only (Mailbox/Email/Thread get+query), SSE, SvelteKit shell that lists and reads mail. *Acceptance:* you can *see* your mail on mobile.

**Phase 3 — submission + outbound queue + DKIM sign.** `submission`, `queue` (MX, retry/backoff, 4xx/5xx, DSN), DKIM-sign outbound. *Acceptance:* you can send to Gmail and it lands in inbox (not spam) — full auth stack live.

**Phase 4 — JMAP write + search.** Email set (flags/move/delete), threads, structured filters over the category table, session in-RAM FTS5 index + locked-fragment merge (with bucketing). *Acceptance:* flag/move/delete round-trip; full-text search while unlocked; filters work while index is cold.

**Phase 5 — harden.** DANE/MTA-STS/TLS-RPT published, audit log live, JMAP hardening checklist complete, reminders/scheduler, best-effort zeroize + host hardening (no swap/hibernate, LUKS), re-key path tested. *Acceptance:* passes the §8.4 checklist; mail-tester / MTA-STS validators green; simulated crash mid-rotation leaves no unreadable message.

---

## 12. Frontend (brief — full design language on request)
SvelteKit + Phosphor icons, JMAP client, SSE for push. Mobile-first. Visual direction: **muted, low-contrast, soft palette; generous spacing; calm.** No localStorage/sessionStorage assumptions server-side; auth via short-lived session tokens over TLS. Keep the JMAP client thin — it mirrors the method-batching model of the server.

---

## 13. Definition of done for v1
A single systemd unit that: receives authenticated, DKIM/DMARC-checked mail on 25; stores it encrypted-at-rest sealed to the account key (readable only after Argon2id unlock); serves it over hardened JMAP to a mobile SvelteKit client; sends DKIM-signed outbound through a durable retrying queue with DSNs; supports threads, folders, labels, structured filters, unlocked full-text search, and reminders; keeps a hash-chained encrypted audit log; and is honest in every doc and comment that its at-rest encryption defends **offline seizure**, not a live or operator adversary.

For all versions, run in docker completely. Use Phosphor icons for icons. Make sure to do SOLID deltaed by KISS. Use a good tailwind based library for the design. Use proper loading states (that is shared), empty states, etc. Use dull colors for the branding. Look for very modern design that is mobile first.

# Part A — Outbound Queue & Scheduler (crate: `queue`)

**Status:** Design locked for v1. Extends §8.3 / §8.6 of the main spec.
**What this crate owns:** every message leaving the server, its retry lifecycle, bounce/DSN generation, and — because it's the only durable wakeup mechanism in the process — the reminder/scheduled-event engine too. One worker, one wakeup loop, two kinds of due work.

---

## A.1 Core principle

**The queue is a durable state machine backed by SQLite, driven by a single-tick worker.** No in-memory-only state that matters survives only in RAM: if the process dies mid-delivery, restart re-derives everything from the DB. The worker never holds a message "in flight" without that fact being committed to disk first.

Concurrency model: a small pool of async send-tasks (default 4) pulling claimed rows, but **all state transitions go through SQLite transactions** so two workers can never double-send the same row. SQLite in WAL mode; claiming a row is an atomic `UPDATE ... WHERE state='ready' AND ... RETURNING` (or `BEGIN IMMEDIATE` + select + update). Never rely on application-level locks for correctness.

---

## A.2 Schema

```sql
-- one row per outbound message (the envelope + a pointer to the built MIME blob)
CREATE TABLE outbound (
  id              INTEGER PRIMARY KEY,
  account_id      INTEGER NOT NULL,        -- which local account sent it
  message_blob    TEXT    NOT NULL,        -- content-addressed hash of the signed MIME
  envelope_from   TEXT    NOT NULL,        -- MAIL FROM (return-path); may be <> for DSNs
  created_at      INTEGER NOT NULL,        -- unix seconds
  expires_at      INTEGER NOT NULL,        -- give-up deadline (created_at + max_lifetime)
  dsn_envid       TEXT,                    -- RFC 3461 ENVID if the submitter set one
  dsn_ret         TEXT,                    -- FULL | HDRS  (how much to return in a bounce)
  is_dsn          INTEGER NOT NULL DEFAULT 0, -- 1 if THIS message is itself a bounce (loop guard)
  state           TEXT    NOT NULL DEFAULT 'ready'  -- see A.3
);

-- one row per recipient: recipients are delivered and retried INDEPENDENTLY
CREATE TABLE outbound_rcpt (
  id              INTEGER PRIMARY KEY,
  outbound_id     INTEGER NOT NULL REFERENCES outbound(id) ON DELETE CASCADE,
  rcpt_to         TEXT    NOT NULL,        -- one recipient address
  domain          TEXT    NOT NULL,        -- rcpt domain, for MX grouping/backoff
  dsn_notify      TEXT,                    -- RFC 3461 NOTIFY: SUCCESS,DELAY,FAILURE / NEVER
  state           TEXT    NOT NULL DEFAULT 'ready',  -- ready|claimed|deferred|delivered|failed|expired
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,        -- when this recipient becomes 'ready' again
  claimed_by      TEXT,                    -- worker/task id holding it (nullable)
  claimed_at      INTEGER,
  last_code       INTEGER,                 -- last SMTP reply code seen (e.g. 250, 421, 550)
  last_status     TEXT,                    -- RFC 3463 enhanced status (e.g. "5.1.1")
  last_detail     TEXT,                    -- trimmed remote text, for the DSN + audit
  delayed_dsn_sent INTEGER NOT NULL DEFAULT 0  -- so we send at most one "still trying" notice
);

CREATE INDEX ix_rcpt_due ON outbound_rcpt(state, next_attempt_at);
CREATE INDEX ix_rcpt_outbound ON outbound_rcpt(outbound_id);

-- unified scheduler (A.8): reminders/snoozes share the same wakeup loop
CREATE TABLE scheduled_events (
  id           INTEGER PRIMARY KEY,
  account_id   INTEGER NOT NULL,
  kind         TEXT    NOT NULL,   -- remind | snooze_resurface | followup_nudge
  fire_at      INTEGER NOT NULL,
  thread_id    TEXT,               -- for followup_nudge / snooze
  payload      TEXT,               -- opaque JSON (sealed if it contains anything sensitive)
  state        TEXT    NOT NULL DEFAULT 'pending'  -- pending | fired | cancelled
);
CREATE INDEX ix_sched_due ON scheduled_events(state, fire_at);
```

**Why per-recipient rows:** a message to three domains where one 250s, one 4xx-defers, and one 5xx-bounces must handle each independently — partial success is the normal case. The `outbound` parent row is "done" only when every child recipient is terminal (delivered/failed/expired).

---

## A.3 State machines

### Recipient state (the one that matters)

```
                 ┌─────────── claim (worker tick) ───────────┐
                 v                                            │
  ready ──────────────► claimed ──► [attempt delivery] ──► outcome:
   ▲                        │                                 ├─ 2xx  → delivered  (terminal)
   │                        │                                 ├─ 4xx  → deferred   → (backoff) → ready
   │  next_attempt_at ≤ now │                                 ├─ 5xx  → failed     (terminal, bounce)
   └────────────────────────┘                                 └─ expiry reached → expired (terminal, bounce)
```

- **ready** — due for an attempt (`next_attempt_at ≤ now`).
- **claimed** — a worker owns it right now. Has a lease (`claimed_at + lease_ttl`); a crashed worker's stale claim is reaped back to `ready` (see A.6).
- **deferred** — got a transient failure; waiting out backoff. Functionally `ready` with a future `next_attempt_at`; kept as a distinct label only for observability.
- **delivered / failed / expired** — terminal. `failed` and `expired` trigger a failure DSN (unless `NOTIFY=NEVER`).

### Parent message state
`ready` → (has claimable recipients) → stays active → when **all** recipients terminal → `complete`. A `complete` row is retained for a short window (audit + dedupe) then GC'd; the MIME blob is refcounted and removed when no row references it.

---

## A.4 SMTP reply classification (the crux — get this exactly right)

Classify on the **first digit** of the SMTP reply code, but with named overrides. Never treat an unknown code by guessing; default unknowns conservatively.

| Code class | Meaning | Action |
|---|---|---|
| **2xx** (250, 251) | accepted | `delivered`. If `NOTIFY` includes SUCCESS, emit a success DSN (rare; usually off). |
| **4xx** (421, 450, 451, 452, 4.7.x greylist) | transient | `deferred`; schedule retry per A.5. |
| **5xx** (550, 551, 552, 553, 554) | permanent | `failed`; generate failure DSN. Do **not** retry. |
| connection/TLS/DNS error (no code) | transient by default | treat as 4xx **unless** it's a hard DNS failure (NXDOMAIN on the domain → permanent `failed`, "no such domain"). |

**Named nuances to implement, not skip:**
- **421** ("service not available, closing channel") — transient, but means *stop hammering this host now*; apply a **per-destination** cooldown (A.7), not just per-recipient backoff.
- **450 vs 550 greylisting** — many greylisters use 4xx; that's why the *first* retry must not be too eager (A.5 starts at minutes, not seconds).
- **Enhanced status codes (RFC 3463)** — parse and store the `X.Y.Z` when present; it's better DSN material than the raw code and feeds the audit log. `5.1.1` = bad mailbox, `4.2.2` = mailbox full (transient), `5.7.1` = policy/blocked.
- **Post-DATA vs pre-DATA failures** — a 5xx after `.` (data phase) is still permanent for that recipient. A 5xx on `RCPT TO` fails only that recipient; keep going with the rest of the RCPTs on the same connection.
- **Never retry on a 5xx by "trying a different MX"** for the same permanent error — that's how you get on blocklists. Different MX is only for *connection-level* transient failures.

---

## A.5 Retry backoff schedule

Exponential with jitter, capped, bounded by a total lifetime. Concrete v1 schedule (per recipient):

```
attempt 1 failed (4xx)  → +5 min
attempt 2               → +15 min
attempt 3               → +30 min
attempt 4               → +1 hour
attempt 5               → +2 hours
attempt 6               → +4 hours
attempt 7+              → +8 hours (cap), repeating
max_lifetime            → 5 days (expires_at); then → expired + failure DSN
delayed-DSN threshold   → if still not delivered after 30 min AND NOTIFY includes DELAY,
                          send ONE "still trying" notice (set delayed_dsn_sent=1)
```

- **Jitter:** actual delay = base × (1 + rand(-0.15, +0.15)). Prevents thundering-herd retries against a recovering host.
- **`next_attempt_at` is authoritative**, not a sleep. The worker computes it, commits, and moves on; the wakeup loop (A.6) re-selects it when due. No in-memory timers for retries.
- These numbers are config keys with these defaults, not hardcoded. Postfix-style defaults (min 300s, max 4000s, lifetime 5d) are the reference point; the above is a slightly gentler curve tuned for greylisting.

---

## A.6 The worker loop

Single logical loop, N concurrent send-tasks. Pseudocode:

```
loop {
    now = unix_now()

    // 1. reap stale claims (crashed workers)
    UPDATE outbound_rcpt SET state='ready', claimed_by=NULL
      WHERE state='claimed' AND claimed_at < now - LEASE_TTL;

    // 2. fire due scheduled events (A.8) — cheap, do inline
    for ev in due_scheduled_events(now): fire(ev)  // push over SSE, mark fired

    // 3. claim a batch of due recipients, grouped by destination domain
    batch = claim_ready(now, limit=BATCH, group_by=domain)   // atomic UPDATE...RETURNING

    // 4. dispatch: one connection per (domain, MX) reused for all its recipients
    for (domain, rcpts) in batch.group_by_domain():
        spawn_send_task(domain, rcpts)   // bounded by the send-task semaphore

    // 5. sleep until the NEXT due row, or a short floor, whichever is sooner
    next = SELECT min(next_attempt_at) FROM outbound_rcpt WHERE state IN ('ready','deferred')
    sleep_until(min(next, now + IDLE_FLOOR))   // IDLE_FLOOR ~ 30s; also woken by submit-signal
}
```

**A submit path signals the loop** (tokio `Notify`) so a freshly-enqueued message is picked up immediately rather than waiting for `IDLE_FLOOR`.

**Inside `spawn_send_task(domain, rcpts)`:**
1. MX lookup via `hickory` (cache per domain, respect TTL). Sort by preference; keep the list for connection-level fallback.
2. Connect to the best MX. **Opportunistic STARTTLS; if a TLSA record exists for this MX, enforce DANE** (fail closed on DANE mismatch — that's the point of DANE). Use the PQ-hybrid TLS where the remote supports it, classical otherwise.
3. One `MAIL FROM`, then `RCPT TO` for each recipient in the group; record per-recipient RCPT responses. `DATA` once, stream the blob via `mail-send`.
4. Map each recipient's outcome through A.4, compute `next_attempt_at` for defers, and **commit all transitions for the group in one transaction.**
5. Connection-level transient failure (couldn't connect / TLS failed / 421) → try the next MX; if all MX exhausted → defer the whole group (per-recipient backoff), and set a per-destination cooldown (A.7).

---

## A.7 Per-destination throttling & cooldowns

Backoff is per-recipient, but *some* signals are per-host and must be respected globally or you'll get blocklisted:
- **421 / connection refused / "too many connections"** → set `cooldown_until` for that destination domain in an in-memory (rebuildable) map; the claimer skips recipients whose domain is cooling down.
- **Concurrency cap per destination** (default 2 simultaneous connections to one domain) — big providers rate-limit and will tempfail or block aggressive senders.
- These are reputation-protection, not correctness; losing them on restart is fine (they rebuild from fresh signals).

---

## A.8 DSN / bounce generation (RFC 3464 / 3461)

When a recipient goes `failed` or `expired` (and its `NOTIFY` doesn't say `NEVER`), or crosses the delay threshold (and `NOTIFY` includes `DELAY`), build a DSN with `mail-builder`:

- **multipart/report; report-type=delivery-status** with three parts: human-readable text, the `message/delivery-status` machine part (Reporting-MTA, Action=failed/delayed, Status=`X.Y.Z`, Diagnostic-Code with the trimmed remote text), and the returned content (`message/rfc822` if `RET=FULL`, `text/rfc822-headers` if `RET=HDRS`).
- **`MAIL FROM:<>`** (null return-path) on the DSN itself — mandatory, and the primary loop guard.
- **Loop guards (all required):** never DSN a message whose envelope-from is `<>`; set `is_dsn=1` and never DSN a DSN; add and honor an `Auto-Submitted: auto-replied` header; cap DSNs generated per original message. A bounce storm from a mislabeled row must be structurally impossible.
- Deliver the DSN back to the original submitter's mailbox by the **internal delivery path** (it's local) — do not round-trip it through SMTP.

**Success DSNs** (`NOTIFY=SUCCESS`) are supported but off by default; almost nobody wants them.

---

## A.9 The scheduler (reminders) — why it lives here

Reminders, snoozes, and follow-up nudges need exactly what the queue already has: a durable, crash-safe, "wake me at time T" mechanism. Reusing it means one loop, one source of truth.

- **remind / snooze_resurface** — at `fire_at`, push an event over the **same SSE channel** the JMAP layer already uses to notify the client; mark `fired`. Snooze = the message was hidden (a keyword/flag) until now; resurfacing clears it and nudges the client.
- **followup_nudge** ("nudge if no reply by T") — at `fire_at`, the worker checks the thread's reply state (does a later inbound message exist in `thread_id`?). If no reply → fire the nudge; if replied → silently `cancelled`. This is the one scheduled kind that reads mailbox state at fire time, so it must run in an unlocked-aware way: if the mailbox is locked it can still check thread *metadata* (that a message exists in the thread — no body needed, §4 of main spec), so it works while locked.
- Scheduled events are cheap and fired inline in the main loop (step 2 of A.6); they don't need the send-task pool.

---

## A.10 Acceptance criteria (Phase 3 + 4)

- Message to a 3-domain recipient set where one domain 250s, one 4xx-defers then later 250s, one 550s → sender gets exactly one failure DSN naming only the 550 recipient; the other two deliver; no double-sends.
- Kill the process mid-`DATA`; on restart the recipient is re-attempted (idempotent — remote may get a dup, which is acceptable and expected for SMTP; do not try to make delivery exactly-once, it's impossible).
- Greylisting simulation (450 on first RCPT, 250 after 10 min) delivers on the second attempt without a bounce.
- A DSN with a forged `<>` return-path cannot itself generate a DSN (loop guard holds).
- A snooze set for T+2min resurfaces at T+2min via SSE; a followup_nudge cancels itself if a reply arrives first.

---
---

# Part B — Frontend Design Language (`web/`, SvelteKit + Phosphor)

**Status:** Design language locked for v1. Governs every screen. The goal is a mail client that feels **calm, quiet, and unhurried** — the opposite of the anxious, badge-covered, high-contrast inbox. Muted, soft, mobile-first, generous with space.

---

## B.1 The single organizing feeling: *quiet*

Every decision serves one adjective: **quiet**. Low contrast, desaturated color, soft edges, restrained motion, one accent used sparingly. If a choice makes the screen louder, it's wrong. Density is not the enemy of quiet — *noise* is. We can show a lot of mail, calmly.

Anti-goals: no pure black on pure white, no saturated reds for counts, no dense toolbars, no more than one accent color competing for attention, no bouncing/springy animation, no unread counts screaming in the corner.

---

## B.2 Color — muted, soft, dual-theme

Design in **OKLCH** (perceptually even; easy to keep saturation genuinely low). Ship as CSS custom properties; default to the user's system theme.

**Light theme (soft off-white, never `#fff`):**
```
--bg           oklch(0.98 0.004 95)   /* warm paper, not white */
--surface      oklch(0.995 0.004 95)  /* cards sit slightly above bg */
--surface-sunk oklch(0.955 0.005 95)  /* wells, input backgrounds */
--border       oklch(0.90 0.005 95)   /* hairlines; barely there */
--text         oklch(0.32 0.01 260)   /* soft near-black, slight cool */
--text-muted   oklch(0.55 0.01 260)   /* secondary: timestamps, preview */
--text-faint   oklch(0.68 0.008 260)  /* tertiary: metadata, hints */
--accent       oklch(0.62 0.08 240)   /* dusty blue — the ONLY chroma that matters */
--accent-weak  oklch(0.94 0.03 240)   /* accent wash for selected rows */
```

**Dark theme (soft charcoal, never `#000`):**
```
--bg           oklch(0.22 0.008 260)
--surface      oklch(0.25 0.008 260)
--surface-sunk oklch(0.19 0.008 260)
--border       oklch(0.31 0.008 260)
--text         oklch(0.90 0.01 260)
--text-muted   oklch(0.68 0.01 260)
--text-faint   oklch(0.55 0.01 260)
--accent       oklch(0.72 0.07 240)   /* lift accent lightness in dark */
--accent-weak  oklch(0.30 0.03 240)
```

**Semantic colors are muted too** — a "failed send" is a dusty terracotta (`oklch(0.60 0.09 40)`), not fire-engine red; "delivered" a sage (`oklch(0.62 0.06 150)`), not neon green. **Chroma stays under ~0.10 everywhere.** That single constraint is what makes it "soft."

**Contrast floor:** body text vs its background must still clear WCAG AA (4.5:1). Quiet ≠ illegible — mute the *chroma* and the *chrome*, keep text–background lightness contrast honest. Muted is a saturation choice, not a contrast excuse.

---

## B.3 Typography

- **One typeface**: a humanist sans with a real range — Inter, or better for the "calm" register, something with slightly more warmth (e.g. "Public Sans", "IBM Plex Sans"). One family, many weights. No second display face.
- **Type scale** (mobile base 16px, `rem`): 13 / 14 / 16 / 18 / 22 / 28. Message body 16, list subject 15–16, preview & metadata 13–14, screen titles 22–28.
- **Weight does the hierarchy work, not size or color**: subjects at 550–600, everything else 400. Unread = subject at 600 + a small accent dot; **not** bold-everything, **not** a colored row.
- **Line-height generous**: 1.5 for body, 1.35 for dense list rows. Message reading width capped ~66ch on larger screens.
- **Numerals**: tabular for timestamps/counts so lists don't shimmer.

---

## B.4 Space — the primary tool

Quiet comes mostly from **space**, not color. Use a 4px base scale: 4 / 8 / 12 / 16 / 24 / 32 / 48.

- List rows: 12–16 vertical padding, 16 horizontal. Rows breathe; they are not spreadsheet lines.
- Generous **section rhythm**: 24–32 between logical groups.
- **Hairline dividers, used sparingly** — prefer whitespace to separate; a `--border` line only where grouping genuinely needs it. Never a divider between every row *and* padding; pick one.
- Touch targets ≥ 44px. Thumb-reachable primary actions.

---

## B.5 Shape, elevation, texture

- **Corner radius**: 10–12px on cards/inputs/buttons, 8px on small chips. Consistent; soft but not pill-round except for status chips.
- **Elevation is barely-there**: separate surfaces with a 1px `--border` + a *whisper* of shadow (`0 1px 2px oklch(0 0 0 / 0.04)`), not floating drop-shadows. In dark theme prefer a slightly lighter surface over shadow.
- **No gradients, no glassmorphism, no borders competing with shadows.** One separation method per element.

---

## B.6 Iconography — Phosphor

- **Phosphor, "regular" weight** as the default; "fill" only for the single active/selected state (e.g. the current folder, a starred message). Never mix more than two weights on one screen.
- Icon size 20–24 in nav/actions, 16 inline with text. Icons inherit `--text-muted` at rest, `--accent` when active. **Labels accompany icons** in primary nav — icon-only is for dense secondary toolbars, and even then with `aria-label`.
- Consistent metaphors: paper-plane (send), archive-box (archive), trash (delete), bell (reminder), tag (label), lock/lock-open (mailbox lock state — this one is load-bearing, see B.9).

---

## B.7 Layout — mobile-first, three canonical screens

Design the phone first; the desktop is the phone's columns placed side by side.

1. **List** (folder/thread list): top bar (folder name + search affordance), scrollable rows, floating compose button (bottom-right, accent, the one prominent element on the screen). Row = [unread dot] sender · time (right, faint) / subject / one-line preview (muted). Swipe actions: archive (leading), more (trailing) — soft-colored, revealed under a rounded row.
2. **Thread** (reading): collapsed message cards in a thread, newest expanded. Sender identity + verified-auth indicator (a quiet check if DKIM/DMARC passed — muted, not a green shield). Reply bar pinned bottom.
3. **Compose**: full-screen sheet, minimal chrome — To / Subject / body, formatting behind a disclosure, send as the one accent action. Nothing else competes.

Desktop/tablet: list + thread as two columns (and a slim nav rail with the folders); the compose sheet becomes a centered modal card. Same components, wider grid.

---

## B.8 Motion — restrained

- **Durations 120–220ms**, `ease-out` (or a gentle custom cubic). No spring, no bounce, no overshoot. Calm means *settled*.
- Transitions earn their place: list→thread slides gently; a sent message fades its row state; the lock overlay cross-fades. Everything else is instant.
- Respect `prefers-reduced-motion` — drop to opacity-only.
- **Optimistic UI** for JMAP writes (flag, archive, move, delete): apply instantly, reconcile on the `Email/set` response, and quietly roll back on failure with a soft inline notice (never a modal error for a failed archive).

---

## B.9 The states that make a mail client feel finished

Design these *first*, not last — they're where quiet either holds or breaks:

- **Locked** (mailbox sealed, §3 of main spec): a calm full-screen unlock, not an error. Soft lock icon, a single password field, the app name. Reads as "resting," not "blocked." After unlock, content fades in as the in-RAM index warms.
- **Loading**: skeleton rows in `--surface-sunk`, no spinners in the list. A spinner only for a genuinely blocking action (send in flight), and even then subtle.
- **Empty**: a quiet line of `--text-faint` and a small Phosphor glyph — "Nothing here yet." No illustrations shouting for attention.
- **Search while locked**: structured filters (from/domain/thread/label) work — surface them; full-text is disabled with a one-line muted explanation ("Full-text search is available while unlocked"), never a dead search box with no reason.
- **Offline / SSE reconnecting**: a thin, muted top strip ("Reconnecting…"), auto-dismissing. Never a blocking overlay.
- **Send failed / DSN arrived**: surfaced as a normal quiet message (the bounce lands in the inbox), plus a soft inline badge on the original in Sent — terracotta, not red.

---

## B.10 Implementation notes

- **No `localStorage`/`sessionStorage` for anything security-relevant**; auth is a short-lived session token held in memory, refreshed over TLS. (Also: artifacts/SSR constraints — keep state in Svelte stores, not web storage.)
- **Tokens as CSS custom properties** on `:root` / `[data-theme]`; components read only variables, never hardcoded hex. This is what lets the whole "quiet" system be tuned in one file.
- **Thin JMAP client**: mirror the server's method-batching — one request carrying `Email/query` + `Email/get` back-to-back; SSE (`EventSource`) for push. Don't build a heavy state framework; Svelte stores + a small typed JMAP wrapper.
- **Accessibility is part of "calm"**: AA contrast held (B.2), focus-visible rings in `--accent`, full keyboard paths, `aria-label` on icon-only controls, reduced-motion honored.
- **Density is a user setting** (comfortable / compact) that only changes the space scale (B.4), never the color or type system.

---

## B.11 Acceptance criteria (Phase 2 + 4)

- The whole UI renders from CSS variables; flipping `data-theme` light↔dark changes nothing else and both pass AA on body text.
- No pure `#000`/`#fff`, no color with chroma > 0.10, exactly one accent hue in use per screen.
- List, thread, compose, and all six B.9 states exist and each reads as "quiet" (no spinner in list, no red badges, no bold-everything).
- Flag/archive/delete feel instant (optimistic) and reconcile against `Email/set`.
- Reduced-motion and keyboard-only navigation both fully usable.