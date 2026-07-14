# litterae

A self-hosted, single-binary mail server: SMTP in/out, JMAP (web mail, no
IMAP), storage, and encryption-at-rest. Ships as a Docker Compose stack
(litterae + rspamd + ClamAV + Caddy + CrowdSec) fronted by a web UI for
both the mailbox (`mail.*`) and admin (`admin.*`).

This README covers running and deploying the stack. For the underlying
design (crypto model, crate boundaries, protocol subset) see `Claude.md`.

## Quick start (local testing, no DNS needed)

```sh
git clone <this repo> && cd litterae
cp .env.example .env
docker compose up -d --build
```

Visit `https://mail.localtest.me` and `https://admin.localtest.me` --
`localtest.me` is a public DNS wildcard that always resolves to
`127.0.0.1`, so this works with zero setup. Caddy serves a self-signed
cert for it (`docker-compose.override.yml` swaps in `Caddyfile.local` for
this; your browser will warn about the cert, that's expected).

Admin login is whatever you set `LITTERAE_ADMIN_USERNAME` /
`LITTERAE_ADMIN_PASSWORD` to in `.env`. On a new installation, you must
replace the password placeholder before startup; insecure bootstrap values
are rejected. The first session is restricted to changing that password
before any other admin API can be used. On an existing installation these
environment variables are ignored once an admin exists, so leaving the old
placeholder in place does not prevent a restart or reset the current password.
From there, add a domain and create a mailbox account in the admin panel, then
log into `mail.localtest.me` with that account.

Outbound mail to the real internet won't deliver from this local setup
(see "Real deployment" below for why) -- it's for exercising the UI and
mail-between-local-accounts only.

## Real deployment

### Prerequisites

- A server with a public IP, reachable on **ports 25, 587, 465, 80, 443**.
- **Outbound port 25 must actually work.** Many residential ISPs and some
  cloud/VPS providers block outbound 25 by default to stop spam relaying
  -- check with your provider before troubleshooting anything else. A
  quick test from the host:
  ```sh
  timeout 5 bash -c 'exec 3<>/dev/tcp/gmail-smtp-in.l.google.com/25 && echo OK'
  ```
  If that doesn't print `OK`, mail will sit in the queue as `deferred`
  forever regardless of anything else being configured correctly (see
  Troubleshooting).
- A domain you control DNS for.
- Docker + Docker Compose.

### 1. DNS records

litterae itself does **not** verify domain ownership -- the admin panel
will let you add any domain string with no check. The verification that
actually matters happens at the DNS layer: other mail servers trust
records only you (as the domain's DNS owner) can publish. Set these
**before** or right after deploying (some take time to propagate):

| Record | Where | Value | Why |
|---|---|---|---|
| A | `mail.yourdomain.com` | your server's public IP | so the hostname resolves |
| MX | `yourdomain.com` | `10 mail.yourdomain.com` | tells senders where to deliver your mail |
| PTR (reverse DNS) | set by your **hosting provider**, not your DNS zone | → `mail.yourdomain.com` | most receiving servers reject/spam-flag mail from IPs with no matching PTR; many providers require a support ticket for this |
| SPF | TXT on `yourdomain.com` | `v=spf1 mx ~all` | declares this server may send as your domain |
| DKIM | TXT on `{selector}._domainkey.yourdomain.com` | printed by `dkim-init` (below) | signs outgoing mail; without it, most providers (Gmail, etc.) will junk or reject you |
| DMARC | TXT on `_dmarc.yourdomain.com` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@yourdomain.com` | policy for SPF/DKIM failures + reporting; increasingly required by large providers |

### 2. Configure

```sh
cp .env.example .env
```

Edit `.env`:

```
MAIL_HOSTNAME=mail.yourdomain.com
ADMIN_HOSTNAME=admin.yourdomain.com
LITTERAE_DOMAIN=yourdomain.com
LITTERAE_ADMIN_USERNAME=admin
LITTERAE_ADMIN_PASSWORD=<pick something real>
```

**Delete `docker-compose.override.yml`** (or always run with
`docker compose -f docker-compose.yml ...`). It exists only to force
self-signed local certs for `*.localtest.me` testing; without it, Caddy
automatically requests real Let's Encrypt certificates for your real
hostnames the first time it starts.

### 3. Start it

```sh
docker compose up -d --build
```

Watch the logs the first time (`docker compose logs -f caddy litterae`)
-- Caddy will attempt an ACME HTTP-01 challenge against
`MAIL_HOSTNAME`/`ADMIN_HOSTNAME`, which requires DNS to already be
pointed at the server and port 80 reachable from the internet.

### 4. Log in and set up

1. Visit `https://admin.yourdomain.com`, log in with the admin
   credentials from `.env`, and change the password when prompted.
2. Add your domain in the **Domains** tab (this is a local record only --
   see the DNS section above for what actually needs to exist publicly).
3. Get your DKIM DNS record and publish it -- there's no admin UI for
   this yet, so run it against the running container:
   ```sh
   docker compose exec litterae litterae dkim-init yourdomain.com
   ```
   This prints the exact TXT record to add (selector + public key,
   generated and persisted on first run; safe to re-run, it's a no-op
   after the first time). Add it to your DNS, then move on -- you don't
   need to wait for it to propagate before creating accounts, only
   before mail delivery relying on it will pass.
4. Create a mailbox account in the **Accounts** tab.
5. Log into `https://mail.yourdomain.com` with that account and send a
   test message.
6. If it doesn't show as delivered, check the **Queue** tab -- recent
   failures show the exact reason (DNS failure, connection refused,
   remote server rejection, etc.). See Troubleshooting below for the two
   most common causes.

### A note on submission (587/465)

The default Docker setup does **not** enable authenticated SMTP
submission (the protocol regular mail clients like Thunderbird/Apple
Mail use to send through a server, as opposed to litterae's own JMAP web
UI). It's disabled by default: submission requires its own TLS
certificate, and litterae doesn't run its own ACME client. Litterae
itself keeps running fine without it (SMTP-in on 25 and JMAP both work)
-- you'll just see a `submission disabled: no TLS cert configured` log
line, and ports 587/465 won't accept connections.

If you need a real external mail client (Thunderbird, Apple Mail, etc.)
to send through litterae, the compose stack already includes a
`cert-sync` sidecar that copies Caddy's cert for `MAIL_HOSTNAME` into a
shared volume litterae can actually read (Caddy's own cert storage is
`0700`-owned by root; litterae deliberately runs as its own non-root
user and can't read it directly, so this goes through a synced,
world-readable copy rather than a direct mount -- see `cert-sync` in
`docker-compose.yml` if you want the details). To turn submission on:

1. Make sure Caddy has already actually issued a cert for
   `MAIL_HOSTNAME` (i.e. you've loaded the site at least once) --
   `cert-sync` can only copy a cert that exists.
2. Copy `docker/litterae.toml.template`'s contents to a local
   `litterae.toml`, fill in the real `${...}` values, and add under
   `[submission]`:
   ```toml
   tls_cert_path = "/submission-certs/submission.crt"
   tls_key_path = "/submission-certs/submission.key"
   ```
3. Uncomment the `./litterae.toml:/etc/litterae/litterae.toml:ro`
   bind-mount in `docker-compose.yml` (the escape hatch that skips the
   `.env`-driven template -- see `docker/entrypoint.sh`) and
   `docker compose up -d litterae`.

**Caveat:** `cert-sync` re-copies hourly so a Let's Encrypt renewal
doesn't go stale in the shared volume, but litterae itself only reads
cert files once at startup -- restart the `litterae` container
periodically (e.g. a monthly cron `docker compose restart litterae`, or
just whenever you redeploy) so it actually picks up a renewed cert
before the old one expires. If litterae fails to start right after
enabling this, check that `docker compose exec litterae ls
/submission-certs` actually shows `submission.crt`/`submission.key` --
if `cert-sync` hasn't synced yet (or Caddy never got a cert for
`MAIL_HOSTNAME` in the first place), litterae's TLS load fails at
startup like any other bad TLS config. Not needed at all if you only use
the built-in JMAP web mail.

## Deploying with Coolify

The stack is a standard `docker-compose.yml`, which Coolify's "Docker
Compose" resource type runs largely as-is. Checklist version first, the
"why" for each item follows below:

1. New resource → **Docker Compose** (not Dockerfile/empty
   compose/public repository -- those are for single-service deploys;
   this stack has six services in one `docker-compose.yml`) → point it
   at this repo.
2. **Stop Coolify's own Traefik** before deploying, if this is the only
   thing running on the server: Servers → your server → **Proxy** tab →
   Stop Proxy, and uncheck the proxy option in Configuration to stop it
   respawning. Skip this only if you're deliberately running litterae
   alongside other Traefik-fronted apps on the same host (see the Ports
   note below for that case instead).
3. Set env vars (`MAIL_HOSTNAME`, `ADMIN_HOSTNAME`, `LITTERAE_DOMAIN`,
   `LITTERAE_ADMIN_USERNAME`, `LITTERAE_ADMIN_PASSWORD`) through
   Coolify's environment variable UI -- don't commit a real `.env`.
4. Confirm ports 25/587/465/80/443 are set as **Ports Mappings** (direct
   host publishing), not **Ports Exposes** (Traefik/HTTP-only -- SMTP and
   submission aren't HTTP, and 80/443 need to stay direct too since Caddy
   runs its own ACME).
5. Deploy, then work through "Real deployment" above (DNS records,
   admin login, DKIM, first mailbox account) the same as any other host.

The things most likely to trip you up, in more detail:

- **`docker-compose.override.yml` is ignored.** Coolify does not merge
  override files for application deployments (this is a known,
  currently-unimplemented feature request, not a config mistake on your
  end) -- so unlike a manual `docker compose up`, you don't need to
  remember to delete it; just don't reference it in Coolify's compose
  file list and it's already effectively gone.
- **Port conflicts with Coolify's own Traefik.** Coolify has two
  distinct ways a service's ports reach the internet: "Ports Exposes"
  (Coolify's built-in Traefik terminates TLS and routes by domain --
  what most Coolify apps use) and "Ports Mappings" (direct
  `host:container` publishing, same as plain Docker Compose, which
  *bypasses* Traefik entirely). This stack's `caddy` service publishes
  80/443 the second way (`ports: ["80:80", "443:443"]`) so it can run
  its own automatic Let's Encrypt -- that only works if nothing else on
  the same host, including Coolify's own Traefik, is also bound to
  80/443. In practice: if this is the only thing on the box, it works
  unmodified. If Coolify's Traefik is already serving other apps on
  80/443 on the same host, either give litterae its own dedicated
  host/IP, or strip Caddy's automatic-HTTPS/port-mapping entirely and
  instead expose it to Coolify via "Ports Exposes" so Traefik terminates
  TLS and forwards to Caddy over HTTP -- don't run both Caddy's ACME and
  Coolify's Traefik ACME for the same hostname at once.
- **Env vars**: set `MAIL_HOSTNAME`, `ADMIN_HOSTNAME`, `LITTERAE_DOMAIN`,
  `LITTERAE_ADMIN_USERNAME`, `LITTERAE_ADMIN_PASSWORD` through Coolify's
  environment variable UI rather than committing a real `.env` -- Coolify
  injects them the same way `env_file: .env` would.
- Ports 25/587/465 are raw TCP, not HTTP -- these need to be "Ports
  Mappings" (direct host publishing), not "Ports Exposes" (that path is
  Traefik/HTTP-only). Confirm they're actually reachable from the
  internet after deploying; Traefik has no role in fronting them either
  way.

Sources on Coolify's compose-override and port-routing behavior:
[Coolify Docker Compose docs](https://coolify.io/docs/knowledge-base/docker/compose),
[docker-compose.override.yaml ignored (issue #3841)](https://github.com/coollabsio/coolify/issues/3841),
[Allow using Docker Compose overrides with git (discussion #4339)](https://github.com/coollabsio/coolify/discussions/4339).

## Troubleshooting

**A sent message sits as "deferred" in the Queue tab.** Deferred means a
delivery attempt failed and it's retrying with backoff, not that
something is broken in litterae per se. The two most common causes,
both visible in the failure's `lastStatus`/`lastDetail` in the admin
Queue tab:

- `could not connect to any MX host` -- outbound port 25 is blocked
  somewhere between your server and the internet (see Prerequisites --
  test it directly with the `/dev/tcp` one-liner above). This is an
  infrastructure/provider issue, not a litterae bug.
- `DNS resolution failed: ... no records found ... query_type: MX` --
  the recipient's domain has no MX record, which usually means you
  mistyped the recipient address, or (if you're testing) you sent to a
  fake/reserved test domain like `example.test` rather than a real one.

**Forgot a mailbox account's password.** There's no recovery -- the
password derives the encryption key for that account's mail, so it
can't be reset the way a login-only password could. Delete and recreate
the account via the admin panel; old mail under the lost password stays
encrypted and unreachable.

**Admin login rejected after you know you set a password.** The admin
bootstrap (`LITTERAE_ADMIN_USERNAME`/`PASSWORD` in `.env`) only ever
fires once, the first time no admin account exists yet -- editing those
values later does nothing. Existing installations may leave the original
placeholder in `.env`; it is ignored after the admin exists. If you've since
changed the password through the admin UI's forced-reset flow, use that
password, not what's in `.env`.

## How it works

One Rust binary (`litterae`), several async listeners in one process,
plus a background outbound worker task -- no message queue, no separate
services beyond the optional scanners/CrowdSec. Each concern is its own
crate under `crates/`:

| Crate | Job |
|---|---|
| `smtp-in` | Inbound MTA: EHLO → opportunistic STARTTLS → SPF/DKIM/DMARC verification → hands accepted mail to `delivery`. Never requires TLS inbound (would break interop with the wide world of MTAs). |
| `submission` | Port 587/465 for real mail clients (Thunderbird, etc.): SASL PLAIN auth, TLS **mandatory** (no plaintext mode at all), hands outgoing mail to `queue`. |
| `scan` | Optional inbound content scanning: rspamd (spam score) + ClamAV (malware). Independently skipped if unconfigured; fails *open* on a timeout/connect error, never blocks mail on a scanner outage. |
| `delivery` | Seals an accepted message to the recipient account's public key and writes it (blob + SQLite metadata). Needs no password/private key -- works identically whether the mailbox is locked or unlocked. |
| `store` | Content-addressed blob storage (crash-safe write-then-rename) + SQLite metadata, WAL mode. |
| `queue` | Durable outbound queue: DKIM signing, MX lookup + delivery, retry/backoff, bounce (DSN) generation. One worker loop drains due recipients. |
| `dns` | MX record lookups for the outbound worker. |
| `jmap` | The mailbox web API (RFC 8620/8621 subset) and SSE push: password-unlock, session-scoped decryption, Mailbox/Email/Thread/Identity method calls. |
| `admin` | Operator API: domains, mailbox account CRUD, outbound queue visibility. Its own crate, own auth model, own session type -- structurally cannot reach mailbox content. |
| `auth` | The mailbox account model: provisioning, password unlock, the AMK/key-wrap hierarchy (see Security model below). |
| `audit` | Hash-chained, tamper-evident, partially-encrypted operator audit log. |
| `crypto` | Every cryptographic primitive used anywhere else in the workspace lives here and nowhere else. |
| `common` | Shared config, error types, TLS loading, the crypto-agility header, cross-crate change notifications for JMAP push. |

**Inbound mail**: `smtp-in` verifies the envelope, hands the raw
message to `scan` (spam/AV) and then `delivery`, which seals it to the
recipient's public key and writes it -- this whole path runs with no
password in memory, even for a mailbox nobody has unlocked in weeks.
`delivery` then notifies `common`'s in-process broadcast channel, which
wakes up any open JMAP `/jmap/sse` connection for that account so the
web UI updates without polling.

**Outbound mail**: either through litterae's own JMAP compose (a draft
is sealed to the sender's *own* public key, same as inbound) and
submitted via `EmailSubmission/set`, or through `submission` from a real
mail client. Either way it lands in `queue`, gets DKIM-signed, and the
worker loop resolves MX records (`dns`) and delivers with its own
retry/backoff schedule, generating a bounce (DSN) back into the sender's
own mailbox on permanent failure.

**Reading mail**: the browser posts a password to `/auth/unlock`;
`auth` turns it back into the account's private key, which lives in RAM
for that session only (`jmap`'s session registry) and is never written
to disk. Every JMAP method call decrypts on demand for that request.

**Admin vs. mailbox**: deliberately two separate crates, two separate
credential stores, two separate session types. An admin login can create
mailbox accounts and see queue/log metadata, but there is no code path
from an admin session to mailbox message content -- not a permission
check that could be misconfigured, a structural separation.

**Frontend**: a SvelteKit SPA (static build), served by Caddy, which
also reverse-proxies `/jmap/*`, `/auth/*`, and `/admin/*` to the same
origin the frontend is served from -- so the browser never needs a
cross-origin API URL configured.

## Security model

The one principle everything else derives from: **a locked server (no
password held anywhere in memory) can only seal data to public keys, never
read it.** Accepting mail, writing blobs, appending audit entries -- all
of it happens as public-key encryption. Every *read* requires the
mailbox's password.

**Per-account encryption**: a mailbox's password runs through Argon2id
(floor: 64 MiB memory, 3 passes, 4-way parallelism -- tuned upward toward
~0.5-1s wall clock on the deploy target) to derive a key that
committing-AEAD-wraps a random 256-bit Account Master Key (AMK). The AMK
in turn wraps the account's HPKE keypair. The public half
(`account_pub`) is stored in the clear -- that's what lets a locked
server seal inbound mail without ever touching the private key. Each
message gets its own random 256-bit DEK (XChaCha20-Poly1305 seals the
message body), and that DEK is HPKE-sealed to `account_pub`. Net effect:
someone with full read access to the disk (a backup, a compromised host)
gets ciphertext and cleartext account public keys for mailbox storage -- no
stored mailbox content and no private keys -- until a specific mailbox's
password is supplied. The active outbound retry spool is an explicit,
short-lived exception: delivery must continue while the mailbox is locked,
so its DKIM-signed wire form is plaintext until every recipient is terminal,
at which point Litterae removes it. Protect `/data` with encrypted storage
such as LUKS if active queued mail is within your offline-seizure threat model.
Every sealed/wrapped blob on disk starts with a small crypto-agility
header (`magic | version | alg_id | key_id | nonce`) so a future
post-quantum migration touches one crate (`crypto`), not the on-disk
format everywhere it's used.

**What's deliberately unencrypted**: envelope routing data
(`mail_from`/`rcpt_to`/`remote_ip`), SPF/DKIM/DMARC verdicts,
mailbox/keyword assignment, and `Message-ID`/`In-Reply-To`/`References`
headers are stored in cleartext -- this is what lets mail get routed,
listed, and threaded without a live unlocked session. `Subject` is not one
of them: only a per-account hash of the normalized subject, salted with that
account's public key, is stored for thread matching. This prevents
cross-account correlation but is not intended to resist a targeted dictionary
attack; the subject text itself is never stored there.

**What's not built yet, said plainly**: account key rotation and a
password-recovery path are both designed in `Claude.md` but not
implemented. A forgotten mailbox password is unrecoverable today, by
construction -- there is no backdoor, and that's the intended tradeoff
of this model, not an oversight (see Troubleshooting above).

**Audit log**: hash-chained (HMAC) with a periodically Ed25519-signed
head for tamper-evidence, and per-entry detail HPKE-sealed so it's only
readable after an admin logs in. The chain/signing keys themselves stay
in the clear on purpose -- audit entries get written from code paths
that run with no admin session at all (inbound SMTP, the outbound
worker), so they can't require an unlock to append. That gives
tamper-evidence against accidental corruption, not against an attacker
who already has full read/write access to the database -- a stronger
guarantee (external anchoring) is a known, explicit non-goal for v1.

**Auth surfaces**: mailbox accounts and the admin identity are two
entirely separate credential stores (see "Admin vs. mailbox" above), but
share the same Argon2id primitive and a per-identity exponential login
throttle -- keyed by identity, not source IP, since a single-operator
server's real threat is many guesses against one account, not a
distributed botnet. CrowdSec (optional, see below) adds network-level
banning on top of this, not instead of it.

**Transport**: submission (587/465) requires TLS unconditionally --
there is no plaintext fallback, ever. Inbound SMTP (25) offers
opportunistic STARTTLS but never requires it, matching how the rest of
the internet's mail servers behave. JMAP/admin/the frontend get real
Let's Encrypt HTTPS from Caddy.

**Content defense**: rspamd (spam scoring) and ClamAV (malware
scanning) run on every inbound message when configured, fully optional,
and independently fail *open* -- an unreachable scanner degrades to
"this message wasn't scored," logged loudly, never "inbound mail
stops." CrowdSec tails litterae's structured logs for repeated
auth-failure patterns and can ban the source IP at the firewall level;
it's an additive layer on top of the in-process login throttle, and the
stack works without it.
