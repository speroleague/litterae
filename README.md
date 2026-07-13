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
`LITTERAE_ADMIN_PASSWORD` to in `.env` (defaults: `admin` /
`change-me-please`) -- you'll be forced to change the password on first
login. From there, add a domain and create a mailbox account in the admin
panel, then log into `mail.localtest.me` with that account.

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
UI). It's disabled on purpose: submission requires its own TLS
certificate, and the stack's Let's Encrypt certs are held internally by
Caddy, not exposed as files litterae can read. Litterae itself keeps
running fine without it (SMTP-in on 25 and JMAP both work) -- you'll just
see a `submission disabled: no TLS cert configured` log line, and ports
587/465 won't accept connections.

If you need a real external mail client to send through litterae, you'll
need to get a cert litterae can read directly (e.g. a separate certbot/
acme.sh container writing into a shared volume, or your own cert) and
bind-mount it, then set `submission.tls_cert_path`/`tls_key_path` via a
custom `litterae.toml` (bind-mount a full config over
`/etc/litterae/litterae.toml` to skip the `.env`-driven template --
see `docker/entrypoint.sh`). Not needed if you only use the built-in
JMAP web mail.

## Deploying with Coolify

The stack is a standard `docker-compose.yml`, which Coolify's "Docker
Compose" resource type runs largely as-is, with a few things worth
knowing going in:

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
values later does nothing. If you've since changed the password through
the admin UI's forced-reset flow, use that password, not what's in
`.env`.
