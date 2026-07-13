# CrowdSec configuration for litterae

Network-level ban layer on top of litterae's own in-process login
throttle (`common::throttle::LoginThrottle`). Two pieces -- only one of
which runs in Docker:

- **`crowdsec` container** (the engine, in `docker-compose.yml`): tails
  litterae's log file (`acquis.yaml`), parses it
  (`parsers/s01-parse/litterae.yaml`), and runs the bruteforce scenario
  (`scenarios/litterae-bruteforce.yaml`) to decide when a source IP
  should be banned.
- **`crowdsec-firewall-bouncer`** (the enforcement -- **installed on the
  host, not containerized**): watches CrowdSec's local API for ban
  decisions and drops the traffic at the real host firewall
  (iptables/nftables/ipset). CrowdSec does not ship an official Docker
  image for this component -- it's distributed as a native package
  (apt/yum/binary) specifically because it needs to manipulate the
  *host's* netfilter rules, which a container can't safely proxy even
  with `NET_ADMIN`. Install it directly on the Docker host following
  CrowdSec's own instructions: https://docs.crowdsec.net/docs/bouncers/firewall/
  -- then point it at the `crowdsec` container's exposed API
  (`docker-compose.yml` publishes CrowdSec's local API port for exactly
  this).

This requires litterae to be started with `LITTERAE_LOG_DIR` set (see
`crates/common/src/tracing_init.rs`) so there's a file on disk for
`crowdsec` to tail -- stdout-only logging has nothing for it to read. The
Docker Compose stack sets this by default.

## Verifying it actually works

These YAML files are config, not code -- there's nothing to unit-test
them against without a running CrowdSec instance. Once the compose stack
is up:

```sh
# Confirm the parser and scenario loaded without errors:
docker compose exec crowdsec cscli parsers list
docker compose exec crowdsec cscli scenarios list

# Trigger a few failed logins against admin or JMAP from one source, then:
docker compose exec crowdsec cscli decisions list

# Once the host-installed firewall bouncer is registered:
docker compose exec crowdsec cscli bouncers list
```

litterae's own audit log and `tracing::warn!` lines (`event: "auth_failure"`)
are the source of truth for what CrowdSec sees -- if a ban isn't
triggering, check `docker compose logs crowdsec` for parser errors first.

## If you'd rather not install anything on the host

litterae's own `LoginThrottle` still rate-limits every auth endpoint
in-process with no CrowdSec involved at all -- the engine container above
is additional defense-in-depth, not a required dependency. Skip it
entirely and the stack works the same, just without network-level
banning.
