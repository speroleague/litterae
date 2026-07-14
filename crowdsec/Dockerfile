# syntax=docker/dockerfile:1
#
# Bakes the acquisition config and litterae-specific parser/scenario into
# the image at build time rather than bind-mounting them at runtime --
# some PaaS docker-compose deployments (Coolify among them) don't
# reliably materialize single-file bind mounts from a cloned repo,
# silently creating an empty directory at the mount source instead and
# failing container startup (see web/Dockerfile for the same fix applied
# to Caddy's config).

FROM crowdsecurity/crowdsec:v1.7.8

COPY acquis.yaml /etc/crowdsec/acquis.yaml
COPY parsers/s01-parse/litterae.yaml /etc/crowdsec/parsers/s01-parse/litterae.yaml
COPY scenarios/litterae-bruteforce.yaml /etc/crowdsec/scenarios/litterae-bruteforce.yaml
