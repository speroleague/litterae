# syntax=docker/dockerfile:1
#
# Build context is the repo root (see docker-compose.yml's
# `caddy.build.context`), not this directory -- needed so this stage can
# also COPY the root Caddyfile into the image below. Every path here is
# relative to that root, not to web/.

########################################
# Build stage: static SvelteKit SPA
########################################
FROM node:24-bookworm-slim AS builder

WORKDIR /build
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

########################################
# Runtime: Caddy serves the static build directly. No separate web server
# (nginx etc.) -- Caddy already terminates TLS and reverse-proxies the API
# in this same container (see ../Caddyfile), so it serves these static
# files too. The Caddyfile is baked in at build time rather than bind-
# mounted at runtime -- Coolify (and some other PaaS docker-compose
# deployments) doesn't reliably materialize single-file bind mounts from a
# cloned repo, silently creating an empty directory at the mount source
# instead and failing container startup.
########################################
FROM caddy:2.11.4

COPY --from=builder /build/build /srv/web
COPY Caddyfile /etc/caddy/Caddyfile
