# syntax=docker/dockerfile:1

########################################
# Build stage: static SvelteKit SPA
########################################
FROM node:24-bookworm-slim AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

########################################
# Runtime: Caddy serves the static build directly. No separate web server
# (nginx etc.) -- Caddy already terminates TLS and reverse-proxies the API
# in this same container (see ../Caddyfile), so it serves these static
# files too.
########################################
FROM caddy:2.11.4

COPY --from=builder /build/build /srv/web
