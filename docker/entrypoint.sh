#!/bin/sh
# Renders litterae.toml.template into $LITTERAE_CONFIG from environment
# variables, unless a real config was already bind-mounted there -- so the
# default deployment needs zero hand-edited TOML (just the root .env), but
# power users can still bind-mount a fully custom litterae.toml over this
# path and skip templating entirely.
set -eu

CONFIG_PATH="${LITTERAE_CONFIG:-/etc/litterae/litterae.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
    mkdir -p "$(dirname "$CONFIG_PATH")"
    envsubst '${LITTERAE_DOMAIN} ${LITTERAE_ADMIN_USERNAME} ${LITTERAE_ADMIN_PASSWORD}' \
        < /etc/litterae/litterae.toml.template > "$CONFIG_PATH"
fi

exec "$@"
