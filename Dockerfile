# syntax=docker/dockerfile:1

########################################
# Build stage
########################################
FROM rust:1.97.0-bookworm AS builder

# rusqlite's `bundled` feature compiles SQLite from source, and aws-lc-rs
# (rustls' crypto backend) compiles AWS-LC's C/C++ and generates bindings
# via bindgen -- both need a real toolchain beyond what `cargo build` alone
# provides.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    libclang-dev \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release -p server

########################################
# Runtime stage
########################################
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcap2-bin \
    gettext-base \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /var/lib/litterae --shell /usr/sbin/nologin litterae

COPY --from=builder /build/target/release/litterae /usr/local/bin/litterae
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/litterae.toml.template /etc/litterae/litterae.toml.template

# Port 25 is privileged (<1024); grant just the one capability needed to
# bind it rather than running the process as root (spec's own hardening
# posture: least privilege where practical).
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/litterae \
    && chmod +x /entrypoint.sh

ENV LITTERAE_CONFIG=/etc/litterae/litterae.toml
ENV LITTERAE_LOG_DIR=/var/log/litterae

RUN mkdir -p /var/log/litterae /data/blobs \
    && chown -R litterae:litterae /var/log/litterae /data /etc/litterae

USER litterae
WORKDIR /var/lib/litterae

# 25/587/465 SMTP+submission, 8620 JMAP, 8621 admin.
EXPOSE 25 587 465 8620 8621

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/litterae"]
