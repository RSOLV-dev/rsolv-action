# Base stage with common dependencies
FROM oven/bun:1@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS base

# Cache-busting argument - use current timestamp or commit SHA to force rebuilds
# Updated for vendor skip fix - 2025-10-10
ARG CACHE_BUST=2

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Development/test stage
FROM base AS test

# Copy package files
COPY package.json bun.lock* ./

# Install all dependencies (including dev)
RUN bun install --frozen-lockfile

# Copy all source files
COPY . .

# Build the project
RUN bun run build || true

# Default command for testing
CMD ["bun", "test"]

# Production build stage
FROM base AS builder

# Copy package files
COPY package.json bun.lock* ./

# Install Node.js: test-runner.ts runs customer jest/vitest/mocha suites via the `node`
# runtime and shells out to `npm ci` / `npm install` for JS/TS projects. Not optional.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs libc6 libstdc++6 libgcc-s1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install production dependencies only
RUN bun install --frozen-lockfile --production

# Copy source files
COPY src/ ./src/
COPY tsconfig.json ./

# Build the TypeScript files: the v4 action, and the v5 sandbox CLI
RUN bun run build && bun run build:sandbox

# Verify build output exists
RUN ls -la dist/

# Toolchain shared by the v4 action (production) and the v5 sandbox: system
# packages, mise, uv and Node. mise and uv live in /usr/local/bin so any user
# can run them.
FROM base AS toolchain

# libc compatibility libraries for native binaries, plus build dependencies for mise to
# compile runtimes (Ruby, Python, etc.) from source and for native gem/package builds
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libc6 libstdc++6 libgcc-s1 procps \
      build-essential libssl-dev libreadline-dev zlib1g-dev \
      libyaml-dev libffi-dev libgdbm-dev libncurses5-dev \
      autoconf bison \
      # Database client libraries for native gem/package compilation
      # (mysql2, pg, sqlite3 gems; psycopg2, mysqlclient Python packages)
      default-libmysqlclient-dev libpq-dev libsqlite3-dev \
      # RFC-103 B1: PostgreSQL for ephemeral test databases (Elixir/Phoenix projects)
      # Started on-demand by ensurePostgresql() in test-runner — NOT running by default
      postgresql postgresql-client \
      # RFC-103 B2: shared-mime-info for Ruby mimemagic/marcel gems (MIME type detection)
      shared-mime-info \
      # zstd required by mise installer (ships .tar.zst archives)
      zstd \
      # RFC-150: lets the v5 sandbox's arbitrary UID, which has no passwd entry, run PostgreSQL
      libnss-wrapper && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install mise for multi-runtime support (Ruby, Python, Java, etc.)
# Runtimes are installed on-demand per project via ensureRuntime() in test-runner
RUN curl https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh && mise --version

# Install uv for fast Python package management (PEP 668 safe, 10-100x faster than pip)
# RFC-103: Default Python installer — respects project lock files, falls back to uv pip install
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh && uv --version

# Copy Node.js and npm toolchain from builder (needed to run customer JS/TS test suites)
# node binary
COPY --from=builder /usr/bin/node /usr/bin/node
# npm lib directory (contains npm package with bin/npm-cli.js, bin/npx-cli.js, lib/cli.js)
COPY --from=builder /usr/lib /usr/lib
# Recreate npm/npx symlinks (Docker COPY resolves symlinks to regular files, breaking
# the require('../lib/cli.js') path resolution in npx-cli.js and npm-cli.js)
RUN ln -sf /usr/lib/node_modules/npm/bin/npm-cli.js /usr/bin/npm && \
    ln -sf /usr/lib/node_modules/npm/bin/npx-cli.js /usr/bin/npx

# Verify Node.js toolchain works in production stage
RUN node --version && npm --version && npx --version

# v5 sandbox (RFC-150, ADR-077 §5): the rsolv-sandbox CLI and the toolchain,
# with no credentials, no entrypoint and nothing else from the repository. The
# host runs it as its own non-root UID with HOME=/opt/home, a private directory
# it mounts, so every per-user path (mise runtimes, caches, global config) is
# under HOME. MISE_TRUSTED_CONFIG_PATHS lets a repository's mise config apply,
# inside the sandbox only.
FROM toolchain AS sandbox
# PHP: mise's vfox-php plugin compiles the version a repository asks for, as
# the sandbox user, behind the egress proxy (RFC-150 3d, owner decision
# 2026-11-07). These are exactly the plugin's documented Debian build
# dependencies (github.com/jdx/vfox-php README).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential autoconf bison re2c pkg-config \
      libxml2-dev libssl-dev libicu-dev libzip-dev libonig-dev \
      libcurl4-openssl-dev libpng-dev libjpeg-dev libfreetype6-dev \
      libwebp-dev libgmp-dev libsodium-dev libreadline-dev libbz2-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Composer, one composer.phar pinned by SHA-256, so the sandbox needs no egress
# to getcomposer.org; it runs on whichever PHP mise builds.
COPY scripts/install-composer.sh /tmp/install-composer.sh
RUN sh /tmp/install-composer.sh /usr/local/bin/composer && rm /tmp/install-composer.sh
COPY --from=builder /app/dist/sandbox /opt/rsolv
ENV HOME=/opt/home \
    PATH="/opt/home/.local/share/mise/shims:${PATH}" \
    MISE_TRUSTED_CONFIG_PATHS=/work \
    MISE_YES=1
RUN printf '#!/bin/sh\nexec /usr/bin/node /opt/rsolv/cli.js "$@"\n' > /usr/local/bin/rsolv-sandbox \
 && chmod 0755 /usr/local/bin/rsolv-sandbox \
 && ln -s /usr/lib/postgresql/*/bin/initdb /usr/lib/postgresql/*/bin/pg_ctl /usr/local/bin/
WORKDIR /work
# No entrypoint: the host starts the container with its own and runs each
# subcommand through docker exec.
ENTRYPOINT []
CMD ["rsolv-sandbox"]

# v4 Docker action: unchanged entrypoint, environment, workspace permissions and
# dist/ copy. It must stay the last stage: action.yml builds the default target.
FROM toolchain AS production
ENV PATH="/root/.local/share/mise/shims:/root/.local/bin:${PATH}"

# Set Gradle cache to writable directory (root cause #31: Docker root user conflicts with default ~/.gradle)
ENV GRADLE_USER_HOME=/tmp/.gradle

# Copy package files, built application and all dependencies
COPY package.json bun.lock* ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set up permissions for GitHub Actions runtime
RUN mkdir -p /github/workspace && \
    chmod 777 /github/workspace && \
    chmod 777 /app

ENTRYPOINT ["/entrypoint.sh"]
