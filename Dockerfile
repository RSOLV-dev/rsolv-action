# Base stage with common dependencies
FROM oven/bun:latest AS base

# Cache-busting argument - use current timestamp or commit SHA to force rebuilds
# Updated for vendor skip fix - 2025-10-10
ARG CACHE_BUST=2

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package.json bun.lock* ./

# Development/test stage
FROM base AS test

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

# Build the TypeScript files
RUN bun run build

# Verify build output exists
RUN ls -la dist/

# Production stage
FROM base AS production

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
      zstd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install mise for multi-runtime support (Ruby, Python, Java, etc.)
# Runtimes are installed on-demand per project via ensureRuntime() in test-runner
RUN curl https://mise.run | sh
ENV PATH="/root/.local/share/mise/shims:/root/.local/bin:${PATH}"

# Set Gradle cache to writable directory (root cause #31: Docker root user conflicts with default ~/.gradle)
ENV GRADLE_USER_HOME=/tmp/.gradle

# Install uv for fast Python package management (PEP 668 safe, 10-100x faster than pip)
# RFC-103: Default Python installer — respects project lock files, falls back to uv pip install
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && uv --version

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

# Copy built application and all dependencies
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
