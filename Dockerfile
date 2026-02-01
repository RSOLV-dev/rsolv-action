# Base stage with common dependencies
FROM oven/bun:latest AS base

# Cache-busting argument - use current timestamp or commit SHA to force rebuilds
# Updated for vendor skip fix - 2025-10-10
ARG CACHE_BUST=2

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI globally with bun
RUN bun install -g @anthropic-ai/claude-code && \
    which claude && \
    claude --version || echo "Claude CLI installed but version check failed"

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

# Install Node.js for Claude Code SDK (some tools still need it)
# Also install libc compatibility libraries for SDK native binaries (fixes Docker spawn issues)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs libc6 libstdc++6 libgcc-s1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install production dependencies only (includes @anthropic-ai/claude-code)
RUN bun install --frozen-lockfile --production

# Copy source files
COPY src/ ./src/
COPY tsconfig.json ./

# Build the TypeScript files
RUN bun run build

# Verify build output exists
RUN ls -la dist/

# Verify Claude Code SDK is installed
RUN ls -la node_modules/@anthropic-ai/claude-code/cli.js || echo "Claude Code SDK not found"

# Production stage
FROM base AS production

# Install libc compatibility libraries for SDK native binaries (fixes Docker spawn issues)
# These are required for the Claude Agent SDK to spawn processes correctly
# Also install build dependencies for mise to compile runtimes (Ruby, Python, etc.) from source
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libc6 libstdc++6 libgcc-s1 procps \
      build-essential libssl-dev libreadline-dev zlib1g-dev \
      libyaml-dev libffi-dev libgdbm-dev libncurses5-dev \
      autoconf bison && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install mise for multi-runtime support (Ruby, Python, Java, etc.)
# Runtimes are installed on-demand per project via ensureRuntime() in test-runner
RUN curl https://mise.run | sh
ENV PATH="/root/.local/share/mise/shims:/root/.local/bin:${PATH}"

# Copy Node.js and npm toolchain from builder
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

# Verify Claude Code SDK is available
RUN ls -la /app/node_modules/@anthropic-ai/claude-code/cli.js || echo "Claude Code SDK not found in production"

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set up permissions for GitHub Actions runtime
RUN mkdir -p /github/workspace && \
    chmod 777 /github/workspace && \
    chmod 777 /app

ENTRYPOINT ["/entrypoint.sh"]
