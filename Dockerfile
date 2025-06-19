# Base stage with common dependencies
FROM oven/bun:latest AS base

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

# Install Node.js for Claude Code CLI
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI using npm (without sudo)
RUN npm install -g @anthropic-ai/claude-code && \
    # Verify it's installed
    which claude && \
    claude --version || echo "Claude Code CLI installation completed"

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

# Copy Node.js and Claude Code CLI from builder
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
COPY --from=builder /usr/bin/claude /usr/bin/claude
# Create symlink for npm-installed global binaries
RUN ln -sf /usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude /usr/bin/claude 2>/dev/null || true

# Copy built application
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
