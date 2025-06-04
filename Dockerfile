FROM oven/bun:latest

WORKDIR /app

# Install Claude Code CLI
RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://claude.ai/install.sh | sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy package.json and install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source files
COPY src/ ./src/
COPY tsconfig.json ./

# Build the TypeScript files
RUN bun run build

# Verify build output exists
RUN ls -la dist/

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set up permissions for GitHub Actions runtime
RUN mkdir -p /github/workspace && \
    chmod 777 /github/workspace && \
    chmod 777 /app

ENTRYPOINT ["/entrypoint.sh"]
