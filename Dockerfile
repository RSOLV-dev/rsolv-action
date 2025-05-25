FROM oven/bun:latest

WORKDIR /app

# Copy package.json and install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source files
COPY src/ ./src/
COPY tsconfig.json ./

# Build the TypeScript files
RUN bun run build || echo "No build script, running TypeScript directly"

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set up secure environment with proper permissions
RUN addgroup --system rsolv && adduser --system --group rsolv && \
    chown -R rsolv:rsolv /app && \
    mkdir -p /github/workspace && \
    chown -R rsolv:rsolv /github

# Switch to non-root user
USER rsolv

ENTRYPOINT ["/entrypoint.sh"]
