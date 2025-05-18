FROM oven/bun:latest

WORKDIR /app

# Copy package.json and install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source files
COPY src/ ./src/

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set up secure environment
RUN addgroup --system rsolv && adduser --system --group rsolv
USER rsolv

ENTRYPOINT ["/entrypoint.sh"]
