FROM oven/bun:latest

# Install additional dependencies
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /rsolv

# Copy package files
COPY package.json bun.lockb ./

# Install dependencies
RUN bun install --frozen-lockfile

# Copy source code
COPY src ./src
COPY tsconfig.json ./

# Build TypeScript code
RUN bun run build

# Set entrypoint
ENTRYPOINT ["bun", "run", "/rsolv/dist/index.js"]