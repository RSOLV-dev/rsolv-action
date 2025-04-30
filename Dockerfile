FROM oven/bun:latest

# Install additional dependencies
RUN apt-get update && \
    apt-get install -y git curl gnupg2 sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (needed for Claude Code)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /rsolv

# Copy package files
COPY package.json ./
# Copy lock file if it exists
COPY bun.lockb* ./

# Install dependencies
RUN bun install

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Copy source code
COPY src ./src
COPY tsconfig.json ./

# Build TypeScript code
RUN bun run build

# Create a directory for Claude CLI config
RUN mkdir -p /root/.claude

# Set environment variables
ENV CLAUDE_CONFIG_DIR=/root/.claude
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Set entrypoint
ENTRYPOINT ["bun", "run", "/rsolv/dist/index.js"]