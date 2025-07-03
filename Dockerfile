# Use official Elixir image
FROM elixir:1.18-alpine AS base

# Install build dependencies
RUN apk add --no-cache build-base git postgresql-client

# Set working directory
WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config

# Development stage - includes full Elixir/mix environment
FROM base AS development

# Install curl for healthchecks and parser languages for development
RUN apk add --no-cache curl \
    # Parser runtimes needed for development AST analysis
    python3 \
    ruby ruby-dev \
    php82 php82-json php82-tokenizer \
    # Required for JavaScript parser and shell scripts
    nodejs npm bash

# Install Ruby bundler and parser gem (make it optional to not block build)
RUN gem install bundler --no-document || true && \
    gem install parser --no-document || true && \
    rm -rf /root/.gem /usr/lib/ruby/gems/*/cache/* || true

# Install additional PHP extensions that parsers might need
RUN apk add --no-cache php82-dom php82-mbstring

# Install all dependencies (dev, test, prod)
RUN mix deps.get

# Copy all source code
COPY . .

# Compile dependencies
RUN mix deps.compile

# CRITICAL: Compile the application including patterns
# This ensures pattern modules are available even with volume mounts
RUN mix compile

# Preserve compiled pattern beams for volume mount scenario
# Copy them to a location that won't be overridden by volume mounts
RUN mkdir -p /pattern-beams && \
    cp -r _build/dev/lib/rsolv_api/ebin/*pattern*.beam /pattern-beams/ 2>/dev/null || true && \
    cp -r _build/dev/lib/rsolv_api/ebin/*Pattern*.beam /pattern-beams/ 2>/dev/null || true

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Use entrypoint to ensure compilation
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command for development
CMD ["mix", "phx.server"]

# Production dependencies stage
FROM base AS prod-deps

# Install only prod dependencies
RUN mix deps.get --only prod
RUN mix deps.compile

# Builder stage for production
FROM prod-deps AS builder

# Install Node.js for asset compilation
RUN apk add --no-cache nodejs npm

# Copy source code
COPY lib lib
COPY priv priv
COPY rel rel
COPY assets assets
COPY package.json package-lock.json tailwind.config.js ./

# Install npm dependencies and build CSS
RUN npm install
RUN npm run deploy

# Use parallel compilation
ENV ERL_FLAGS="+JPperf true"
ENV ELIXIR_MAKE_CACHE_DIR=/app/.make_cache

# Compile the application with optimizations
RUN MIX_ENV=prod mix compile

# Generate static asset digests
RUN MIX_ENV=prod mix phx.digest

# Build release with optimizations
RUN MIX_ENV=prod mix release --overwrite

# Final production stage - minimal runtime image
FROM alpine:3.19 AS production

# Install runtime dependencies including parser languages
# Note: Keeping image relatively small by only including essential runtimes
RUN apk add --no-cache \
    # Elixir/Erlang runtime dependencies
    openssl ncurses-libs libstdc++ libgcc \
    # Parser runtimes - only the most commonly used initially
    python3 \
    ruby \
    php82 php82-json php82-tokenizer \
    # Required for JavaScript parser and shell scripts
    nodejs npm bash

# Install Ruby bundler and parser gem
RUN gem install bundler parser --no-document && \
    rm -rf /root/.gem /usr/lib/ruby/gems/*/cache/*

# Install additional PHP extensions that parsers might need
RUN apk add --no-cache php82-dom php82-mbstring

# Create app user
RUN adduser -D -h /app app

# Copy release from builder
COPY --from=builder --chown=app:app /app/_build/prod/rel/rsolv /app

# Set environment
ENV HOME=/app
ENV MIX_ENV=prod
ENV PORT=4000

# Expose port
EXPOSE 4000

# Switch to app user
USER app

# Set working directory
WORKDIR /app

# Start the application
CMD ["bin/rsolv", "start"]