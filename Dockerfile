# Multi-stage build for RSOLV Platform (Alpine-based)
# Stage 1: Build stage
FROM elixir:1.18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base git nodejs npm python3 bash

# Set working directory
WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Set build environment
ENV MIX_ENV=prod

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config

# Install dependencies
RUN mix deps.get --only prod && \
    mix deps.compile

# Copy assets and non-static priv files
COPY assets assets
COPY priv/repo priv/repo
COPY priv/parsers priv/parsers
COPY priv/benchmarks priv/benchmarks
COPY priv/blog priv/blog
COPY priv/grafana_dashboards priv/grafana_dashboards

# Build assets
RUN rm -rf priv/static && mix assets.deploy

# Copy source code
COPY lib lib

# Copy the correct static files
COPY priv/static priv/static

# Compile the application
RUN mix compile

# Build release
RUN mix release

# Copy custom env.sh
COPY rel/env.sh _build/prod/rel/rsolv/releases/0.1.0/env.sh

# Stage 2: Runtime stage
FROM alpine:3.22

# Install runtime dependencies including parser runtimes
RUN apk add --no-cache \
    openssl ncurses-libs libstdc++ libgcc \
    curl \
    ca-certificates \
    python3 \
    ruby ruby-dev ruby-bundler \
    php82 php82-json php82-tokenizer \
    nodejs npm bash

# Install Ruby gems for parser (needs build-base temporarily for native extensions)
COPY --from=builder /app/priv/parsers/ruby/Gemfile /tmp/ruby-parser/Gemfile
COPY --from=builder /app/priv/parsers/ruby/Gemfile.lock /tmp/ruby-parser/Gemfile.lock
RUN apk add --no-cache --virtual .build-deps build-base && \
    cd /tmp/ruby-parser && \
    bundle install --system --jobs=4 --retry=3 && \
    rm -rf /tmp/ruby-parser && \
    apk del .build-deps

# Create app user
RUN adduser -D -h /app app

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

# Copy release from builder
COPY --from=builder --chown=app:app /app/_build/prod/rel/rsolv /app

# Start the application
CMD ["bin/rsolv", "start"]
