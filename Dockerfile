# Multi-stage build for RSOLV Platform
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

# Copy assets
COPY assets assets
COPY priv priv

# Build assets (esbuild is handled by mix)
RUN mix assets.deploy

# Copy source code
COPY lib lib

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
    python3 \
    ruby ruby-dev \
    php82 php82-json php82-tokenizer \
    nodejs npm bash

# Install Ruby parser gem
RUN apk add --no-cache --virtual .build-deps build-base && \
    gem install bundler parser --no-document && \
    apk del .build-deps && \
    rm -rf /root/.gem /usr/lib/ruby/gems/*/cache/*

# Install PHP dependencies for parser
RUN apk add --no-cache php82-dom php82-mbstring

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