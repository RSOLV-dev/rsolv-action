# Use official Elixir image
FROM elixir:1.15-alpine AS base

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

# Install curl for healthchecks
RUN apk add --no-cache curl

# Install all dependencies (dev, test, prod)
RUN mix deps.get

# Copy all source code
COPY . .

# Compile dependencies
RUN mix deps.compile

# Default command for development
CMD ["mix", "phx.server"]

# Production dependencies stage
FROM base AS prod-deps

# Install only prod dependencies
RUN mix deps.get --only prod
RUN mix deps.compile

# Builder stage for production
FROM prod-deps AS builder

# Copy source code
COPY lib lib
COPY priv priv
COPY rel rel

# Use parallel compilation
ENV ERL_FLAGS="+JPperf true"
ENV ELIXIR_MAKE_CACHE_DIR=/app/.make_cache

# Compile the application with optimizations
RUN MIX_ENV=prod mix compile

# Build release with optimizations
RUN MIX_ENV=prod mix release --overwrite

# Final production stage - minimal runtime image
FROM alpine:3.19 AS production

# Install runtime dependencies
RUN apk add --no-cache openssl ncurses-libs libstdc++ libgcc

# Create app user
RUN adduser -D -h /app app

# Copy release from builder
COPY --from=builder --chown=app:app /app/_build/prod/rel/rsolv_api /app

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
CMD ["bin/rsolv_api", "start"]