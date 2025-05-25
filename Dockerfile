# Use official Elixir image
FROM elixir:1.15-alpine AS deps

# Install build dependencies
RUN apk add --no-cache build-base git

# Set working directory
WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config

# Install dependencies
RUN mix deps.get --only prod

# Dependencies compilation stage
FROM deps AS deps-compiled
RUN mix deps.compile

# Builder stage
FROM deps-compiled AS builder

# Copy source code
COPY lib lib
COPY priv priv

# Use parallel compilation
ENV ERL_FLAGS="+JPperf true"
ENV ELIXIR_MAKE_CACHE_DIR=/app/.make_cache

# Compile the application with optimizations
RUN MIX_ENV=prod mix compile

# Build release with optimizations
RUN MIX_ENV=prod mix release --overwrite

# Final stage - minimal runtime image
FROM alpine:3.19

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