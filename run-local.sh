#!/bin/bash
# Local development script for RSOLV API

echo "Setting up RSOLV API for local development..."

# Set required environment variables
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/rsolv_api_dev"
export SECRET_KEY_BASE="your-secret-key-base-here-at-least-64-chars-long-abcdefghijklmnopqrstuvwxyz0123456789"
export PHX_HOST="localhost"
export PORT="4000"

# AI Provider keys (you'll need to set these)
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-your-anthropic-key}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-your-openai-key}"
export OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-your-openrouter-key}"

# Email (optional for now)
export SENDGRID_API_KEY="${SENDGRID_API_KEY:-dummy-key}"

# LiveView salt
export LIVE_VIEW_SALT="your-live-view-salt"

echo "Environment variables set."
echo ""
echo "Make sure you have PostgreSQL running locally with:"
echo "  - Database: rsolv_api_dev"
echo "  - User: postgres"
echo "  - Password: postgres"
echo ""
echo "To create the database, run:"
echo "  createdb -U postgres rsolv_api_dev"
echo ""
echo "Installing dependencies..."
mix deps.get

echo ""
echo "Creating and migrating database..."
mix ecto.create
mix ecto.migrate

echo ""
echo "Starting Phoenix server..."
mix phx.server