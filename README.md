# RSOLV API Service

Backend API service for the RSOLV automated issue fixing platform.

## Overview

This API service handles:

- Authentication and authorization
- Usage tracking and metrics
- Expert review request management
- Customer dashboard data

## Architecture

The RSOLV API is built with Phoenix/Elixir for reliability and scalability. It provides the central coordination point between GitHub Actions, expert reviewers, and customer dashboards.

## Security

The API is designed with security as a top priority, ensuring:

- No customer source code is ever stored or processed by the API
- Only metadata about issues and fixes is transmitted
- All communication is encrypted with TLS
- API keys are required for all requests

## Development Setup

```bash
# Install dependencies
mix deps.get

# Setup the database
mix ecto.setup

# Start the Phoenix server
mix phx.server
```

## API Endpoints

### Authentication

- `POST /api/auth` - Authenticate and retrieve a token

### Usage

- `POST /api/usage` - Report usage metrics
- `GET /api/usage/:customer_id` - Get usage statistics

### Expert Review

- `POST /api/review/request` - Request expert review
- `GET /api/review/:review_id` - Get review status
- `POST /api/review/:review_id/comment` - Post expert comment

## Deployment

The API service is deployed using Docker and Kubernetes for high availability and scalability.