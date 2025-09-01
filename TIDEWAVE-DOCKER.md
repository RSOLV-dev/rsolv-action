# Using Tidewave with Docker Compose

## Overview
Tidewave can be used in Docker Compose for team development environments. This allows developers to use AI-assisted coding without local Elixir setup.

## Quick Start

1. **Set your Anthropic API key**:
   ```bash
   export ANTHROPIC_API_KEY="your-api-key-here"
   ```

2. **Start the development environment**:
   ```bash
   docker-compose -f docker-compose.dev.yml up
   ```

3. **Access Tidewave**:
   - From host machine: http://localhost:4001/tidewave
   - From local network: http://[docker-host-ip]:4001/tidewave

## Features

### ✅ What Works in Docker
- Full Tidewave AI assistance
- Code generation and refactoring
- LiveView debug annotations
- Hot code reloading via volume mounts
- Access from any machine on local network
- Persistent database between restarts

### ⚠️ Limitations
- **Development only** - never use in production
- Performance may be slightly slower than native
- File watchers might need container restart occasionally
- Browser connection might need refresh after container restart

## Configuration

### Environment Variables
Set these before running docker-compose:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."  # Required for Tidewave
export OPENAI_API_KEY="..."            # Optional
export OPENROUTER_API_KEY="..."        # Optional
```

### Network Access
The dev compose file configures:
- PHX_HOST set to "0.0.0.0" for external access
- Port 4001 exposed (to avoid conflicts)
- Extra hosts configured for Docker networking

### Volume Mounts
Development volumes are mounted for hot reloading:
- Source code: `.:/app`
- Dependencies: `deps:/app/deps`
- Build artifacts: `_build:/app/_build`

## Team Development

### For Team Members
1. Clone the repository
2. Copy `.env.example` to `.env.dev` and add your API key
3. Run: `docker-compose -f docker-compose.dev.yml up`
4. Access Tidewave at http://localhost:4001/tidewave

### Sharing Sessions
- Team members on same network can access each other's instances
- Use host machine's IP address instead of localhost
- Example: http://10.0.1.50:4001/tidewave

## Troubleshooting

### Tidewave not loading
- Check ANTHROPIC_API_KEY is set: `echo $ANTHROPIC_API_KEY`
- Verify container logs: `docker-compose -f docker-compose.dev.yml logs rsolv-api`
- Ensure you're using port 4001, not 4000

### Connection refused from network
- Check Docker host allows external connections
- Verify firewall rules allow port 4001
- Confirm PHX_HOST is set to "0.0.0.0" in compose file

### Hot reload not working
- Restart the container: `docker-compose -f docker-compose.dev.yml restart rsolv-api`
- Check volume mounts are correct
- Verify file system events are propagating

## Security Notes

⚠️ **IMPORTANT**: 
- Never deploy Tidewave to staging/production
- Keep API keys secure and rotate regularly
- Only use on trusted development networks
- Review all AI-generated code before committing

## Why Not Staging?

Tidewave is intentionally restricted to development because:
1. **Security**: Exposes AI-assisted code modification capabilities
2. **Cost**: Would incur API costs for all staging users
3. **Purpose**: It's a development tool, not a runtime feature
4. **Compliance**: Prevents accidentally processing production data

## Alternative for Remote Development

If you need AI assistance on a remote server:
1. Use SSH port forwarding: `ssh -L 4001:localhost:4001 your-server`
2. Run Docker Compose on the remote server
3. Access via the forwarded port locally

This keeps Tidewave secure while enabling remote development.