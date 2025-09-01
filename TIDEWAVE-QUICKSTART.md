# Tidewave Quick Start

## 🚀 Instant Start

```bash
./start-tidewave.sh
```

This script will:
1. Check for your Anthropic API key
2. Let you choose local or Docker environment
3. Start Tidewave automatically

## 🔑 API Key Setup

Your ANTHROPIC_API_KEY is **already configured** in your shell environment.

For team members or fresh setups:
1. **Shell (recommended)**: Add to ~/.zshrc or ~/.bashrc
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

2. **Local file**: Create .env.dev (gitignored)
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

## 📍 Access Points

### Local Development (Port 4000)
- Tidewave UI: http://localhost:4000/tidewave
- Network access: http://10.5.0.5:4000/tidewave
- Health check: http://localhost:4000/health

### Docker Compose (Port 4001) 
- Tidewave UI: http://localhost:4001/tidewave
- Network access: http://10.5.0.5:4001/tidewave
- Health check: http://localhost:4001/health

## ✅ Current Status

**Everything is ready for immediate use:**
- ✅ Tidewave 0.4.1 integrated
- ✅ Local development configured
- ✅ Docker Compose configured
- ✅ Network access enabled (10.x.x.x)
- ✅ Hot code reloading works
- ✅ API key inherited from shell
- ✅ Security documented

## 🛠 Manual Commands

### Local Development
```bash
# Start
mix phx.server

# Tidewave at: http://localhost:4000/tidewave
```

### Docker Compose
```bash
# Start
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop
docker-compose -f docker-compose.dev.yml down

# Tidewave at: http://localhost:4001/tidewave
```

## 🔧 Troubleshooting

### API Key Issues
```bash
# Check if key is set
echo $ANTHROPIC_API_KEY

# Set temporarily
export ANTHROPIC_API_KEY="your-key"

# Set permanently (add to ~/.zshrc)
echo 'export ANTHROPIC_API_KEY="your-key"' >> ~/.zshrc
source ~/.zshrc
```

### Docker Issues
```bash
# Clean restart
docker-compose -f docker-compose.dev.yml down -v
docker-compose -f docker-compose.dev.yml up --build

# Check logs
docker-compose -f docker-compose.dev.yml logs rsolv-api
```

### Network Access Issues
- Ensure firewall allows port 4000/4001
- Check server is bound to 0.0.0.0 (not 127.0.0.1)
- Verify with: `ss -tln | grep 400`

## 📚 Documentation

- [Security Considerations](TIDEWAVE-SECURITY.md)
- [Docker Setup Details](TIDEWAVE-DOCKER.md)
- [Tidewave Docs](https://tidewave.ai/docs)

## 🎯 Use Cases

Tidewave is perfect for:
- **AST Debugging**: Analyze pattern matching and parser behavior
- **Vulnerability Detection**: Test and refine detection patterns
- **Code Generation**: Generate Elixir modules and tests
- **Refactoring**: Safely refactor with AI assistance
- **Documentation**: Generate comprehensive docs
- **Learning**: Understand Phoenix/Elixir patterns

## ⚠️ Important Notes

- **Development Only**: Never deploy to staging/production
- **API Costs**: Be mindful of Anthropic API usage
- **Code Review**: Always review AI-generated code
- **Git Workflow**: Commit manually after reviewing changes