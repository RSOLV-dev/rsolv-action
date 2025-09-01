# Tidewave MCP Integration with Claude Desktop

## Overview

Tidewave includes a built-in MCP (Model Context Protocol) server that exposes Phoenix/Elixir development tools to Claude Desktop. This allows Claude to directly interact with your running application.

## Available MCP Tools

Tidewave exposes the following MCP tools:

### 1. **Logs Tool**
- Read application logs
- Filter by severity level
- Search log messages
- Access Phoenix request logs

### 2. **Source Tool**  
- Read source files from the project
- Navigate module structures
- Access configuration files
- Browse dependencies

### 3. **Eval Tool**
- Execute Elixir code in the application context
- Inspect running processes
- Query application state
- Test functions interactively

### 4. **Ecto Tool**
- Run database queries
- Inspect schemas
- Execute migrations status checks
- Interact with Repo directly

### 5. **Hex Tool**
- Check package versions
- List dependencies
- Search for packages
- Inspect package documentation

## Setting Up Claude Desktop Integration

### Step 1: Start Tidewave with MCP Server

```bash
# Start locally with MCP enabled
./start-tidewave.sh

# Or manually
mix phx.server
```

The MCP server will be available at:
- Local: `http://localhost:4000/tidewave/mcp`
- Docker: `http://localhost:4001/tidewave/mcp`

### Step 2: Configure Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "rsolv-platform": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", "@-",
        "http://localhost:4000/tidewave/mcp"
      ],
      "env": {},
      "disabled": false
    }
  }
}
```

For Docker setup, use port 4001 instead:
```json
"http://localhost:4001/tidewave/mcp"
```

### Step 3: Alternative - Direct HTTP Configuration

If you prefer, you can configure it as an HTTP endpoint:

```json
{
  "mcpServers": {
    "rsolv-platform": {
      "type": "http",
      "url": "http://localhost:4000/tidewave/mcp",
      "headers": {
        "Content-Type": "application/json"
      }
    }
  }
}
```

## Usage Examples

Once configured, Claude Desktop can use these tools directly:

### Reading Source Files
```
Use the source tool to read lib/rsolv_web/controllers/health_controller.ex
```

### Checking Logs
```
Use the logs tool to show the last 50 error messages
```

### Running Database Queries
```
Use the ecto tool to query: SELECT COUNT(*) FROM early_access_signups
```

### Evaluating Code
```
Use the eval tool to run: Application.get_all_env(:rsolv)
```

### Checking Dependencies
```
Use the hex tool to list all dependencies and their versions
```

## Security Considerations

⚠️ **IMPORTANT SECURITY NOTES:**

1. **Development Only** - Never expose MCP endpoint in production
2. **Local Network** - MCP server is accessible from 10.x.x.x addresses
3. **No Authentication** - MCP endpoint has no auth by default
4. **Code Execution** - Eval tool can execute arbitrary Elixir code
5. **Database Access** - Ecto tool has full database access

### Recommended Security Practices

1. **Firewall Rules** - Restrict MCP port access to localhost only:
   ```bash
   # Example with iptables
   iptables -A INPUT -p tcp --dport 4000 -s 127.0.0.1 -j ACCEPT
   iptables -A INPUT -p tcp --dport 4000 -j DROP
   ```

2. **Environment Check** - Ensure MCP only runs in dev:
   ```elixir
   # Already configured in endpoint.ex
   if code_reloading? do
     # MCP only available in dev
   end
   ```

3. **Network Isolation** - Use Docker network isolation:
   ```bash
   docker-compose -f docker-compose.dev.yml up
   # MCP contained within Docker network
   ```

## Troubleshooting

### MCP Not Responding
```bash
# Check if server is running
curl http://localhost:4000/tidewave/mcp

# Check logs
docker-compose -f docker-compose.dev.yml logs | grep -i mcp
```

### Tools Not Available
```bash
# Verify Tidewave is loaded
mix phx.server

# Check available tools (correct endpoint)
curl -X POST http://localhost:4000/tidewave/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

### Permission Errors
- Ensure Phoenix server has necessary file permissions
- Check database user has required privileges
- Verify Elixir has execution permissions

## Advanced Configuration

### Custom Tool Development

You can extend Tidewave with custom MCP tools by creating modules in your project:

```elixir
defmodule MyApp.MCP.CustomTool do
  def tools do
    [
      %{
        name: "my_custom_tool",
        description: "Does something custom",
        inputSchema: %{
          type: "object",
          properties: %{
            query: %{type: "string"}
          }
        },
        callback: &handle_custom_tool/1
      }
    ]
  end
  
  defp handle_custom_tool(%{"query" => query}) do
    # Your custom logic here
    %{result: "processed: #{query}"}
  end
end
```

Then register it in your application startup.

## Benefits for RSOLV Development

With MCP integration, Claude can:

1. **Debug AST Issues** - Read parser files and evaluate AST transformations
2. **Test Patterns** - Run pattern matching queries directly
3. **Inspect Database** - Check vulnerability patterns and fix attempts
4. **Monitor Logs** - Track real-time issues during development
5. **Explore Code** - Navigate the codebase efficiently

## Related Documentation

- [Tidewave Quick Start](TIDEWAVE-QUICKSTART.md)
- [Tidewave Security](TIDEWAVE-SECURITY.md)
- [MCP Specification](https://modelcontextprotocol.io/)
- [Claude Desktop Docs](https://claude.ai/docs/desktop)