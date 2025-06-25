# RSOLV AST Parser Scripts

This directory contains language-specific parser scripts that run as external Port processes to provide AST analysis for RFC-031.

## Directory Structure

```
priv/parsers/
├── README.md           # This file
├── setup/              # Installation and setup scripts
│   ├── install-all.sh  # Install all parser dependencies
│   └── verify.sh       # Verify parser installations
├── python/             # Python AST parser
│   ├── parser.py       # Main parser script
│   └── lib/            # Python-specific libraries
├── ruby/               # Ruby parser
│   ├── parser.rb       # Main parser script
│   └── lib/            # Ruby-specific libraries
├── php/                # PHP parser
│   ├── parser.php      # Main parser script
│   └── lib/            # PHP-specific libraries (vendor/)
├── java/               # Java parser
│   ├── parser.java     # Main parser script
│   └── lib/            # JAR dependencies
└── go/                 # Go parser
    ├── parser.go       # Main parser script
    └── lib/            # Go modules
```

## Communication Protocol

All parsers communicate via JSON over stdin/stdout with the following protocol:

### Request Format
```json
{
  "action": "parse",
  "id": "unique-request-id",
  "code": "source code to parse",
  "filename": "example.py",
  "options": {
    "language_version": "3.11",
    "include_comments": false
  }
}
```

### Response Format (Success)
```json
{
  "id": "unique-request-id",
  "status": "success",
  "ast": { /* AST structure */ },
  "metadata": {
    "parser_version": "1.0.0",
    "language_version": "3.11",
    "parse_time_ms": 42
  }
}
```

### Response Format (Error)
```json
{
  "id": "unique-request-id",
  "status": "error",
  "error": {
    "type": "SyntaxError",
    "message": "Unexpected token at line 5",
    "line": 5,
    "column": 10
  }
}
```

## Parser Requirements

### Python Parser
- **Runtime**: Python 3.8+
- **Dependencies**: None (uses built-in `ast` module)
- **Features**: Full Python AST with type comments

### Ruby Parser
- **Runtime**: Ruby 2.7+
- **Dependencies**: `parser` gem
- **Install**: `gem install parser`

### PHP Parser
- **Runtime**: PHP 7.4+
- **Dependencies**: nikic/php-parser
- **Install**: `composer require nikic/php-parser`

### Java Parser
- **Runtime**: Java 11+
- **Dependencies**: JavaParser
- **Install**: Download JAR to `java/lib/`

### Go Parser
- **Runtime**: Go 1.18+
- **Dependencies**: None (uses built-in `go/parser`)

## Setup Instructions

1. Run the setup script to install all dependencies:
   ```bash
   cd priv/parsers/setup
   ./install-all.sh
   ```

2. Verify installations:
   ```bash
   ./verify.sh
   ```

## Testing Parsers

Each parser can be tested standalone:

```bash
# Python
echo '{"action":"parse","id":"test","code":"def hello(): pass"}' | python python/parser.py

# Ruby
echo '{"action":"parse","id":"test","code":"def hello; end"}' | ruby ruby/parser.rb
```

## Security Considerations

- Parsers run with limited resources (CPU, memory, time)
- No network access permitted
- Input size limited to 10MB
- Automatic process termination after 30s
- All code is ephemeral - never written to disk

## Adding New Languages

1. Create directory: `mkdir -p newlang/lib`
2. Copy parser template from existing language
3. Implement AST conversion to common format
4. Add to setup scripts
5. Test with Port supervisor