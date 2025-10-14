defmodule Rsolv.Security.Patterns.JavaScript.LogInjection do
  @moduledoc """
  Pattern for detecting log injection vulnerabilities in JavaScript/Node.js code.

  Log injection occurs when user input is logged without proper sanitization,
  potentially allowing attackers to forge log entries or inject malicious content.

  CWE-117: Improper Output Neutralization for Logs
  OWASP: A09:2021 - Security Logging and Monitoring Failures
  """

  use Rsolv.Security.Patterns.PatternBase

  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    meta = metadata()
    %Pattern{
      id: meta.id,
      name: meta.name,
      description: meta.description,
      type: String.to_existing_atom(meta.type),
      severity: String.to_existing_atom(meta.severity),
      languages: meta.languages,
      regex: hd(regex_patterns()),  # Use first pattern as primary
      cwe_id: meta.cwe_id,
      owasp_category: meta.owasp_category,
      recommendation: recommendation(),
      test_cases: test_cases()
    }
  end

  def metadata do
    %{
      id: "javascript-log-injection",
      name: "Log Injection via User Input",
      type: "log_injection",
      severity: "medium",
      languages: ["javascript", "typescript"],
      cwe_id: "CWE-117",
      owasp_category: "A09:2021",
      description: "User input is logged without sanitization, potentially allowing log forging attacks"
    }
  end


  def regex_patterns do
    [
      # console.log/error/warn with concatenation or template literal containing req/request
      ~r/console\.(log|error|warn|info)\s*\([^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i,

      # logger methods with user input
      ~r/logger\.(info|error|warn|debug|trace)\s*\([^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i,

      # winston logging with user input
      ~r/winston\.(log|info|error|warn)\s*\([^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i,

      # process.stdout/stderr.write with user input
      ~r/process\.(stdout|stderr)\.write\s*\([^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i,

      # fs.appendFile for logging with user input
      ~r/fs\.(appendFile|appendFileSync)\s*\([^,]*log[^,]*,[^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i
    ]
  end


  def test_cases do
    %{
      vulnerable: [
        ~S|console.log("User logged in: " + req.query.username);|,
        ~S|logger.info(`Failed login attempt from: ${request.body.email}`);|,
        ~S|winston.log('info', 'User action: ' + req.params.action);|,
        ~S|process.stdout.write("Request from: " + req.headers['user-agent'] + "\n");|,
        ~S|fs.appendFile('access.log', 'User: ' + req.body.user + '\n', callback);|
      ],
      safe: [
        ~S|console.log("Application started successfully");|,
        ~S|logger.info("Server listening on port 3000");|,
        ~S|console.log("User:", JSON.stringify(req.query.username));|,
        ~S|logger.info(`User: ${sanitizeForLog(req.body.username)}`);|,
        ~S|winston.log('info', 'User action', { action: req.params.action });|
      ]
    }
  end


  def recommendation do
    """
    Sanitize all user input before including it in log messages:

    1. Remove or encode newline characters (\\r, \\n)
    2. Remove or encode control characters
    3. Use structured logging with separate fields for user data
    4. Consider using JSON.stringify() for complex data
    5. Implement a sanitization function for log output

    Example safe logging:
    ```javascript
    // Instead of:
    console.log("User: " + req.query.username);

    // Use:
    console.log("User:", sanitizeForLog(req.query.username));
    // Or use structured logging:
    logger.info("User login", { username: req.query.username });
    ```
    """
  end


  def ast_rules do
    %{
      javascript: %{
        call_expression: %{
          callee: %{
            member_expression: %{
              object: ["console", "logger", "winston", "process.stdout", "process.stderr"],
              property: ["log", "error", "warn", "info", "debug", "trace", "write"]
            }
          },
          arguments: %{
            contains_user_input: true,
            concatenation_or_template: true
          }
        }
      }
    }
  end


  def context_rules do
    %{
      exclude_paths: [
        "**/test/**",
        "**/tests/**",
        "**/spec/**",
        "**/__tests__/**"
      ],
      safe_if_wrapped: [
        "sanitizeForLog",
        "escapeLogMessage",
        "JSON.stringify",
        "encodeURIComponent"
      ]
    }
  end

  @impl true
  def ast_enhancement do
    %{
      ast_rules: ast_rules(),
      context_rules: context_rules(),
      min_confidence: 0.6
    }
  end
end