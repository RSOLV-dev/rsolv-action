defmodule RsolvApi.Security.Patterns.Elixir.ExposedErrorDetails do
  @moduledoc """
  Exposed Error Details vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects error handling that exposes sensitive information through 
  detailed error messages, stack traces, or internal system details in HTTP 
  responses, enabling information disclosure attacks.

  ## Vulnerability Details

  Exposed error details occur when applications include sensitive information 
  in error messages returned to clients:
  - Database error messages revealing connection details or query structures
  - Stack traces exposing internal file paths and system architecture  
  - Exception details showing configuration values or sensitive data
  - Debug information leaking in production error responses

  ## Technical Impact

  Security risks through information disclosure:
  - System fingerprinting via detailed error messages and stack traces
  - Path traversal attack vectors revealed through file path exposure
  - Database schema inference from SQL error messages  
  - Configuration discovery through debug output and exception details

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Database error exposed to client
  send_resp(conn, 500, "Database error: \#{error.message}")
  
  # VULNERABLE - Stack trace information in response
  json(conn, %{error: "Failed: \#{inspect(exception)}"})
  
  # VULNERABLE - Internal details in error message
  text(conn, "Processing error: \#{changeset.errors}")
  
  # VULNERABLE - Detailed exception information
  render(conn, "error.html", message: "Error: \#{error}")
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Generic error message with logging
  Logger.error("Database error: \#{inspect(error)}")
  send_resp(conn, 500, "Internal server error")
  
  # SAFE - User-friendly error without details
  json(conn, %{error: "Something went wrong, please try again"})
  
  # SAFE - Structured error handling
  case result do
    {:error, _reason} -> 
      Logger.error("Processing failed: \#{inspect(reason)}")
      text(conn, "Unable to process request")
    {:ok, data} -> 
      json(conn, data)
  end
  ```

  ## Attack Scenarios

  1. **System Fingerprinting**: Attacker triggers errors to gather information 
     about database versions, file paths, and system configuration

  2. **Path Traversal Reconnaissance**: Error messages revealing file paths 
     enable attackers to map system structure for further attacks

  3. **SQL Injection Intelligence**: Database error details help attackers 
     refine injection payloads and understand schema structure

  ## References

  - CWE-209: Generation of Error Message Containing Sensitive Information
  - OWASP Top 10 2021 - A05: Security Misconfiguration
  - Phoenix Error Handling Best Practices
  - Elixir Logging and Error Management Guidelines
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-exposed-error-details",
      name: "Exposed Error Details",
      description: "Error responses containing sensitive system information enable information disclosure attacks",
      type: :information_disclosure,
      severity: :low,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # send_resp with error interpolation - exclude comments
        ~r/^(?!\s*#).*send_resp\s*\(\s*[^,]+\s*,\s*[45]\d\d\s*,\s*[^,)]*#\{[^}]*(?:error|exception|inspect|message)/m,
        
        # put_resp with error interpolation - exclude comments
        ~r/^(?!\s*#).*put_resp\s*\(\s*[^,]+\s*,\s*[45]\d\d\s*,\s*[^,)]*#\{[^}]*(?:error|exception|inspect|message)/m,
        
        # Phoenix.Controller.json/text with error interpolation - exclude comments
        ~r/^(?!\s*#).*Phoenix\.Controller\.(?:json|text)\s*\(\s*[^,]+\s*,\s*[^,)]*#\{[^}]*(?:error|exception|inspect)/m,
        
        # json/text functions with error interpolation - exclude comments  
        ~r/^(?!\s*#).*(?:json|text)\s*\(\s*[^,]+\s*,\s*[^,)]*#\{[^}]*(?:error|exception|inspect|message)/m,
        
        # render with error interpolation - exclude comments
        ~r/^(?!\s*#).*render\s*\([^)]*(?:message|error)[^)]*#\{[^}]*(?:error|exception|inspect)/m,
        
        # Pipeline syntax with error responses - exclude comments
        ~r/^(?!\s*#).*\|>\s*(?:json|text|put_resp|send_resp)\s*\([^)]*#\{[^}]*(?:error|exception|inspect)/m
      ],
      cwe_id: "CWE-209",
      owasp_category: "A05:2021",
      recommendation: "Use generic error messages for client responses and log detailed errors server-side only",
      test_cases: %{
        vulnerable: [
          ~S|send_resp(conn, 500, "Database error: #{error.message}")|,
          ~S|json(conn, %{error: "Failed: #{inspect(exception)}"})|,
          ~S|text(conn, "Processing error: #{changeset.errors}")|,
          ~S|render(conn, "error.html", message: "Error: #{error}")|
        ],
        safe: [
          ~S|send_resp(conn, 500, "Internal server error")|,
          ~S|json(conn, %{error: "Something went wrong"})|,
          ~S"""
          Logger.error("Database error: #{inspect(error)}")
          send_resp(conn, 500, "Internal server error")
          """,
          ~S|text(conn, "Please try again later")|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. System fingerprinting by triggering detailed error messages to gather database versions, file paths, and configuration information
      2. Path traversal reconnaissance using error messages that expose internal file system structure and directory paths
      3. SQL injection intelligence gathering from database error details helping attackers understand schema and refine payloads
      4. Information disclosure through stack traces revealing application architecture, dependency versions, and internal code structure
      5. Configuration discovery via debug output and exception details exposing sensitive environment variables and system settings
      """,
      business_impact: """
      Low: Error message information disclosure can result in:
      - Security intelligence gathering enabling more sophisticated targeted attacks
      - Competitive disadvantage through technology stack and architecture disclosure
      - Compliance violations related to information security and data protection requirements
      - Reputation damage from security incidents involving information leakage
      - Operational risk through system reconnaissance enabling future attack vectors
      """,
      technical_impact: """
      Low: Error information disclosure enables:
      - System fingerprinting revealing technology stack, versions, and configuration details
      - Path traversal attack preparation through file system structure disclosure
      - SQL injection attack refinement using database error message intelligence
      - Attack surface mapping via internal system architecture exposure
      - Social engineering attacks using leaked organizational and technical information
      """,
      likelihood: "Medium: Common oversight in development where error handling prioritizes debugging over security",
      cve_examples: [
        "CWE-209: Generation of Error Message Containing Sensitive Information",
        "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "CVE-2021-44228: Log4Shell information disclosure via error messages",
        "OWASP Top 10 A05:2021 - Security Misconfiguration"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "NIST Cybersecurity Framework - PR.DS: Data Security",
        "ISO 27001 - A.13.1: Network security management", 
        "PCI DSS - Requirement 2: Do not use vendor-supplied defaults for system passwords"
      ],
      remediation_steps: """
      1. Implement generic error messages for all client-facing responses
      2. Configure comprehensive server-side logging for detailed error information
      3. Use Phoenix error views to standardize error response formatting
      4. Implement error handling middleware to sanitize all outgoing error messages
      5. Configure production environment to suppress debug output and stack traces
      6. Review all error handling code to ensure no sensitive information exposure
      """,
      prevention_tips: """
      1. Always use generic error messages in production environments for client responses
      2. Log detailed error information server-side only using Logger with appropriate levels
      3. Configure Phoenix error views to return standardized user-friendly error messages
      4. Use pattern matching and case statements to handle specific errors appropriately
      5. Implement error handling middleware to catch and sanitize unexpected error responses
      6. Never include inspect/1, error.message, or exception details in client responses
      """,
      detection_methods: """
      1. Static code analysis scanning for error interpolation in response functions
      2. Dynamic testing with error triggering payloads to identify information leakage
      3. Code reviews focusing on error handling patterns and response generation
      4. Security scanning tools checking for verbose error message configurations
      5. Penetration testing with deliberate error conditions to assess information disclosure
      """,
      safe_alternatives: """
      1. Generic error responses: send_resp(conn, 500, "Internal server error")
      2. Structured error logging: Logger.error("Database error: \#{inspect(error)}")
      3. Phoenix error views with standardized user-friendly messages
      4. Error handling middleware for consistent error response sanitization
      5. Environment-based error detail control for development vs production
      6. Centralized error handling with appropriate logging and generic client messages
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      context_rules: %{
        response_functions: [
          "send_resp", "put_resp", "json", "text", "render",
          "Phoenix.Controller.json", "Phoenix.Controller.text",
          "Phoenix.Controller.render"
        ],
        error_interpolation_patterns: [
          "error.message", "error", "exception", "inspect(error)",
          "inspect(exception)", "changeset.errors", "exception.message"
        ],
        http_error_codes: [
          "400", "401", "403", "404", "422", "500", "502", "503"
        ],
        safe_error_messages: [
          "Internal server error", "Something went wrong", "Please try again",
          "An error occurred", "Unable to process", "Service unavailable"
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          error_interpolation_bonus: 0.3,
          http_error_code_bonus: 0.2,
          generic_message_penalty: -0.8,
          logging_only_penalty: -0.9,
          development_context_penalty: -0.3,
          comment_penalty: -1.0
        }
      },
      ast_rules: %{
        node_type: "error_disclosure_analysis",
        error_context_analysis: %{
          check_response_functions: true,
          response_functions: ["send_resp", "put_resp", "json", "text", "render"],
          check_error_interpolation: true,
          detect_http_error_codes: true
        },
        message_content_analysis: %{
          check_interpolation_patterns: true,
          error_indicators: ["error", "exception", "inspect", "message"],
          check_generic_messages: true,
          safe_message_patterns: ["Internal", "Something went wrong", "Please try"]
        },
        context_analysis: %{
          distinguish_logging_vs_response: true,
          check_environment_context: true,
          development_indicators: ["dev", "test", "debug"],
          context_radius: 3
        }
      }
    }
  end
end
