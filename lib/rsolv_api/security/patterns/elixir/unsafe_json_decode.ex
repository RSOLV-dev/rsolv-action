defmodule RsolvApi.Security.Patterns.Elixir.UnsafeJsonDecode do
  @moduledoc """
  Unsafe JSON Decoding vulnerability pattern for Elixir applications.

  This pattern detects the use of decode! functions that can crash the process
  when receiving malformed JSON input, potentially leading to denial of service attacks.

  ## Vulnerability Details

  Unsafe JSON decoding occurs when applications use decode! functions that raise 
  exceptions on invalid input instead of returning error tuples:
  - `Jason.decode!` raises on invalid JSON instead of returning `{:error, reason}`
  - `Poison.decode!` raises on parsing errors
  - `JSON.decode!` (from other libraries) with similar behavior
  - Process crashes when malformed JSON is processed from user input

  ## Technical Impact

  Security risks through:
  - Denial of service attacks by sending malformed JSON to crash processes
  - Service instability and potential cascade failures in distributed systems
  - Resource exhaustion through repeated process crashes and restarts
  - Availability issues affecting legitimate users and business operations

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Jason.decode! can crash on invalid JSON
  def handle_request(conn, %{"data" => json_string}) do
    parsed_data = Jason.decode!(json_string)  # Crashes on invalid JSON
    process_data(parsed_data)
  end
  
  # VULNERABLE - Poison.decode! with user input
  def parse_user_input(user_input) do
    result = Poison.decode!(user_input)  # Process crash on malformed JSON
    {:ok, result}
  end
  
  # VULNERABLE - decode! in pipelines
  def process_request(params) do
    params["json"]
    |> Jason.decode!()  # Can crash entire pipeline
    |> validate_data()
  end
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Using Jason.decode with pattern matching
  def handle_request(conn, %{"data" => json_string}) do
    case Jason.decode(json_string) do
      {:ok, parsed_data} -> 
        process_data(parsed_data)
      {:error, _reason} -> 
        {:error, "Invalid JSON format"}
    end
  end
  
  # SAFE - Using with statement for error handling
  def parse_user_input(user_input) do
    with {:ok, parsed} <- Jason.decode(user_input) do
      {:ok, parsed}
    else
      {:error, reason} -> {:error, "JSON parsing failed"}
    end
  end
  
  # SAFE - Graceful error handling in pipelines
  def process_request(params) do
    case Jason.decode(params["json"]) do
      {:ok, data} -> validate_data(data)
      {:error, _} -> {:error, :invalid_json}
    end
  end
  ```

  ## Attack Scenarios

  1. **DoS via Malformed JSON**: Attackers send malformed JSON payloads to endpoints
     that use decode! functions, causing process crashes and service disruption

  2. **Resource Exhaustion**: Repeated crashes can overwhelm supervisor trees and
     consume system resources through constant process restarts

  3. **Cascade Failures**: Critical processes crashing can trigger failures in
     dependent services and create system-wide availability issues

  ## References

  - CWE-20: Improper Input Validation  
  - OWASP Top 10 2021 - A05: Security Misconfiguration
  - Jason documentation: https://hexdocs.pm/jason/
  - Elixir error handling best practices
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-unsafe-json-decode",
      name: "Unsafe JSON Decoding",
      description: "decode! functions can crash the process on invalid JSON input, leading to denial of service",
      type: :dos,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # decode! with common user input patterns (params, conn, request, etc)
        ~r/(?:Jason|Poison|JSON)\.decode!\s*\(\s*(?:params|conn\.|request|socket\.|args|query|body|external_|user_|untrusted_)[^)]+\)/,
        
        # decode! with array/map access (potential user input)
        ~r/(?:Jason|Poison|JSON)\.decode!\s*\(\s*\w+\[[^\]]+\]\s*\)/,
        
        # decode! functions in pipelines with user input indicators
        ~r/(?:user_|params|conn\.|request|input|external|untrusted)[^|]*\|\>\s*\w*\.decode!\s*\(\)/,
        
        # decode! with specific variable names suggesting user input
        ~r/(?:Jason|Poison|JSON)\.decode!\s*\(\s*(?:user_input|external_json|request_body|payload|raw_data|raw_json|json_string|data|input)\s*\)/
      ],
      cwe_id: "CWE-20",
      owasp_category: "A05:2021",
      recommendation: "Use Jason.decode/1 with proper error handling instead of Jason.decode!/1 to prevent process crashes",
      test_cases: %{
        vulnerable: [
          ~S|Jason.decode!(user_input)|,
          ~S|Poison.decode!(params["data"])|,
          ~S|result = Jason.decode!(external_json)|,
          "user_input |> Jason.decode!()"
        ],
        safe: [
          ~S|case Jason.decode(user_input) do|,
          ~S|Jason.decode!(static_json)|,
          ~S|{:ok, data} = Jason.decode(params["json"])|,
          ~S|with {:ok, json} <- Jason.decode(data) do|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. DoS attacks via malformed JSON payloads sent to endpoints using decode! functions
      2. Resource exhaustion through repeated process crashes and supervisor restarts
      3. Service disruption by targeting critical processes that handle JSON parsing
      4. Cascade failures in distributed systems dependent on crashed processes
      """,
      business_impact: """
      Medium: Unsafe JSON decoding can result in:
      - Service availability issues affecting customer experience and revenue
      - Increased infrastructure costs from resource consumption during attacks  
      - Potential SLA violations and customer dissatisfaction
      - Reduced system reliability and operational stability
      - Support overhead from investigating and resolving crash incidents
      """,
      technical_impact: """
      Medium: Process crashes enable:
      - Denial of service through malformed JSON input
      - System instability from repeated process failures and restarts
      - Resource exhaustion in supervisor trees and process pools
      - Availability degradation for legitimate users and requests
      - Potential memory leaks from incomplete request processing
      """,
      likelihood: "Medium: Common pattern when developers prioritize convenience over error handling",
      cve_examples: [
        "CWE-20: Improper Input Validation",
        "CWE-754: Improper Check for Unusual or Exceptional Conditions", 
        "CVE-2023-5072: DoS vulnerability in JSON-Java through malformed input",
        "OWASP Top 10 A05:2021 - Security Misconfiguration"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "NIST Cybersecurity Framework - DE.CM: Security Continuous Monitoring",
        "ISO 27001 - A.12.6: Management of technical vulnerabilities",
        "PCI DSS - Requirement 6: Develop and maintain secure systems"
      ],
      remediation_steps: """
      1. Replace decode! functions with decode and proper error handling
      2. Use pattern matching or with statements to handle parsing errors gracefully
      3. Validate JSON input before attempting to parse when possible
      4. Implement rate limiting on endpoints that accept JSON input
      5. Add monitoring and alerting for process crashes related to JSON parsing
      6. Consider using JSON schema validation for additional input protection
      """,
      prevention_tips: """
      1. Always use Jason.decode/1 instead of Jason.decode!/1 for untrusted input
      2. Implement comprehensive error handling for all JSON parsing operations
      3. Validate JSON structure and content before processing business logic
      4. Use defensive programming practices with proper error boundaries
      5. Monitor application logs for JSON parsing errors and trends
      6. Consider implementing request timeouts and size limits for JSON payloads
      """,
      detection_methods: """
      1. Static code analysis for decode! function usage with variable inputs
      2. Runtime monitoring for process crashes with JSON parsing stack traces
      3. Code reviews focusing on input validation and error handling patterns
      4. Integration testing with malformed JSON payloads
      5. Penetration testing targeting JSON endpoints with invalid data
      """,
      safe_alternatives: """
      1. Pattern matching: case Jason.decode(input) do
      2. With statements: with {:ok, json} <- Jason.decode(input) do
      3. Error handling: Jason.decode(input) |> handle_result()
      4. Guard clauses and validation before parsing
      5. Defensive parsing with timeouts and size limits
      6. JSON schema validation libraries for additional protection
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        exclude_comments: true,
        comment_patterns: [
          ~r/^\s*#/,
          ~r/@doc\s+[\"']/,
          ~r/@moduledoc\s+[\"']/
        ],
        input_sources: [
          "user_",
          "params",
          "conn.",
          "request",
          "input",
          "external",
          "untrusted",
          "body",
          "payload",
          "data"
        ],
        trusted_sources: [
          "static",
          "config",
          "Application.get_env",
          "System.get_env", 
          "File.read!",
          "@",
          "\"",
          "'"
        ],
        unsafe_functions: [
          "Jason.decode!",
          "Poison.decode!",
          "JSON.decode!"
        ],
        safe_functions: [
          "Jason.decode",
          "Poison.decode", 
          "JSON.decode"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          trusted_source_penalty: -0.6,
          static_string_penalty: -0.8,
          comment_penalty: -1.0,
          user_input_bonus: 0.2,
          pipeline_bonus: 0.1,
          assignment_bonus: 0.1
        }
      },
      ast_rules: %{
        node_type: "json_decode_analysis",
        function_analysis: %{
          check_function_calls: true,
          unsafe_decode_functions: ["Jason.decode!", "Poison.decode!", "JSON.decode!"],
          safe_decode_functions: ["Jason.decode", "Poison.decode", "JSON.decode"],
          check_arguments: true
        },
        input_analysis: %{
          check_variable_sources: true,
          user_input_indicators: ["user_", "params", "conn.", "request", "input", "external"],
          trusted_input_indicators: ["static", "config", "Application.", "System.", "File.", "@"],
          check_string_literals: true,
          check_pipeline_context: true
        },
        context_analysis: %{
          check_error_handling: true,
          safe_error_patterns: ["case", "with", "try", "rescue"],
          check_surrounding_code: true,
          error_handling_radius: 3
        }
      }
    }
  end
end
