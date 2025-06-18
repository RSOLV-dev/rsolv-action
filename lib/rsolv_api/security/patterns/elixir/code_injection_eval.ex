defmodule RsolvApi.Security.Patterns.Elixir.CodeInjectionEval do
  @moduledoc """
  Detects code injection vulnerabilities via eval functions in Elixir.
  
  This pattern identifies the use of dangerous evaluation functions like Code.eval_string/1,
  Code.eval_file/1, Code.eval_quoted/1, and EEx eval functions that can execute arbitrary
  code when given untrusted input.
  
  ## Vulnerability Details
  
  Dynamic code evaluation is one of the most dangerous operations in any programming language.
  In Elixir, functions that evaluate strings or files as code can lead to complete system
  compromise if user input reaches them. An attacker can execute any Elixir code, including
  system commands, file operations, or network requests.
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  # Controller accepting user code
  def execute(conn, %{"code" => code}) do
    {result, _} = Code.eval_string(code)  # CRITICAL VULNERABILITY!
    json(conn, %{result: result})
  end
  ```
  
  An attacker could send: `System.cmd("rm", ["-rf", "/"])` or steal secrets.
  
  ### Safe Alternative
  
  Safe code:
  ```elixir
  # Use pattern matching for specific commands
  def execute(conn, %{"command" => command}) do
    result = case command do
      "status" -> get_status()
      "metrics" -> get_metrics()
      _ -> {:error, "Unknown command"}
    end
    json(conn, result)
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-code-injection-eval",
      name: "Code Injection via eval",
      description: "Evaluating user input as code can lead to remote code execution",
      type: :code_injection,
      severity: :critical,
      languages: ["elixir"],
      regex: [
        # Code.eval_string usage
        ~r/Code\.eval_string\s*\(/,
        # Code.eval_file usage
        ~r/Code\.eval_file\s*\(/,
        # Code.eval_quoted usage
        ~r/Code\.eval_quoted\s*\(/,
        # Code.eval_quoted_with_env usage
        ~r/Code\.eval_quoted_with_env\s*\(/,
        # EEx.eval_string usage
        ~r/EEx\.eval_string\s*\(/,
        # EEx.eval_file usage
        ~r/EEx\.eval_file\s*\(/,
        # Pipe to eval functions
        ~r/\|>\s*Code\.eval_/,
        ~r/\|>\s*EEx\.eval_/,
        # Variable assignment from eval
        ~r/=\s*Code\.eval_(?:string|file|quoted)/,
        # Eval in function calls
        ~r/apply\s*\(\s*Code\s*,\s*:eval_/
      ],
      default_tier: :ai,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Never evaluate user input as code. Use pattern matching or predefined commands instead",
      test_cases: %{
        vulnerable: [
          ~S|Code.eval_string(params["code"])|,
          ~S|Code.eval_string(user_input)|,
          ~S|Code.eval_file(file_path)|,
          ~S|Code.eval_file("scripts/#{script_name}.exs")|,
          ~S|Code.eval_quoted(ast)|,
          ~S|{result, _} = Code.eval_quoted(user_ast)|,
          ~S|EEx.eval_string(template, assigns)|,
          ~S|EEx.eval_file(template_path)|,
          "user_code |> Code.eval_string()"
        ],
        safe: [
          ~S|case command do
  "start" -> start_process()
  "stop" -> stop_process()
  _ -> {:error, :unknown_command}
end|,
          ~S|apply(Module, :function, args)|,
          ~S|quote do
  def unquote(name)(), do: unquote(value)
end|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Code injection via eval functions in Elixir is a critical security vulnerability that
      occurs when user-controlled input is passed to functions like Code.eval_string/1,
      Code.eval_file/1, or Code.eval_quoted/1. These functions execute arbitrary Elixir code,
      giving attackers complete control over the application and potentially the underlying
      system. The BEAM VM's powerful metaprogramming capabilities make this especially
      dangerous, as evaluated code has access to all modules, processes, and system functions.
      Unlike sandboxed environments, there are no restrictions on what evaluated code can do.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-94",
          title: "Improper Control of Generation of Code ('Code Injection')",
          url: "https://cwe.mitre.org/data/definitions/94.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "erlef_secure_coding",
          title: "ErlEF Security WG - Secure Coding Guidelines",
          url: "https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/"
        },
        %{
          type: :research,
          id: "guardrails_eval",
          title: "GuardRails - Insecure Use of Dangerous Function",
          url: "https://docs.guardrails.io/docs/vulnerabilities/elixir/insecure_use_of_dangerous_function"
        }
      ],
      attack_vectors: [
        "Direct code execution: Attacker sends malicious Elixir code as input",
        "System command execution: System.cmd() or :os.cmd() to run shell commands",
        "File system access: File.read!/write! to steal or modify files",
        "Network requests: HTTPoison/Req to exfiltrate data or attack internal services",
        "Process manipulation: Process.exit() or spawn malicious processes",
        "Module redefinition: Redefine critical modules at runtime",
        "Environment variable theft: System.get_env() to steal secrets"
      ],
      real_world_impact: [
        "Complete system compromise with application privileges",
        "Data theft including database credentials and API keys",
        "Cryptocurrency mining using server resources",
        "Backdoor installation for persistent access",
        "Lateral movement to internal network services",
        "Denial of service by killing processes or exhausting resources",
        "Supply chain attacks by modifying application behavior"
      ],
      cve_examples: [
        %{
          id: "CVE-2017-1000053",
          description: "Elixir Plug deserialization RCE via code evaluation",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates how eval-like functionality in deserialization leads to RCE"
        }
      ],
      detection_notes: """
      This pattern detects various forms of code evaluation:
      - Direct Code.eval_* function calls
      - EEx template evaluation functions
      - Piped operations to eval functions
      - Variable assignments from eval results
      - Dynamic function application of eval functions
      """,
      safe_alternatives: [
        "Use pattern matching with predefined commands instead of eval",
        "Implement a DSL with limited, safe operations",
        "Use compile-time code generation with macros, not runtime eval",
        "For templates, use pre-compiled EEx templates, not eval_string",
        "Use function references and apply/3 for dynamic function calls",
        "Implement a parser for safe expression evaluation if needed"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking input validation/sanitization makes eval safe (it doesn't)",
          "Using eval for simple dynamic operations that pattern matching could handle",
          "Evaluating configuration files instead of using proper config formats",
          "Not realizing EEx.eval_* is just as dangerous as Code.eval_*"
        ],
        secure_patterns: [
          "Pattern match on known commands/operations",
          "Use Application.get_env for configuration",
          "Pre-compile templates at build time",
          "Use proper parsers for data formats (JSON, YAML, etc.)"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing context and usage patterns.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.CodeInjectionEval.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.CodeInjectionEval.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        eval_analysis: %{
          check_eval_functions: true,
          dangerous_functions: ["Code.eval_string", "Code.eval_file", "Code.eval_quoted", 
                               "Code.eval_quoted_with_env", "EEx.eval_string", "EEx.eval_file"],
          check_input_source: true,
          check_template_usage: true
        },
        input_analysis: %{
          user_input_indicators: ["params", "conn", "socket", "args", "input", "request", "body", "query"],
          check_variable_flow: true,
          check_function_arguments: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/seeds\.exs$/],
        user_input_sources: ["params", "conn.params", "conn.body_params", "socket.assigns", 
                            "args", "input", "user_input", "request_data"],
        safe_contexts: ["compile", "macro", "__using__", "defmacro"],
        exclude_compile_time: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_user_input" => 0.4,
          "uses_compile_time_code" => -0.9,
          "in_test_code" => -1.0,
          "in_macro_context" => -0.8,
          "hardcoded_string" => -0.7
        }
      },
      min_confidence: 0.8
    }
  end
end