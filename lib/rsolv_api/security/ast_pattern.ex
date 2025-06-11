defmodule RsolvApi.Security.ASTPattern do
  @moduledoc """
  Simple AST-enhanced pattern format that dramatically reduces false positives.
  
  Instead of complex infrastructure, we just extend our Pattern struct
  with AST matching rules that the client interprets.
  """
  
  alias RsolvApi.Security.Pattern
  
  defstruct [
    # All existing Pattern fields
    :id, :name, :type, :severity, :description,
    :regex,  # Keep for pre-filtering - FAST!
    :languages, :frameworks,
    :cwe_id, :owasp_category,
    :recommendation,
    :default_tier,
    :test_cases,
    
    # New AST enhancement fields
    :ast_rules,        # AST node matching configuration
    :context_rules,    # Path exclusions, framework checks
    :confidence_rules, # Dynamic confidence scoring
    :min_confidence    # Threshold for reporting (default 0.7)
  ]
  
  @doc """
  Convert standard patterns to AST-enhanced patterns.
  This is where we fix the false positive problem!
  """
  def enhance(%Pattern{} = pattern) do
    pattern
    |> Map.from_struct()
    |> enhance_by_type()
    |> then(&struct(__MODULE__, &1))
  end
  
  # Fix SQL injection false positives (was matching console.log!)
  defp enhance_by_type(%{type: :sql_injection} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      # Must be inside a database call
      parent_node: %{
        type: "CallExpression",
        callee_matches: ~r/\.(query|execute|exec|run)/
      },
      # Must have SQL keywords
      contains_sql: true,
      # Must have user input
      has_user_input: true
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
      exclude_if_parameterized: true  # Big FP reducer!
    })
    |> Map.put(:confidence_rules, %{
      base: 0.7,
      adjustments: %{
        "direct_user_input" => 0.2,
        "has_validation" => -0.4,
        "uses_orm" => -0.5
      }
    })
    |> Map.put(:min_confidence, 0.7)
  end
  
  # Fix logging false positives (was matching 37/57 findings!)
  defp enhance_by_type(%{type: :logging} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      # Must be a function definition, not just any occurrence
      node_type: "FunctionDeclaration",
      # Must be security-critical function name
      name_matches: ~r/^(login|authenticate|authorize|payment|delete|reset)/,
      # Must NOT have logging in body
      body_excludes: ~r/\b(log|logger|audit|console\.log)\b/i
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/mock/, ~r/stub/],
      exclude_if_delegates: true,  # Don't flag wrapper functions
      require_modifies_data: true  # Only flag if actually does something
    })
    |> Map.put(:confidence_rules, %{
      base: 0.5,  # Start lower
      adjustments: %{
        "is_test_code" => -1.0,  # Never flag tests
        "has_error_handling" => 0.2,
        "modifies_database" => 0.3
      }
    })
    |> Map.put(:min_confidence, 0.75)  # Higher threshold
  end
  
  # Fix NoSQL injection false positives
  defp enhance_by_type(%{type: :nosql_injection} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      method_names: ["find", "findOne", "update", "delete"],
      # Check for dangerous operators
      argument_contains: %{
        dangerous_keys: ["$where", "$expr", "$function"],
        user_input_in_query: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/],
      safe_if_uses: ["mongoose.Schema", "sanitize", "validate"]
    })
    |> Map.put(:confidence_rules, %{
      base: 0.7,
      adjustments: %{
        "has_dangerous_operator" => 0.3,
        "direct_json_parse" => 0.2,
        "uses_schema" => -0.5
      }
    })
  end

  # PHP XSS Echo - Fix 100% false positives by checking for escaping
  defp enhance_by_type(%{id: "php-xss-echo"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "Echo",
      # Must check that user input is NOT properly escaped
      argument_analysis: %{
        contains_user_input: true,
        not_escaped_with: ["htmlspecialchars", "htmlentities", "esc_html"]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/vendor/],
      safe_if_wrapped: ["htmlspecialchars", "htmlentities", "esc_html", "e()"],
      safe_in_context: ["CLI", "email_template"]
    })
    |> Map.put(:confidence_rules, %{
      base: 0.3,  # Start low since echo is common
      adjustments: %{
        "direct_user_input" => 0.4,
        "no_escaping_function" => 0.3,
        "in_html_context" => 0.2,
        "has_escaping" => -0.8  # Big reduction if escaped
      }
    })
    |> Map.put(:min_confidence, 0.8)  # High threshold
  end

  # PHP XSS Print - Similar to echo
  defp enhance_by_type(%{id: "php-xss-print"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "Print",
      argument_analysis: %{
        contains_user_input: true,
        not_escaped_with: ["htmlspecialchars", "htmlentities", "esc_html"]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/vendor/],
      safe_if_wrapped: ["htmlspecialchars", "htmlentities", "esc_html", "e()"],
      safe_in_context: ["CLI", "email_template"]
    })
    |> Map.put(:confidence_rules, %{
      base: 0.3,
      adjustments: %{
        "direct_user_input" => 0.4,
        "no_escaping_function" => 0.3,
        "in_html_context" => 0.2,
        "has_escaping" => -0.8
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Django CVE-2021-33571 - IPv4 validation bypass
  defp enhance_by_type(%{id: "django-cve-2021-33571"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "FieldUsage",
      field_type: "IPv4AddressField",
      # Only vulnerable in specific Django versions
      django_version_check: %{
        vulnerable_ranges: [
          ">=2.2,<2.2.24",
          ">=3.0,<3.1.12", 
          ">=3.2,<3.2.4"
        ]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/migrations/],
      require_django_project: true,
      check_requirements: true  # Look at requirements.txt for version
    })
    |> Map.put(:confidence_rules, %{
      base: 0.1,  # Very low unless version matches
      adjustments: %{
        "vulnerable_django_version" => 0.8,
        "has_validation" => -0.3,
        "in_migration" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Django Missing Security Middleware
  defp enhance_by_type(%{id: "django-missing-security-middleware"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "SettingsVariable",
      variable_name: "MIDDLEWARE",
      # Check that SecurityMiddleware is NOT present
      array_analysis: %{
        missing_values: [
          "django.middleware.security.SecurityMiddleware",
          "SecurityMiddleware"
        ]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/local/, ~r/dev/],
      only_in_files: ["settings.py", "base.py", "production.py"],
      production_only: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.2,
      adjustments: %{
        "is_production_settings" => 0.6,
        "missing_security_middleware" => 0.2,
        "is_test_settings" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.7)
  end

  # Ruby Insecure Cookie Settings
  defp enhance_by_type(%{id: "ruby-insecure-cookie"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "HashLiteral",
      context: "cookie_setting",
      # Check for insecure values
      hash_analysis: %{
        has_insecure_flags: %{
          "secure" => false,
          "httponly" => false,
          "samesite" => ["none", nil]
        }
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/development/],
      only_in_methods: ["set_cookie", "cookies", "session"],
      production_context_only: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.3,
      adjustments: %{
        "secure_false" => 0.3,
        "httponly_false" => 0.2,
        "samesite_none" => 0.2,
        "in_development" => -0.8
      }
    })
    |> Map.put(:min_confidence, 0.7)
  end

  # Rails Insecure Session Config
  defp enhance_by_type(%{id: "rails-insecure-session-config"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "ConfigBlock",
      config_path: "session_store",
      # Check for insecure session settings
      options_analysis: %{
        has_insecure_options: %{
          "secure" => false,
          "httponly" => false,
          "expire_after" => nil,
          "key" => ["_session", "session_id"]  # Default/weak keys
        }
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/development/],
      only_in_files: ["application.rb", "production.rb", "session_store.rb"],
      production_only: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.2,
      adjustments: %{
        "secure_false" => 0.4,
        "no_expiration" => 0.2,
        "weak_key" => 0.2,
        "in_test_env" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # PHP Missing CSRF Token
  defp enhance_by_type(%{id: "php-missing-csrf-token"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "FormTag",
      method: "POST",
      # Check that CSRF token is NOT present
      form_analysis: %{
        missing_csrf_elements: [
          "csrf_token()",
          "_token",
          "wp_nonce_field",
          "csrf_field()"
        ]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/vendor/, ~r/public/],
      only_post_forms: true,
      exclude_ajax_forms: true,  # Different CSRF handling
      exclude_if_has_custom_protection: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.2,
      adjustments: %{
        "is_post_form" => 0.3,
        "no_csrf_token" => 0.3,
        "modifies_data" => 0.2,
        "has_custom_protection" => -0.7
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Missing Security Event Logging
  defp enhance_by_type(%{id: "missing-security-event-logging"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "FunctionDeclaration",
      function_patterns: [
        ~r/login|authenticate|authorize/,
        ~r/payment|transaction|transfer/,
        ~r/delete|remove|destroy/,
        ~r/admin|elevated|privilege/
      ],
      # Check that logging is NOT present in function body
      body_analysis: %{
        missing_logging_calls: [
          "log", "logger", "audit", "track",
          "console.log", "error_log", "syslog"
        ]
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/mock/],
      exclude_if_delegates: true,  # Wrapper functions are OK
      only_security_critical: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.1,  # Very low base
      adjustments: %{
        "is_auth_function" => 0.3,
        "modifies_sensitive_data" => 0.3,
        "no_logging_found" => 0.3,
        "is_wrapper_function" => -0.8
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # PHP Register Globals Dependency
  defp enhance_by_type(%{id: "php-register-globals"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "VariableUsage",
      # Look for patterns that indicate register_globals dependency
      usage_analysis: %{
        uses_request_directly: true,
        no_input_validation: true,
        # Check for direct variable usage that would come from register_globals
        has_global_variable_assumption: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/vendor/],
      check_php_version: ">= 5.4",  # register_globals removed in 5.4
      only_if_no_input_sanitization: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.1,  # Very low unless clear dependency
      adjustments: %{
        "direct_request_usage" => 0.3,
        "no_validation" => 0.3,
        "old_php_patterns" => 0.3,
        "modern_php_version" => -0.8  # Almost certainly FP on modern PHP
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # JavaScript Command Injection (exec/execSync)
  defp enhance_by_type(%{id: "js-command-injection-exec"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      callee_names: ["exec", "execSync"],
      # Must have string concatenation or template literals with variables
      argument_analysis: %{
        has_string_concatenation: true,
        has_template_literal_with_variables: true,
        not_using_array_arguments: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/node_modules/, ~r/scripts/],
      exclude_if_static_command: true,  # Skip if no dynamic content
      require_user_input_source: true   # Must trace back to user input
    })
    |> Map.put(:confidence_rules, %{
      base: 0.4,
      adjustments: %{
        "has_user_input" => 0.3,
        "uses_string_concatenation" => 0.2,
        "no_input_validation" => 0.2,
        "is_static_command" => -0.9,
        "uses_array_args" => -0.7  # Safe pattern
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # JavaScript Command Injection (spawn with shell)
  defp enhance_by_type(%{id: "js-command-injection-spawn"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      callee_names: ["spawn", "spawnSync"],
      # Must have shell:true option AND user input in command
      option_analysis: %{
        has_shell_true: true,
        command_has_user_input: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/node_modules/, ~r/scripts/],
      safe_if_no_shell: true,           # spawn without shell is safer
      safe_if_array_command: true       # spawn(['cmd', 'arg1', 'arg2']) is safer
    })
    |> Map.put(:confidence_rules, %{
      base: 0.3,
      adjustments: %{
        "has_shell_true" => 0.4,
        "command_has_user_input" => 0.3,
        "no_shell_option" => -0.8,
        "uses_array_command" => -0.5
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Python Command Injection (os.system)
  defp enhance_by_type(%{id: "python-command-injection-os-system"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      module_function: "os.system",
      # Must have string concatenation or f-strings with variables
      argument_analysis: %{
        has_string_concatenation: true,
        has_fstring_with_variables: true,
        not_using_shlex_quote: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/tests/, ~r/__pycache__/, ~r/venv/, ~r/\.env/],
      safe_if_uses_shlex: true,         # shlex.quote() makes it safer
      require_user_input_trace: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.5,
      adjustments: %{
        "has_user_input" => 0.3,
        "uses_string_concat" => 0.2,
        "uses_fstring" => 0.2,
        "uses_shlex_quote" => -0.8,
        "is_static_command" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Python Command Injection (subprocess with shell=True)
  defp enhance_by_type(%{id: "python-command-injection-subprocess-shell"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      module_function: ["subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.Popen"],
      # Must have shell=True AND string command (not array)
      keyword_analysis: %{
        has_shell_true: true,
        command_is_string: true,
        command_has_user_input: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/tests/, ~r/__pycache__/, ~r/venv/],
      safe_if_array_command: true,      # subprocess.run(['cmd', 'arg']) is safe
      safe_if_no_shell: true            # shell=False is safer
    })
    |> Map.put(:confidence_rules, %{
      base: 0.4,
      adjustments: %{
        "has_shell_true" => 0.3,
        "command_is_string" => 0.2,
        "has_user_input" => 0.3,
        "uses_array_command" => -0.8,
        "shell_false" => -0.7
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Java Command Injection (Runtime.exec)
  defp enhance_by_type(%{id: "java-command-injection-runtime-exec"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "MethodCallExpression",
      method_chain: ["Runtime", "getRuntime", "exec"],
      # Must have string concatenation in argument
      argument_analysis: %{
        has_string_concatenation: true,
        not_using_array_overload: true,
        contains_user_input: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/src\/test/, ~r/target/],
      safe_if_array_args: true,         # exec(String[]) is safer than exec(String)
      require_user_input_source: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.5,
      adjustments: %{
        "uses_string_concat" => 0.3,
        "has_user_input" => 0.3,
        "uses_array_overload" => -0.8,
        "is_static_command" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Java Command Injection (ProcessBuilder)
  defp enhance_by_type(%{id: "java-command-injection-processbuilder"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "MethodCallExpression",
      class_name: "ProcessBuilder",
      method_name: "command",
      # Check for string concatenation in command setup
      argument_analysis: %{
        has_string_concatenation: true,
        not_using_string_array: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/src\/test/, ~r/target/],
      safe_if_string_array: true,       # command(String...) is safer
      exclude_if_static_only: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.4,
      adjustments: %{
        "uses_string_concat" => 0.3,
        "has_user_input" => 0.3,
        "uses_string_array" => -0.7,
        "is_static_command" => -0.8
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Ruby Command Injection (system/backticks)
  defp enhance_by_type(%{id: "ruby-command-injection"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "CallExpression",
      method_names: ["system", "`"],
      # Must have string interpolation with variables
      argument_analysis: %{
        has_string_interpolation: true,
        interpolates_user_input: true,
        not_using_array_form: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/vendor/],
      safe_if_array_args: true,         # system('cmd', 'arg1', 'arg2') is safer
      require_user_input_trace: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.5,
      adjustments: %{
        "has_string_interpolation" => 0.3,
        "interpolates_user_input" => 0.3,
        "uses_array_form" => -0.8,
        "is_static_command" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # PHP Command Injection (system/exec/shell_exec/passthru)
  defp enhance_by_type(%{id: "php-command-injection"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "FunctionCall",
      function_names: ["system", "exec", "shell_exec", "passthru"],
      # Must have superglobal variables or user input
      argument_analysis: %{
        contains_superglobals: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
        has_string_concatenation: true,
        not_using_escapeshellarg: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/vendor/, ~r/wp-admin/],
      safe_if_uses_escapeshellarg: true,
      safe_if_uses_escapeshellcmd: true,
      require_superglobal_usage: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.6,  # Higher base since PHP superglobals are clearly user input
      adjustments: %{
        "uses_superglobals" => 0.3,
        "has_string_concat" => 0.2,
        "uses_escapeshellarg" => -0.8,
        "uses_escapeshellcmd" => -0.6
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end

  # Elixir Command Injection (System.shell/:os.cmd)
  defp enhance_by_type(%{id: "elixir-command-injection-system"} = pattern) do
    pattern
    |> Map.put(:ast_rules, %{
      node_type: "FunctionCall",
      module_functions: ["System.shell", ":os.cmd"],
      # Must have string interpolation with variables
      argument_analysis: %{
        has_string_interpolation: true,
        interpolation_contains_variables: true,
        not_using_safe_shell_split: true
      }
    })
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/mix\/tasks/, ~r/priv\/scripts/],
      safe_if_uses_shell_split: true,   # Using proper argument parsing
      exclude_if_static_only: true
    })
    |> Map.put(:confidence_rules, %{
      base: 0.4,
      adjustments: %{
        "has_string_interpolation" => 0.3,
        "interpolates_user_input" => 0.3,
        "uses_shell_split" => -0.7,
        "is_static_command" => -0.9
      }
    })
    |> Map.put(:min_confidence, 0.8)
  end
  
  # Default enhancement for other patterns
  defp enhance_by_type(pattern) do
    pattern
    |> Map.put(:ast_rules, nil)  # Explicitly set to nil for patterns without AST rules yet
    |> Map.put(:context_rules, %{
      exclude_paths: [~r/test/, ~r/node_modules/]
    })
    |> Map.put(:confidence_rules, nil)
    |> Map.put(:min_confidence, 0.7)
  end
  
  @doc """
  Get patterns in AST-enhanced format when requested.
  """
  def get_patterns(language, tier, format \\ :standard)
  
  def get_patterns(language, tier, :enhanced) do
    # Get standard patterns
    patterns = apply(pattern_module(language), :all, [])
    
    # Enhance them
    patterns
    |> Enum.map(&enhance/1)
    |> filter_by_tier(tier)
  end
  
  def get_patterns(language, tier, :standard) do
    # Existing behavior unchanged
    apply(pattern_module(language), :all, [])
    |> filter_by_tier(tier)
  end
  
  defp pattern_module("javascript"), do: RsolvApi.Security.Patterns.Javascript
  defp pattern_module("python"), do: RsolvApi.Security.Patterns.Python
  defp pattern_module("ruby"), do: RsolvApi.Security.Patterns.Ruby
  defp pattern_module("java"), do: RsolvApi.Security.Patterns.Java
  defp pattern_module("elixir"), do: RsolvApi.Security.Patterns.Elixir
  defp pattern_module("php"), do: RsolvApi.Security.Patterns.Php
  defp pattern_module(_), do: RsolvApi.Security.Patterns.Javascript
  
  defp filter_by_tier(patterns, :public) do
    # Public gets fewer patterns
    Enum.take(patterns, div(length(patterns), 2))
  end
  
  defp filter_by_tier(patterns, :protected) do
    # Protected gets most patterns
    Enum.take(patterns, round(length(patterns) * 0.8))
  end
  
  defp filter_by_tier(patterns, tier) when tier in [:ai, :enterprise] do
    # Premium tiers get everything
    patterns
  end
end