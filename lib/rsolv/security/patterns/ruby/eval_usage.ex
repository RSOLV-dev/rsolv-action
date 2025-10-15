defmodule Rsolv.Security.Patterns.Ruby.EvalUsage do
  @moduledoc """
  Pattern for detecting dangerous eval usage in Ruby applications.

  This pattern identifies when code evaluation methods like eval(), instance_eval(),
  class_eval(), module_eval(), and dynamic method calling are used with user-controlled
  input, which can lead to remote code execution vulnerabilities.

  ## Vulnerability Details

  Eval injection vulnerabilities occur when applications use Ruby's code evaluation
  functions with untrusted user input. These functions execute arbitrary Ruby code
  at runtime, providing attackers with complete control over the application when
  exploited successfully.

  ### Attack Example
  ```ruby
  # Vulnerable code evaluation
  class DynamicController < ApplicationController
    def execute
      # VULNERABLE: Direct eval with user input
      result = eval(params[:code])

      # VULNERABLE: instance_eval with user data
      user.instance_eval(params[:method_definition])

      # VULNERABLE: Dynamic method calling
      model.send(params[:action], params[:args])

      # VULNERABLE: Dynamic constant access
      klass = Object.const_get(params[:class_name])

      render json: { result: result }
    end
  end

  # Attack payloads:
  # params[:code] = "system('rm -rf /')"
  # params[:method_definition] = "def admin?; true; end"
  # params[:action] = "destroy!"
  # params[:class_name] = "User; system('cat /etc/passwd')"
  ```

  **Real-world Impact:**
  CVE-2019-16255 demonstrated eval injection in Ruby's Shell library leading to
  remote code execution. Many Rails applications have been compromised through
  eval-related vulnerabilities in dynamic code generation features.

  **Safe Alternative:**
  ```ruby
  # SECURE: No dynamic code evaluation
  class SecureController < ApplicationController
    def execute
      # SECURE: Predefined allowed actions
      allowed_actions = ['show', 'update', 'create']
      action = params[:action]

      if allowed_actions.include?(action)
        case action
        when 'show'
          render json: model.show
        when 'update'
          model.update(permitted_params)
        when 'create'
          model.create(permitted_params)
        end
      else
        render json: { error: 'Invalid action' }, status: 400
      end
    end

    private

    def permitted_params
      params.require(:model).permit(:name, :email, :description)
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "ruby-eval-usage",
      name: "Dangerous Eval Usage",
      description: "Detects eval usage which can lead to code injection",
      type: :code_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        # eval(params[:code])
        ~r/eval\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # eval params[:code]
        ~r/eval\s+(?:params|request|user_\w+|user\w*)/,
        # eval("#{user_input}")
        ~r/eval\s*\(\s*["'].*?#\{.*?(?:params|request|user_\w+|user\w*)/,
        # instance_eval(params[:method])
        ~r/instance_eval\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # instance_eval params[:code]
        ~r/instance_eval\s+(?:params|request|user_\w+|user\w*)/,
        # class_eval(params[:code])
        ~r/class_eval\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # class_eval params[:code]
        ~r/class_eval\s+(?:params|request|user_\w+|user\w*)/,
        # module_eval(params[:code])
        ~r/module_eval\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # module_eval params[:code]
        ~r/module_eval\s+(?:params|request|user_\w+|user\w*)/,
        # obj.send(params[:method])
        ~r/\.send\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # send(params[:method])
        ~r/\bsend\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # const_get(params[:class])
        ~r/const_get\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # Object.const_get(params[:class])
        ~r/Object\.const_get\s*\(\s*(?:params|request|user_\w+|user\w*)/,
        # Module.const_get(params[:class])
        ~r/Module\.const_get\s*\(\s*(?:params|request|user_\w+|user\w*)/
      ],
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation:
        "Avoid eval with user input. Use safer alternatives like JSON parsing, whitelisted method calls, or predefined action mappings",
      test_cases: %{
        vulnerable: [
          ~S|eval(params[:code])|,
          ~S|instance_eval(user_input)|,
          ~S|obj.send(params[:method])|,
          ~S|const_get(params[:class])|
        ],
        safe: [
          ~S|eval("puts 'static code'")|,
          ~S|instance_eval { @name = 'safe' }|,
          ~S|send(:safe_method)|,
          ~S|const_get("STATIC_CONSTANT")|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Eval injection is a critical code injection vulnerability that occurs when
      applications use Ruby's dynamic code evaluation functions with untrusted user input.
      These functions execute arbitrary Ruby code at runtime, providing attackers with
      complete control over the application when exploited successfully.

      **How Eval Injection Works:**
      Ruby provides several methods for dynamic code evaluation:
      - **eval()**: Executes a string containing Ruby source code
      - **instance_eval()**: Evaluates code in the context of an object instance
      - **class_eval()/module_eval()**: Evaluates code in the context of a class or module
      - **send()**: Dynamically calls methods by name
      - **const_get()**: Dynamically accesses constants and classes

      When any of these methods receive user-controlled input, attackers can inject
      arbitrary Ruby code that executes with the application's privileges.

      **Ruby-Specific Evaluation Methods:**
      - **eval()**: Direct string-to-code execution, most dangerous
      - **instance_eval()**: Context-aware evaluation on object instances
      - **class_eval()**: Class context evaluation, can modify class definitions
      - **module_eval()**: Module context evaluation, can modify module behavior
      - **send()**: Dynamic method dispatch, can call private methods
      - **const_get()**: Dynamic constant resolution, can access any class

      **Critical Security Impact:**
      Eval injection vulnerabilities are extremely dangerous because they provide:
      - **Complete System Access**: Execute any Ruby code with app privileges
      - **Data Exfiltration**: Access sensitive data, database credentials, secrets
      - **System Compromise**: Execute system commands, install backdoors
      - **Privilege Escalation**: Access internal methods and sensitive functionality
      - **Business Logic Bypass**: Modify application behavior at runtime

      **Rails-Specific Vulnerabilities:**
      Rails applications are particularly vulnerable to eval injection through:
      - Dynamic method generation in controllers and models
      - Template rendering with user-controlled content
      - Configuration parsing with eval-based DSLs
      - Plugin and gem loading mechanisms
      - Serialization/deserialization with code execution

      **Common Attack Scenarios:**
      - Code execution through dynamic method definitions
      - System command injection via Ruby's backtick operator
      - Database credential extraction through environment access
      - Session manipulation and authentication bypass
      - File system access and sensitive data extraction
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-94",
          title: "Improper Control of Generation of Code ('Code Injection')",
          url: "https://cwe.mitre.org/data/definitions/94.html"
        },
        %{
          type: :cwe,
          id: "CWE-95",
          title:
            "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
          url: "https://cwe.mitre.org/data/definitions/95.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "ruby_eval_bishopfox",
          title: "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization",
          url: "https://bishopfox.com/blog/ruby-vulnerabilities-exploits"
        },
        %{
          type: :research,
          id: "akamai_rails_injection",
          title: "Rails Without Derails: Thwarting Code Injection Attacks",
          url:
            "https://www.akamai.com/blog/security/2024-october-ruby-on-rails-waf-code-injection-protection"
        },
        %{
          type: :research,
          id: "rails_security_guide",
          title: "Ruby on Rails Security Guide - Code Evaluation",
          url: "https://guides.rubyonrails.org/security.html"
        },
        %{
          type: :research,
          id: "owasp_rails_cheatsheet",
          title: "OWASP Ruby on Rails Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Direct eval injection: eval(params[:code]) allowing arbitrary Ruby code execution",
        "Instance method injection: instance_eval(user_input) to modify object behavior",
        "Class definition injection: class_eval(params[:method]) to redefine class methods",
        "Dynamic method calling: send(params[:method]) to invoke any method including private ones",
        "Constant injection: const_get(params[:class]) to access any class or module",
        "System command execution: eval(params[:code]) with backtick or system() calls",
        "Environment variable access: eval() to extract ENV secrets and credentials",
        "Database credential extraction: eval to access ActiveRecord connection details",
        "Session manipulation: instance_eval to modify user session and authentication state",
        "File system access: eval with File operations to read sensitive configuration files"
      ],
      real_world_impact: [
        "CVE-2019-16255: Ruby Shell library code injection vulnerability with CVSS 9.8",
        "CVE-2025-27407: GraphQL Ruby remote code execution via eval-like methods",
        "Multiple Rails applications compromised through eval in dynamic code generation",
        "Web shells installed through eval injection in content management systems",
        "Database credentials extracted via eval in configuration parsing vulnerabilities",
        "System compromise through eval in plugin loading mechanisms",
        "Authentication bypass via instance_eval manipulation of user objects",
        "Business logic bypass through class_eval modification of authorization methods",
        "Data exfiltration through eval-based access to sensitive application internals",
        "Remote code execution in production Rails applications via template injection"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-16255",
          description: "Ruby Shell library code injection vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Code injection if first argument to Shell#[] or Shell#test is untrusted data"
        },
        %{
          id: "CVE-2025-27407",
          description: "GraphQL Ruby remote code execution via eval-like methods",
          severity: "critical",
          cvss: 9.8,
          note: "Unsafe use of instance_eval, class_eval, module_eval in schema processing"
        },
        %{
          id: "CVE-2013-3221",
          description: "Ruby on Rails eval injection in development environment",
          severity: "high",
          cvss: 7.5,
          note: "Dynamic code evaluation in Rails development mode allowing RCE"
        },
        %{
          id: "CVE-2016-0752",
          description: "Rails Action Pack eval injection vulnerability",
          severity: "critical",
          cvss: 9.3,
          note: "Possible information disclosure and eval injection in development mode"
        }
      ],
      detection_notes: """
      This pattern detects eval injection vulnerabilities by identifying Ruby evaluation
      methods that receive user-controlled input:

      **Primary Detection Points:**
      - eval() with params, request, or user_input variables
      - instance_eval() with dynamic user-controlled strings
      - class_eval()/module_eval() with user input
      - send() method calls with dynamic method names from user input
      - const_get() with user-controlled class/module names

      **Ruby-Specific Patterns:**
      - Multiple eval syntax forms: eval(expr) and eval expr
      - Context-aware evaluation methods: instance_eval, class_eval, module_eval
      - Dynamic method dispatch: send() and public_send()
      - Constant resolution: const_get() on Object and Module
      - Both parenthesized and space-separated argument forms

      **False Positive Considerations:**
      - Static string evaluation (acceptable in some contexts)
      - Block-based evaluation ({ } and do..end blocks)
      - Symbol-based method calling with send()
      - Hardcoded constant names with const_get()
      - Commented out evaluation code

      **Detection Enhancements:**
      The AST enhancement provides sophisticated analysis:
      - User input source detection (params, request, cookies, etc.)
      - Argument analysis to distinguish dynamic vs static content
      - Context analysis for development vs production environments
      - Method call chain analysis for nested evaluation
      """,
      safe_alternatives: [
        "Use JSON.parse() instead of eval() for data parsing",
        "Use predefined action mappings instead of dynamic method calling",
        "Use case/when statements instead of dynamic code evaluation",
        "Use symbol-based method calls: send(:method_name) instead of send(user_input)",
        "Use const_get with hardcoded strings: const_get('SAFE_CONSTANT')",
        "Use block-based evaluation: instance_eval { } instead of instance_eval(string)",
        "Implement whitelist validation for any dynamic method calls",
        "Use strong parameters to restrict allowed input fields",
        "Implement proper input sanitization and validation",
        "Use configuration-driven behavior instead of dynamic code generation"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing eval is safe with 'sanitized' user input",
          "Using eval for simple data parsing instead of JSON",
          "Thinking instance_eval/class_eval are safer than eval (they're not)",
          "Not validating method names before using send()",
          "Using const_get with user input to dynamically load classes",
          "Assuming development-only eval code won't reach production",
          "Using eval in configuration parsing without input validation",
          "Not understanding that eval executes with full application privileges"
        ],
        secure_patterns: [
          "JSON.parse(params[:data]) # Safe data parsing",
          "send(:predefined_method) # Symbol-based method calling",
          "case params[:action] when 'show' then show_action end # Action mapping",
          "ALLOWED_ACTIONS.include?(action) && send(action) # Whitelist validation",
          "const_get('SAFE_CONSTANT') # Hardcoded constant access",
          "instance_eval { @safe = true } # Block-based evaluation",
          "eval('puts \"hello\"') if Rails.env.development? # Environment checks"
        ],
        ruby_specific: %{
          evaluation_methods: [
            "eval(): Direct string-to-code execution, most dangerous",
            "instance_eval(): Evaluates code in object instance context",
            "class_eval(): Evaluates code in class context, alias for module_eval",
            "module_eval(): Evaluates code in module context",
            "send(): Dynamic method calling, can access private methods",
            "public_send(): Like send() but only public methods",
            "const_get(): Dynamic constant/class resolution"
          ],
          rails_specific: [
            "Dynamic controller action generation",
            "Template rendering with user content",
            "ActiveRecord dynamic finder methods",
            "Configuration DSL evaluation",
            "Plugin and gem loading mechanisms",
            "Serialization with Marshal and YAML"
          ],
          mitigation_strategies: [
            "Use strong parameters to limit input fields",
            "Implement action whitelists for dynamic method calling",
            "Use JSON for data exchange instead of eval-based parsing",
            "Validate all user input before any dynamic operations",
            "Use symbols instead of strings for method names",
            "Implement proper error handling for dynamic operations",
            "Regular security audits of eval usage in codebase"
          ]
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual security issues and
  acceptable eval usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.EvalUsage.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Ruby.EvalUsage.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: [
          "eval",
          "instance_eval",
          "class_eval",
          "module_eval",
          "send",
          "public_send",
          "const_get"
        ],
        receiver_analysis: %{
          check_object_context: true,
          built_in_receivers: ["Object", "Module", "Kernel"],
          instance_receivers: true
        },
        user_input_analysis: %{
          check_params: true,
          check_request_data: true,
          check_user_variables: true,
          input_sources: ["params", "request", "user_input", "user_data", "cookies", "headers"],
          dangerous_patterns: [
            "params[",
            "request.",
            "user_input",
            "user_data",
            "cookies[",
            "headers["
          ]
        },
        argument_analysis: %{
          check_string_arguments: true,
          check_interpolation: true,
          detect_static_vs_dynamic: true,
          require_user_input_presence: true
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/factories/,
          ~r/seeds/,
          ~r/migrations/,
          ~r/examples/,
          ~r/demo/
        ],
        check_development_context: true,
        environment_patterns: [
          ~r/Rails\.env\.development\?/,
          ~r/Rails\.env\.test\?/,
          ~r/if\s+Rails\.env\.development/,
          ~r/unless\s+Rails\.env\.production/
        ],
        safe_patterns: %{
          static_strings: true,
          block_syntax: true,
          symbol_arguments: true,
          hardcoded_constants: true
        },
        dangerous_contexts: [
          "controller",
          "params processing",
          "user input handling",
          "request processing",
          "form handling",
          "API endpoint"
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "direct_params_access" => 0.3,
          "request_data_access" => 0.3,
          "user_variable_pattern" => 0.2,
          "interpolated_user_input" => 0.2,
          "controller_context" => 0.1,
          "api_endpoint_context" => 0.1,
          "static_string_argument" => -0.4,
          "block_syntax" => -0.5,
          "symbol_argument" => -0.6,
          "development_environment" => -0.2,
          "test_context" => -0.3,
          "hardcoded_constant" => -0.4,
          "commented_out" => -1.0
        }
      },
      min_confidence: 0.8
    }
  end
end
