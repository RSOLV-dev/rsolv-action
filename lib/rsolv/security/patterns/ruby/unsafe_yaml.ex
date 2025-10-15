defmodule Rsolv.Security.Patterns.Ruby.UnsafeYaml do
  @moduledoc """
  Detects unsafe YAML deserialization vulnerabilities in Ruby code.

  YAML deserialization can lead to remote code execution when deserializing untrusted data.
  Ruby's YAML.load and Psych.load can instantiate arbitrary objects, executing code during deserialization.

  ## Vulnerability Details

  YAML deserialization attacks exploit the ability to instantiate arbitrary Ruby objects from YAML data.
  Attackers can craft malicious YAML payloads containing objects that execute code during deserialization.

  ### Attack Example
  ```ruby
  # Vulnerable - loads untrusted YAML that can execute arbitrary code
  data = YAML.load(params[:config])
  config = Psych.load(request.body.read)

  # Attacker payload example:
  # --- !ruby/object:ERB
  # src: "<%= `whoami` %>"
  # Safe alternative:
  data = YAML.safe_load(params[:config], permitted_classes: [Symbol])
  ```

  ### Real-World Impact
  - Remote Code Execution (RCE) with application privileges
  - Data exfiltration and system compromise 
  - Privilege escalation and lateral movement
  - Denial of service through resource exhaustion
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the unsafe YAML loading pattern for Ruby applications.

  Detects usage of YAML.load, Psych.load, and similar unsafe deserialization methods
  with user-controlled input that can lead to remote code execution.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Ruby.UnsafeYaml.pattern()
      iex> pattern.id
      "ruby-unsafe-yaml"
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.UnsafeYaml.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.UnsafeYaml.pattern()
      iex> vulnerable = "data = YAML.load(params[:config])"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.UnsafeYaml.pattern()
      iex> safe = "data = YAML.safe_load(params[:config])"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-unsafe-yaml",
      name: "Unsafe YAML Loading",
      description: "Detects unsafe YAML deserialization that can lead to remote code execution",
      type: :deserialization,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        # YAML.load with params
        ~r/YAML\.load\s*\(\s*params\[/,
        ~r/YAML\.load\s*\(\s*params\./,

        # YAML.load with request data
        ~r/YAML\.load\s*\(\s*request\./,
        ~r/YAML\.load\s*\(\s*request\[/,

        # YAML.load with user input variables
        ~r/YAML\.load\s*\(\s*(?:user_input|untrusted_data|external_data|client_data|uploaded_content)/,

        # YAML.load with file operations (user-controlled paths)
        ~r/YAML\.load\s*\(\s*File\.read\s*\(\s*params\[/,
        ~r/YAML\.load\s*\(\s*uploaded_file\.read/,
        ~r/YAML\.load\s*\(\s*File\.open\s*\(\s*user_\w+/,
        ~r/YAML\.load\s*\(\s*IO\.read\s*\(\s*params\[/,

        # Psych.load patterns
        ~r/Psych\.load\s*\(\s*params\[/,
        ~r/Psych\.load\s*\(\s*(?:user_input|untrusted_data)/,
        ~r/Psych\.load\s*\(\s*request\./,
        ~r/Psych\.load\s*\(\s*uploaded_file\.read/,

        # Rails CVE-2013-0156 patterns (double-colon syntax)
        ~r/YAML::load\s*\(\s*params\[/,
        ~r/Psych::load\s*\(\s*params\[/,
        ~r/YAML::load\s*\(\s*request\./,
        ~r/Psych::load\s*\(\s*request\./
      ],
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation:
        "Use YAML.safe_load with explicit permitted_classes to safely deserialize YAML data. Validate and sanitize all user input before processing.",
      test_cases: %{
        vulnerable: [
          "data = YAML.load(params[:config])",
          "config = YAML.load(request.body.read)",
          "obj = Psych.load(user_input)",
          "result = YAML.load(File.read(params[:file]))",
          "YAML::load(params[:yaml])"
        ],
        safe: [
          "data = YAML.safe_load(params[:config])",
          "config = YAML.safe_load(user_input, permitted_classes: [Symbol])",
          "obj = Psych.safe_load(params[:data])",
          "result = YAML.load_file('config/settings.yml')",
          "YAML.dump(user_object)"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe YAML deserialization allows attackers to execute arbitrary code by crafting malicious YAML payloads. 
      Ruby's YAML.load and Psych.load can instantiate arbitrary objects, including those that execute code during deserialization.
      This vulnerability has been exploited in numerous Rails applications and can lead to complete system compromise.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-502",
          title: "Deserialization of Untrusted Data",
          url: "https://cwe.mitre.org/data/definitions/502.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :research,
          id: "yaml_deserialization_ruby",
          title: "YAML Deserialization Attack in Ruby",
          url: "https://www.elttam.com/blog/ruby-deserialization/"
        },
        %{
          type: :research,
          id: "rails_yaml_vulnerability",
          title: "Rails Remote Code Execution Vulnerability",
          url:
            "https://blog.codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained/"
        }
      ],
      attack_vectors: [
        "Malicious YAML containing ERB objects that execute system commands",
        "YAML payloads with Ruby objects that trigger code execution in initialize methods",
        "Exploitation of vulnerable gems through deserialized objects",
        "File system access through crafted Pathname objects",
        "Network requests via deserialized HTTP objects",
        "Code execution through eval-based YAML tags",
        "Memory exhaustion attacks through recursive object structures"
      ],
      real_world_impact: [
        "Remote Code Execution with full application privileges",
        "Complete system compromise and data exfiltration",
        "Privilege escalation and lateral movement within networks",
        "Denial of service through resource exhaustion attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2013-0156",
          description: "Rails YAML deserialization remote code execution vulnerability",
          severity: "critical",
          cvss: 10.0,
          note:
            "Allowed remote attackers to execute arbitrary code via crafted YAML data in HTTP requests"
        },
        %{
          id: "CVE-2022-47986",
          description: "IBM Cloud Pak YAML deserialization vulnerability",
          severity: "critical",
          cvss: 9.8,
          note:
            "Remote code execution through unsafe YAML deserialization in configuration processing"
        },
        %{
          id: "CVE-2020-14343",
          description: "PyYAML arbitrary code execution vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Full_load method allowed execution of arbitrary Python code via malicious YAML"
        }
      ],
      detection_notes: """
      This pattern detects direct usage of YAML.load and Psych.load with user-controlled input.
      AST enhancement provides additional context analysis to reduce false positives by:
      - Checking for safe_load usage instead of unsafe load methods
      - Validating input source (params, request, user variables)
      - Excluding static configuration file loading
      - Detecting sanitization and validation patterns
      """,
      safe_alternatives: [
        "Use YAML.safe_load with explicit permitted_classes parameter",
        "Use Psych.safe_load for secure YAML parsing",
        "Validate YAML structure and content before processing",
        "Use JSON for data interchange when YAML features aren't needed",
        "Implement input sanitization and content filtering",
        "Use configuration management systems for trusted YAML files"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that input validation prevents YAML deserialization attacks",
          "Using YAML.load for configuration files with user-controlled paths",
          "Assuming that complex objects are safe to deserialize",
          "Not understanding the difference between safe_load and load methods"
        ],
        secure_patterns: [
          "Always use YAML.safe_load for untrusted input",
          "Explicitly define permitted_classes for deserialization",
          "Validate YAML content structure before processing",
          "Use static configuration files with controlled access"
        ],
        framework_notes: %{
          rails:
            "Rails 4.0+ uses safe_load by default, but explicit user calls to YAML.load remain vulnerable",
          sinatra: "No built-in YAML protection - must explicitly use safe_load",
          general: "Ruby 2.1+ includes Psych which is safer but load methods remain dangerous"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for YAML deserialization detection.

  This enhancement helps distinguish between actual vulnerabilities and false positives by
  analyzing the AST context around YAML loading operations.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.UnsafeYaml.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.UnsafeYaml.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.UnsafeYaml.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.UnsafeYaml.ast_enhancement()
      iex> "YAML.load" in enhancement.ast_rules.yaml_analysis.unsafe_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        yaml_analysis: %{
          yaml_libraries: ["YAML", "Psych"],
          unsafe_methods: ["YAML.load", "Psych.load", "YAML::load", "Psych::load"],
          safe_methods: ["YAML.safe_load", "Psych.safe_load", "YAML.load_file", "YAML.dump"]
        },
        user_input_analysis: %{
          input_sources: [
            "params",
            "request",
            "user_input",
            "untrusted_data",
            "external_data",
            "client_data",
            "uploaded_content"
          ],
          file_operations: ["File.read", "uploaded_file.read", "File.open", "IO.read"],
          user_controlled_paths: true
        },
        method_call_analysis: %{
          receiver_patterns: ["YAML", "Psych"],
          method_patterns: ["load"],
          argument_patterns: ["user_controlled_input"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/config\//, ~r/fixtures/],
        exclude_if_safe_method: true,
        safe_if_uses: ["YAML.safe_load", "Psych.safe_load", "permitted_classes"],
        exclude_static_files: true,
        exclude_if_validated: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_params_or_request" => 0.2,
          "file_upload_context" => 0.2,
          "uses_safe_load" => -1.0,
          "has_permitted_classes" => -0.5,
          "static_file_path" => -0.8,
          "in_test_code" => -1.0,
          "in_config_file" => -0.7
        }
      },
      min_confidence: 0.8
    }
  end
end
