defmodule RsolvApi.Security.Patterns.Python.UnsafeYamlLoad do
  @moduledoc """
  Pattern for detecting unsafe YAML loading in Python code.
  
  Detects usage of yaml.load() without SafeLoader which can execute arbitrary code.
  This is a critical vulnerability that has been exploited in multiple CVEs.
  """

  alias RsolvApi.Security.Pattern

  @doc """
  Returns the complete pattern for detecting unsafe YAML loading.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeYamlLoad.pattern()
      iex> pattern.id
      "python-unsafe-yaml-load"
      iex> pattern.severity
      :critical
      iex> pattern.type
      :deserialization
  """
  def pattern do
    %Pattern{
      id: "python-unsafe-yaml-load",
      name: "Unsafe YAML Deserialization",
      description: "Detects unsafe usage of yaml.load() which can execute arbitrary Python code",
      type: :deserialization,
      severity: :critical,
      languages: ["python"],
      regex: ~r/
        # yaml.load() without SafeLoader or with FullLoader
        yaml\.load\s*\((?:[^,)]|,\s*Loader\s*=\s*yaml\.FullLoader)*\)|
        # from yaml import load
        from\s+yaml\s+import\s+.*\bload\b|
        # Direct load() call after import
        (?:^|\s)load\s*\([^,)]*\)
      /x,
      default_tier: :public,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
      test_cases: %{
        vulnerable: [
          "data = yaml.load(user_input)",
          "config = yaml.load(f)",
          "from yaml import load; data = load(request.body)",
          "result = yaml.load(untrusted_data, Loader=yaml.FullLoader)"
        ],
        safe: [
          "data = yaml.safe_load(user_input)",
          "data = yaml.load(user_input, Loader=yaml.SafeLoader)",
          "data = json.loads(user_input)"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.
  """
  def test_cases do
    %{
      positive: [
        %{
          code: """
          import yaml
          data = yaml.load(user_input)
          """,
          description: "Basic unsafe yaml.load() usage"
        },
        %{
          code: """
          import yaml
          with open('config.yml') as f:
              config = yaml.load(f)
          """,
          description: "Unsafe yaml.load() reading from file"
        },
        %{
          code: """
          from yaml import load
          data = load(request.body)
          """,
          description: "Imported load function without SafeLoader"
        },
        %{
          code: """
          import yaml
          # This is dangerous
          result = yaml.load(untrusted_data, Loader=yaml.FullLoader)
          """,
          description: "Using FullLoader which is also unsafe"
        }
      ],
      negative: [
        %{
          code: """
          import yaml
          data = yaml.safe_load(user_input)
          """,
          description: "Using safe_load which is secure"
        },
        %{
          code: """
          import yaml
          data = yaml.load(user_input, Loader=yaml.SafeLoader)
          """,
          description: "Using SafeLoader explicitly"
        },
        %{
          code: """
          import json
          data = json.loads(user_input)
          """,
          description: "Using JSON instead of YAML"
        },
        %{
          code: """
          # yaml.load() in a comment is fine
          data = parse_config(input)
          """,
          description: "Pattern in comment should not match"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Basic unsafe load" => """
        import yaml
        
        # This allows arbitrary code execution
        config = yaml.load(user_provided_yaml)
        """,
        "Loading from file" => """
        import yaml
        
        with open('user_upload.yml', 'r') as f:
            # Dangerous if file content is not trusted
            data = yaml.load(f)
        """,
        "Using FullLoader" => """
        import yaml
        
        # FullLoader is still unsafe for untrusted data
        settings = yaml.load(config_string, Loader=yaml.FullLoader)
        """
      },
      fixed: %{
        "Use safe_load" => """
        import yaml
        
        # safe_load only constructs simple Python objects
        config = yaml.safe_load(user_provided_yaml)
        """,
        "Use SafeLoader explicitly" => """
        import yaml
        
        # Explicitly specify SafeLoader
        data = yaml.load(user_input, Loader=yaml.SafeLoader)
        """,
        "Validate and use JSON" => """
        import json
        
        # JSON is safe by default
        config = json.loads(user_provided_json)
        """
      }
    }
  end

  @doc """
  Returns references for the vulnerability.
  """
  def references do
    [
      "https://cwe.mitre.org/data/definitions/502.html",
      "https://owasp.org/www-project-top-ten/2021/Top_10/A08_2021-Software_and_Data_Integrity_Failures/",
      "https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation",
      "https://python.land/data-processing/python-yaml",
      "https://pyyaml.org/wiki/PyYAMLDocumentation"
    ]
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    YAML deserialization in Python using yaml.load() can execute arbitrary code.
    This is not a bug but a feature of YAML that allows it to instantiate any
    Python object, including those that execute code upon creation.
    
    ## Attack Mechanism
    
    1. **Object Instantiation**: YAML can create any Python object using tags
    2. **Code Execution**: Objects can execute code in __init__ or __reduce__
    3. **System Compromise**: Attackers can run OS commands, read files, etc.
    
    ## Example Attack Payload
    
    ```yaml
    !!python/object/apply:os.system
    args: ['rm -rf /']
    ```
    
    ## Real CVE Examples
    
    - **CVE-2020-14343**: PyYAML vulnerability allowing arbitrary code execution
    - **CVE-2019-20477**: PyYAML vulnerability in versions before 5.2
    - **CVE-2020-1747**: PyYAML vulnerability allowing arbitrary command execution
    
    ## Safe Alternatives
    
    - **yaml.safe_load()**: Only loads standard YAML tags (strings, lists, dicts)
    - **yaml.load(data, Loader=yaml.SafeLoader)**: Explicit safe loader
    - **JSON**: Consider JSON for data that doesn't need YAML features
    - **Validation**: Always validate deserialized data structure
    """
  end

  @doc """
  Returns AST enhancement rules for improved detection.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeYamlLoad.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeYamlLoad.ast_enhancement()
      iex> enhancement.min_confidence
      0.85
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeYamlLoad.ast_enhancement()
      iex> length(enhancement.rules)
      2
  """
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "safe_loader_check",
          description: "Check if SafeLoader is used",
          patterns: [
            "Loader=yaml.SafeLoader",
            "Loader = yaml.SafeLoader",
            "yaml.safe_load",
            "safe_load"
          ]
        },
        %{
          type: "context_check",
          description: "Check data source trustworthiness",
          untrusted_sources: [
            "request",
            "user_input",
            "upload",
            "external",
            "network",
            "socket"
          ]
        }
      ],
      min_confidence: 0.85
    }
  end
end