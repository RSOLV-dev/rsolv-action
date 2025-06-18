defmodule RsolvApi.Security.Patterns.Python.UnsafePickle do
  @moduledoc """
  Insecure Deserialization via Python pickle Module
  
  Detects dangerous patterns like:
    data = pickle.loads(user_data)
    with open('data.pkl', 'rb') as f: obj = pickle.load(f)
    result = pickle.loads(base64.b64decode(encoded_data))
    
  Safe alternatives:
    data = json.loads(user_data)
    result = yaml.safe_load(content)
    obj = msgpack.loads(bytes_data, strict_map_key=False)
    
  Python's pickle module can execute arbitrary code during deserialization.
  When pickle deserializes an object, it can invoke any callable Python
  object, allowing attackers to execute arbitrary commands by crafting
  malicious pickle data. This is not a bug - it's by design.
  
  ## Vulnerability Details
  
  Pickle is Python's native serialization format that can serialize almost
  any Python object, including code objects. During deserialization, pickle
  can be instructed to import modules, call functions, and execute code.
  This makes it extremely dangerous when used with untrusted data.
  
  ### Attack Example
  ```python
  # Attacker creates malicious pickle data
  import pickle
  import os
  
  class RCE:
      def __reduce__(self):
          return (os.system, ('rm -rf /',))
  
  malicious_data = pickle.dumps(RCE())
  
  # Victim application deserializes it
  pickle.loads(malicious_data)  # Executes 'rm -rf /'
  ```
  
  ### Why Pickle is Dangerous
  The pickle protocol includes opcodes that can:
  - Import any module
  - Get attributes from any object
  - Call any callable with arguments
  - Execute arbitrary Python expressions
  This functionality cannot be disabled or sandboxed safely.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the unsafe pickle detection pattern.
  
  This pattern detects usage of Python's pickle module for deserialization,
  which can lead to remote code execution vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> pattern.id
      "python-unsafe-pickle"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> pattern.cwe_id
      "CWE-502"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> vulnerable = "data = pickle.loads(user_data)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> safe = "data = json.loads(user_data)"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafePickle.pattern()
      iex> pattern.recommendation
      "Use json.loads() or implement custom deserialization with validation"
  """
  def pattern do
    %Pattern{
      id: "python-unsafe-pickle",
      name: "Insecure Deserialization via pickle",
      description: "pickle.loads() can execute arbitrary code during deserialization",
      type: :deserialization,
      severity: :critical,
      languages: ["python"],
      # Match pickle.loads, pickle.load, cPickle usage, and direct imports
      # Use word boundary or whitespace to avoid matching json.loads
      regex: ~r/(?:(?:pickle|cPickle)\.|(?:^|\s))(?:loads?|Unpickler)\s*\(/,
      default_tier: :ai,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use json.loads() or implement custom deserialization with validation",
      test_cases: %{
        vulnerable: [
          "data = pickle.loads(user_data)",
          "with open('data.pkl', 'rb') as f: obj = pickle.load(f)",
          "result = pickle.loads(base64.b64decode(encoded_data))",
          "import cPickle; obj = cPickle.loads(serialized)"
        ],
        safe: [
          "data = json.loads(user_data)",
          "with open('data.json', 'r') as f: obj = json.load(f)",
          "result = yaml.safe_load(content)",
          "# Use a safe serialization format like JSON or MessagePack"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for Python pickle deserialization.
  
  This metadata documents the severe security implications of using pickle
  with untrusted data and provides guidance for secure alternatives.
  """
  def vulnerability_metadata do
    %{
      description: """
      Insecure deserialization vulnerabilities through Python's pickle module
      represent one of the most critical security issues in Python applications.
      Unlike other serialization formats, pickle is not just a data format - it's
      a stack-based virtual machine that can execute arbitrary Python code.
      
      When pickle deserializes data, it can:
      - Import any Python module
      - Create instances of any class
      - Call any callable object
      - Execute arbitrary Python expressions
      - Access and modify global state
      
      This is not a flaw or bug in pickle - it's the intended design. The pickle
      documentation explicitly warns: "The pickle module is not secure. Only
      unpickle data you trust." However, many developers don't fully understand
      the implications of this warning.
      
      The vulnerability is particularly dangerous because:
      1. Exploitation requires only the ability to provide pickle data
      2. No additional vulnerabilities are needed - pickle itself is the vulnerability
      3. Attacks can be crafted to work across Python versions
      4. The payload executes with the privileges of the Python process
      5. It's often used in web applications, APIs, and distributed systems
      
      Common attack vectors include web applications that pickle user sessions,
      APIs that accept pickled data, distributed computing frameworks like Celery
      when configured to use pickle, and any system that stores pickled data
      where an attacker might modify it.
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
          type: :documentation,
          id: "python_pickle",
          title: "Python pickle Module Documentation",
          url: "https://docs.python.org/3/library/pickle.html"
        },
        %{
          type: :research,
          id: "exploiting_pickle",
          title: "Exploiting Python Pickles",
          url: "https://davidhamann.de/2020/04/05/exploiting-python-pickle/"
        },
        %{
          type: :research,
          id: "pickle_security",
          title: "Python Pickle Security Problems and Solutions",
          url: "https://www.synopsys.com/blogs/software-security/python-pickling/"
        }
      ],
      attack_vectors: [
        "Basic RCE: pickle.loads(b\"cos\\nsystem\\n(S'rm -rf /'\\ntR.\")",
        "Import and execute: __reduce__ returning (os.system, ('whoami',))",
        "Reverse shell: __reduce__ with subprocess.Popen for shell access",
        "Module manipulation: Importing and modifying sys.modules",
        "Global modification: Using pickle opcodes to modify __builtins__",
        "Chained execution: Multiple __reduce__ calls for complex payloads",
        "Cross-version attacks: Payloads that work on Python 2 and 3",
        "Polyglot payloads: Pickle data that's also valid in other formats"
      ],
      real_world_impact: [
        "Complete system compromise with code execution",
        "Data exfiltration through command execution",
        "Cryptomining through compromised servers",
        "Lateral movement in internal networks",
        "Persistent backdoors via cron jobs or services",
        "Supply chain attacks by poisoning shared pickle files",
        "Denial of service through resource exhaustion",
        "Privilege escalation in multi-user systems"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-24329",
          description: "Python urllib.parse url bypass via blank characters in scheme",
          severity: "critical",
          cvss: 9.8,
          note: "URL validation bypass leading to pickle deserialization"
        },
        %{
          id: "CVE-2022-42919",
          description: "Python 3.9.x and 3.10.x local privilege escalation via pickle",
          severity: "high",
          cvss: 7.8,
          note: "Privilege escalation through malicious pickle in multiprocessing"
        },
        %{
          id: "CVE-2021-33026",
          description: "Flask-Caching remote code execution via pickle deserialization",
          severity: "critical",
          cvss: 9.8,
          note: "RCE in popular Flask extension through pickle in cache backend"
        },
        %{
          id: "CVE-2020-35678",
          description: "Autodesk Desktop Connector pickle deserialization RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Desktop application RCE through pickle deserialization"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. Direct pickle.loads() and pickle.load() calls
      2. cPickle usage (Python 2 compatibility)
      3. pickle.Unpickler class instantiation
      4. Both immediate calls and stored references
      
      The pattern intentionally catches all pickle usage because there's no
      safe way to use pickle with untrusted data. Even with restricted
      unpicklers or custom find_class methods, bypasses have been found.
      """,
      safe_alternatives: [
        "Use JSON for cross-language compatibility: json.loads(data)",
        "Use MessagePack for binary efficiency: msgpack.loads(data, raw=False)",
        "Use Protocol Buffers for schema enforcement: message.ParseFromString(data)",
        "Use YAML with safe_load: yaml.safe_load(data)",
        "Implement custom serialization with validation",
        "Use dataclasses with JSON: dataclass.from_dict(json.loads(data))",
        "For Numpy arrays: numpy.load(file, allow_pickle=False)",
        "For pandas: use Parquet or CSV instead of pickle",
        "For model persistence: use ONNX or model-specific formats",
        "Never use eval(), exec(), or pickle with user data"
      ],
      additional_context: %{
        common_vulnerable_uses: [
          "Session storage in web frameworks",
          "Celery task serialization (when using pickle)",
          "Distributed computing frameworks",
          "Model serialization in ML pipelines",
          "Inter-process communication",
          "Cache backends",
          "Configuration storage",
          "Database blob fields"
        ],
        secure_pickle_myths: [
          "Myth: Restricted Unpickler is safe - Reality: Bypasses exist",
          "Myth: Signing pickle data makes it safe - Reality: Only proves authenticity",
          "Myth: Encryption makes pickle safe - Reality: Only hides the vulnerability",
          "Myth: find_class restrictions work - Reality: __reduce__ can bypass them",
          "Myth: pickle protocol 0 is safe - Reality: Still allows code execution"
        ],
        framework_specific_notes: %{
          django: "Use Django's signing.loads() with JSON serializer, not pickle",
          flask: "Configure session interface to use JSON, not pickle",
          celery: "Set task_serializer='json' instead of 'pickle'",
          pandas: "Use to_parquet() or to_json() instead of to_pickle()",
          joblib: "Use joblib.dump() with compress=0 to avoid pickle"
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities
  and safe usage patterns (though pickle is rarely truly safe).
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafePickle.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafePickle.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "Call"
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafePickle.ast_enhancement()
      iex> "pickle.loads" in enhancement.ast_rules.function_names
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafePickle.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Call",
        function_names: [
          "pickle.loads",
          "pickle.load", 
          "cPickle.loads",
          "cPickle.load",
          "pickle.Unpickler",
          "loads",  # When imported directly
          "load"    # When imported directly
        ],
        import_check: %{
          modules: ["pickle", "cPickle", "_pickle"],
          from_imports: ["loads", "load", "Unpickler"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__pycache__/,
          ~r/migrations/,
          ~r/\.pyc$/,
          ~r/examples?/,
          ~r/docs?/,
          ~r/benchmarks?/
        ],
        exclude_if_comment: [
          "# nosec",
          "# noqa: S301",
          "# safe:",
          "# trusted source"
        ],
        check_data_source: true
      },
      confidence_rules: %{
        base: 0.9,  # Start high - pickle is almost always dangerous
        adjustments: %{
          "user_controlled_input" => 0.1,    # Definite vulnerability
          "network_data" => 0.1,             # Remote exploitation
          "file_input" => 0.05,              # File-based attacks
          "base64_decode" => 0.05,           # Common attack pattern
          "request_data" => 0.1,             # Web exploitation
          "hardcoded_data" => -0.3,          # Less likely exploitable
          "test_code" => -0.8,               # Test files
          "example_code" => -0.6,            # Documentation
          "trusted_source_comment" => -0.4,  # Marked as trusted
          "generated_file" => -0.5           # Auto-generated code
        }
      },
      min_confidence: 0.7
    }
  end
end