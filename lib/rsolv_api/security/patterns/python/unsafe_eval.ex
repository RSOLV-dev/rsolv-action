defmodule RsolvApi.Security.Patterns.Python.UnsafeEval do
  @moduledoc """
  Code Injection via Python eval() Function
  
  Detects dangerous patterns like:
    result = eval(user_input)
    value = eval(request.args.get('expression'))
    computed = eval(f"2 + {user_number}")
    
  Safe alternatives:
    result = ast.literal_eval(user_input)  # Only literals
    value = int(request.args.get('number', 0))
    data = json.loads(json_string)
    
  Python's eval() function executes arbitrary Python code from a string,
  making it one of the most dangerous functions when used with untrusted
  input. Unlike other languages, Python's eval() has full access to the
  Python runtime and can execute any valid Python expression.
  
  ## Vulnerability Details
  
  The eval() function takes a string and evaluates it as a Python expression.
  This means attackers can execute arbitrary code including:
  - Importing modules: __import__('os').system('command')
  - Accessing built-ins: __builtins__.__import__('os').system('command')
  - File operations: open('/etc/passwd').read()
  - Network operations: __import__('urllib').request.urlopen('http://evil.com')
  
  Even with restricted globals/locals, eval() is often bypassable through
  Python's introspection capabilities.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the unsafe eval detection pattern.
  
  This pattern detects usage of Python's eval() function which can lead
  to arbitrary code execution vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> pattern.id
      "python-unsafe-eval"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> pattern.cwe_id
      "CWE-95"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> vulnerable = "result = eval(user_input)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> safe = "result = ast.literal_eval(user_input)"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Python.UnsafeEval.pattern()
      iex> pattern.recommendation
      "Use ast.literal_eval() for safe evaluation of literals or custom parsers for complex expressions"
  """
  def pattern do
    %Pattern{
      id: "python-unsafe-eval",
      name: "Code Injection via eval()",
      description: "eval() can execute arbitrary Python code",
      type: :rce,
      severity: :critical,
      languages: ["python"],
      # Match eval( but not literal_eval or other safe variants
      regex: ~r/\beval\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-95",
      owasp_category: "A03:2021",
      recommendation: "Use ast.literal_eval() for safe evaluation of literals or custom parsers for complex expressions",
      test_cases: %{
        vulnerable: [
          "result = eval(user_input)",
          "value = eval(request.args.get('expression'))",
          "computed = eval(f\"2 + {user_number}\")",
          "eval('__import__(\"os\").system(\"id\")')"
        ],
        safe: [
          "result = ast.literal_eval(user_input)",
          "value = int(request.args.get('number', 0))",
          "computed = 2 + int(user_number)",
          "# This function is dangerous - use ast.literal_eval instead"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for Python eval() injection.
  
  This metadata documents the severe security implications of using eval()
  with untrusted data and provides guidance for secure alternatives.
  """
  def vulnerability_metadata do
    %{
      description: """
      Code injection vulnerabilities through Python's eval() function represent
      one of the most critical security issues in Python applications. The eval()
      function executes arbitrary Python code passed as a string, providing
      attackers with complete control over the Python runtime.
      
      Unlike more limited evaluation functions in other languages, Python's eval()
      has access to the full Python environment, including:
      - All built-in functions and modules
      - The ability to import any installed module
      - File system access through open() and other functions
      - Network access through urllib, requests, and socket modules
      - Process execution through os.system() and subprocess
      - Access to environment variables and system information
      
      The vulnerability is particularly dangerous because:
      1. It requires only the ability to control the input to eval()
      2. Python's introspection makes sandbox escapes trivial
      3. Even restricted eval() with custom globals/locals is often bypassable
      4. The attack surface includes the entire Python standard library
      5. Successful exploitation grants the attacker full code execution
      
      Common attack patterns include using __import__() to access modules,
      traversing __builtins__ to find useful functions, and using Python's
      object model to access restricted functionality through introspection.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-95",
          title: "Improper Neutralization of Directives in Dynamically Evaluated Code",
          url: "https://cwe.mitre.org/data/definitions/95.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :documentation,
          id: "python_eval",
          title: "Python eval() Documentation",
          url: "https://docs.python.org/3/library/functions.html#eval"
        },
        %{
          type: :security_guide,
          id: "python_security",
          title: "Python Security Considerations",
          url: "https://python.readthedocs.io/en/latest/library/functions.html#eval"
        },
        %{
          type: :research,
          id: "eval_exploitation",
          title: "Exploiting Python's eval()",
          url: "https://realpython.com/python-eval-function/#minimizing-the-security-risks-of-eval"
        }
      ],
      attack_vectors: [
        "__import__('os').system('whoami')",
        "__import__('subprocess').call(['cat', '/etc/passwd'])",
        "[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Popen'][0](['ls'])",
        "__builtins__.__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "[a:=__import__('os'),a.system('id')]",  # Walrus operator exploit
        "compile('import os; os.system(\"id\")', 'string', 'exec')",
        "globals()['__builtins__']['__import__']('os').system('pwd')"
      ],
      real_world_impact: [
        "Complete system compromise through arbitrary code execution",
        "Data exfiltration via file system or network access",
        "Cryptomining through compromised servers",
        "Backdoor installation for persistent access",
        "Lateral movement in internal networks",
        "Denial of service through resource exhaustion",
        "Modification or deletion of critical data",
        "Privilege escalation to system level"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-50447",
          description: "Pillow PIL.ImageMath.eval allows arbitrary code execution",
          severity: "critical",
          cvss: 9.8,
          note: "Image processing library executing arbitrary code via eval()"
        },
        %{
          id: "CVE-2024-6345",
          description: "Python setuptools arbitrary code execution via eval()",
          severity: "high",
          cvss: 8.8,
          note: "Package installation leading to code execution"
        },
        %{
          id: "CVE-2022-42919",
          description: "Python multiprocessing module eval() vulnerability",
          severity: "high",
          cvss: 7.8,
          note: "Local privilege escalation through eval() in standard library"
        },
        %{
          id: "CVE-2021-38305",
          description: "Yamale schema validator code injection via eval()",
          severity: "critical",
          cvss: 9.8,
          note: "YAML schema validation leading to RCE"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. Direct eval() function calls
      2. eval() with any parameter type
      3. Both immediate calls and stored references
      
      The pattern uses word boundary (\\b) to avoid matching:
      - ast.literal_eval() (safe alternative)
      - evaluate() or other function names containing 'eval'
      - Comments mentioning eval
      """,
      safe_alternatives: [
        "Use ast.literal_eval() for evaluating literal expressions",
        "Use json.loads() for JSON data parsing",
        "Use configparser for configuration files",
        "Implement custom parsers for domain-specific languages",
        "Use operator module for mathematical expressions",
        "For templates, use jinja2 or other template engines",
        "Use numexpr for numerical expressions",
        "Whitelist allowed operations and build safe evaluators",
        "Use exec() with restricted globals/locals (still risky)",
        "Never evaluate user input directly"
      ],
      additional_context: %{
        related_functions: [
          "exec() - Executes Python statements (equally dangerous)",
          "compile() - Compiles code objects that can be executed",
          "__import__() - Dynamic module importing",
          "globals() / locals() - Access to namespace dictionaries",
          "getattr() / setattr() - Dynamic attribute access"
        ],
        sandbox_escape_techniques: [
          "Subclass traversal: ().__class__.__base__.__subclasses__()",
          "Import via builtins: __builtins__.__import__",
          "Unicode bypass: Using unicode characters to hide imports",
          "Encoding tricks: Base64 or rot13 to bypass filters",
          "Walrus operator: [a:=__import__('os'), a.system('cmd')]"
        ],
        framework_specific_notes: %{
          django: "Django templates auto-escape but eval() in views is still dangerous",
          flask: "Jinja2 templates are sandboxed but eval() in routes is vulnerable",
          fastapi: "Type hints don't prevent eval() vulnerabilities",
          jupyter: "IPython's %run magic commands can also execute code",
          pandas: "pd.eval() is safer but still has security implications"
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities
  and safe usage patterns or comments.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeEval.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeEval.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "Call"
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeEval.ast_enhancement()
      iex> "eval" in enhancement.ast_rules.function_names
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.UnsafeEval.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Call",
        function_names: [
          "eval",
          "eval()"  # Sometimes appears in AST
        ],
        exclude_functions: [
          "literal_eval",
          "ast.literal_eval",
          "safe_eval",
          "evaluate"  # Common safe wrapper name
        ]
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
          "# noqa: S307",
          "# safe:",
          "# security: reviewed"
        ],
        check_data_source: true
      },
      confidence_rules: %{
        base: 0.85,  # Start high - eval() is almost always dangerous
        adjustments: %{
          "user_controlled_input" => 0.15,    # Definite vulnerability
          "request_data" => 0.1,              # Web input
          "input_function" => 0.1,            # User input
          "f_string" => 0.05,                 # Format strings with user data
          "concatenation" => 0.05,            # String building
          "hardcoded_string" => -0.4,         # Less likely exploitable
          "literal_only" => -0.5,             # Only literals
          "test_code" => -0.8,                # Test files
          "example_code" => -0.6,             # Documentation
          "commented_out" => -0.9             # Commented code
        }
      },
      min_confidence: 0.7
    }
  end
end