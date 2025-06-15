defmodule RsolvApi.Security.Patterns.Java.PathTraversalFile do
  @moduledoc """
  Path Traversal via File constructor pattern for Java code.
  
  Detects path traversal vulnerabilities where user input is concatenated with 
  file paths in the File constructor, potentially allowing access to files 
  outside the intended directory.
  
  ## Vulnerability Details
  
  Path traversal occurs when user-controlled input is used to construct file paths
  without proper validation. Attackers can use special characters like "../" to
  navigate to parent directories and access sensitive files outside the intended scope.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  String filename = request.getParameter("file");
  File file = new File("/var/uploads/" + filename);
  
  // Attack: filename = "../../etc/passwd"
  // Results in: /var/uploads/../../etc/passwd -> /etc/passwd
  // Attacker can read system password file
  ```
  
  ## References
  
  - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
  - OWASP A01:2021 - Broken Access Control
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-path-traversal-file",
      name: "Path Traversal via File",
      description: "Unsanitized file paths in File constructor can lead to directory traversal",
      type: :path_traversal,
      severity: :high,
      languages: ["java"],
      regex: [
        # Basic new File with concatenation - exclude comments
        ~r/^(?!.*\/\/).*new\s+File\s*\(\s*[^)]+\+[^)]+\)/m,
        # Variable assignment (String path = ...) followed by new File
        ~r/String\s+\w+\s*=\s*[^;]+\+[^;]+;[\s\S]*?new\s+File\s*\(\s*\w+\s*\)/,
        # File variable assignment with concatenation
        ~r/^(?!.*\/\/).*File\s+\w+\s*=\s*new\s+File\s*\([^)]+\+[^)]+\)/m,
        # Variable assignment without type prefix (e.g., file = new File...)
        ~r/^(?!.*\/\/).*\w+\s*=\s*new\s+File\s*\([^)]+\+[^)]+\)/m,
        # Method calls with concatenation inside File constructor
        ~r/new\s+File\s*\(\s*\w+(?:\.\w+\([^)]*\))+\s*\+/,
        # Return statement with new File and concatenation (handles nested parens)
        ~r/return\s+new\s+File\s*\(.*\+.*\)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use Paths.get() with canonical path validation",
      test_cases: %{
        vulnerable: [
          ~S|File file = new File(uploadDir + "/" + filename);|,
          ~S|new File(baseDir + File.separator + userPath);|
        ],
        safe: [
          ~S|Path path = Paths.get(uploadDir, filename).normalize();
if (path.startsWith(uploadDir)) {
    File file = path.toFile();
}|,
          ~S|String safeFilename = Paths.get(filename).getFileName().toString();
File file = new File(uploadDir, safeFilename);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal through the File constructor occurs when untrusted user input is used
      to construct file paths without proper validation. The Java File constructor doesn't
      restrict navigation through parent directories when given paths containing "../" or
      "..\\" sequences. This allows attackers to access files outside the intended directory.
      
      The vulnerability is particularly dangerous because:
      - File paths are often used to access sensitive configuration files
      - Attackers can read source code, database credentials, or system files
      - In write scenarios, attackers might overwrite critical files
      - The File API provides no built-in protection against path traversal
      
      Common vulnerable patterns include:
      - Direct concatenation: new File(baseDir + userInput)
      - Path separator joining: new File(dir + File.separator + file)
      - Multi-part construction: new File(path1 + "/" + path2 + "/" + filename)
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-22",
          title: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
          url: "https://cwe.mitre.org/data/definitions/22.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :research,
          id: "java_path_traversal",
          title: "Path Traversal Vulnerability in Java Applications",
          url: "https://www.invicti.com/white-papers/exploiting-path-traversal-vulnerabilities-java-web-applications-technical-paper/"
        },
        %{
          type: :research,
          id: "snyk_path_traversal",
          title: "Mitigating path traversal vulns in Java with Snyk Code",
          url: "https://snyk.io/blog/mitigating-path-traversal-java-snyk-code/"
        }
      ],
      attack_vectors: [
        "Basic traversal: filename = '../../../etc/passwd'",
        "Windows traversal: filename = '..\\..\\..\\windows\\system32\\config\\sam'",
        "URL encoded: filename = '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'",
        "Double encoding: filename = '%252e%252e%252f'",
        "Unicode encoding: filename = '\\u002e\\u002e\\u002f'",
        "Null byte injection: filename = '../../../etc/passwd%00.jpg'",
        "Absolute path: filename = '/etc/passwd' (if not validated)"
      ],
      real_world_impact: [
        "Read sensitive files like /etc/passwd or application configuration",
        "Access source code and discover other vulnerabilities",
        "Read database credentials or API keys from config files",
        "Download backup files or version control data (.git)",
        "In write scenarios, overwrite critical system or application files",
        "Bypass authentication by reading session files",
        "Information disclosure leading to further attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability included path traversal as attack vector",
          severity: "critical",
          cvss: 10.0,
          note: "Path traversal used to load malicious configuration files"
        },
        %{
          id: "CVE-2023-50164",
          description: "Apache Struts path traversal vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Allowed upload of malicious files to arbitrary locations"
        },
        %{
          id: "CVE-2022-24112",
          description: "Apache APISIX path traversal vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Allowed access to files outside the web root directory"
        }
      ],
      detection_notes: """
      This pattern detects File constructor usage with path concatenation:
      - new File() with string concatenation using + operator
      - Concatenation with File.separator
      - Method calls that return paths concatenated with user input
      - Variable assignments followed by File construction
      
      The pattern looks for the dangerous combination of File instantiation
      and string concatenation that could introduce user-controlled paths.
      """,
      safe_alternatives: [
        "Use Paths.get() with normalize() and validation: Paths.get(base, user).normalize()",
        "Validate paths start with expected directory after canonicalization",
        "Use getCanonicalPath() and verify the path stays within bounds",
        "Implement allowlist of permitted filenames or patterns",
        "Use numeric IDs mapped to filenames instead of user-provided names",
        "Utilize Java NIO.2 APIs with better path handling",
        "Reject any input containing path traversal sequences",
        "Use a secure file storage service with access controls"
      ],
      additional_context: %{
        common_mistakes: [
          "Only blocking '../' but not '..\\' (Windows paths)",
          "Not handling URL-encoded or Unicode variants",
          "Checking for '../' after concatenation (too late)",
          "Using blacklist instead of whitelist validation",
          "Not considering absolute paths as attack vector"
        ],
        secure_patterns: [
          "Always resolve to canonical path before validation",
          "Ensure resolved path starts with expected base directory",
          "Use Paths.get() instead of File constructor when possible",
          "Validate filenames match expected patterns",
          "Store files with generated names, map to user-friendly names"
        ],
        file_api_notes: [
          "File constructor doesn't validate or restrict paths",
          "File.separator is OS-dependent (/ or \\)",
          "getCanonicalPath() resolves ../ references",
          "toPath() can convert File to more secure Path API"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual path traversal vulnerabilities
  and safe file operations.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.PathTraversalFile.ast_enhancement()
      iex> Map.keys(enhancement)
      [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.PathTraversalFile.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.PathTraversalFile.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "NewExpression"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "NewExpression",
        file_analysis: %{
          check_constructor_name: true,
          constructor_patterns: ["File", "java.io.File"],
          check_argument_concatenation: true,
          check_argument_count: true
        },
        concatenation_analysis: %{
          check_operators: true,
          dangerous_operators: ["+", "concat", "StringBuilder.append", "String.format"],
          check_method_calls: true,
          method_patterns: ["getParameter", "getHeader", "getCookie", "getPathInfo"]
        },
        path_analysis: %{
          check_separators: true,
          separator_patterns: ["File.separator", "/", "\\\\"],
          check_traversal_sequences: true,
          dangerous_sequences: ["..", "..\\", "%2e%2e", "..%2f", "..%5c"]
        },
        variable_analysis: %{
          check_user_input_flow: true,
          input_methods: [
            "getParameter", "getHeader", "getQueryString",
            "getInputStream", "getReader", "getPathInfo",
            "getRequestURI", "getServletPath"
          ],
          check_variable_usage: true
        }
      },
      context_rules: %{
        check_path_validation: true,
        safe_patterns: [
          "getCanonicalPath() validation",
          "Path normalization with startsWith check",
          "Whitelist validation",
          "Generated filename usage"
        ],
        validation_methods: [
          "getCanonicalPath",
          "normalize",
          "startsWith",
          "matches",
          "isValidFilename"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_constant_paths: true,
        safe_if_no_user_input: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_string_concatenation" => 0.3,
          "has_user_input_method" => 0.3,
          "uses_file_separator" => 0.2,
          "has_path_validation" => -0.6,
          "uses_canonical_path" => -0.5,
          "is_constant_path" => -0.8,
          "in_test_code" => -0.9,
          "has_whitelist_check" => -0.7
        }
      },
      min_confidence: 0.7
    }
  end
end