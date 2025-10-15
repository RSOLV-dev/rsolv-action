defmodule Rsolv.Security.Patterns.Python.PathTraversalOpen do
  @moduledoc """
  Path Traversal via Python open()

  Detects dangerous patterns like:
    open("/uploads/" + filename)
    open(f"/tmp/{user_file}")
    open("/data/%s" % request.file)

  Safe alternatives:
    safe_name = os.path.basename(filename)
    open(os.path.join("/uploads", safe_name))

    # Validate path stays within intended directory
    if os.path.commonpath([base_dir, requested_path]) == base_dir:
        open(requested_path)

  ## Vulnerability Details

  Path traversal (directory traversal) vulnerabilities occur when user-controlled
  input is used to construct file paths without proper validation. Attackers can
  use special sequences like "../" to navigate outside intended directories and
  access sensitive files anywhere on the filesystem.

  In Python, the open() function is commonly used for file operations. When the
  filename parameter includes user input without validation, attackers can:
  - Access configuration files (/etc/passwd, ~/.ssh/id_rsa)
  - Read application source code and secrets
  - Access log files containing sensitive data
  - Read system files to gather information for further attacks
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the path traversal via open() pattern.

  This pattern detects usage of open() with user-controlled input
  which can lead to unauthorized file access.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> pattern.id
      "python-path-traversal-open"

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> pattern.severity
      :high

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> vulnerable = ~S|open("/uploads/" + filename)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> safe = ~S|open("config.json")|
      iex> Regex.match?(pattern.regex, safe)
      false

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> fstring_vuln = ~S|open(f"/tmp/{user_file}")|
      iex> Regex.match?(pattern.regex, fstring_vuln)
      true

      iex> pattern = Rsolv.Security.Patterns.Python.PathTraversalOpen.pattern()
      iex> validated = ~S|safe_name = os.path.basename(filename); open(os.path.join("/uploads", safe_name))|
      iex> Regex.match?(pattern.regex, validated)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-path-traversal-open",
      name: "Path Traversal via open()",
      description: "Unsanitized file paths in open() can lead to directory traversal",
      type: :path_traversal,
      severity: :high,
      languages: ["python"],
      regex: ~r/
        # open() with string concatenation
        open\s*\(\s*[^)]*\+|
        # open() with f-string
        open\s*\(\s*f[\"'`].*\{|
        # open() with % formatting
        open\s*\(\s*[\"'][^\"']*%[sd]|
        # open() with .format()
        open\s*\(\s*[^)]*\.format|
        # Variable assignment followed by open
        (?:file_path|path|filename)\s*=.*(?:\+|f[\"']|%|\.format).*;\s*open\s*\(
      /x,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use os.path.join() safely",
      test_cases: %{
        vulnerable: [
          ~S|open("/uploads/" + filename)|,
          ~S|with open(f"/tmp/{user_file}") as f:|,
          ~S|open("/uploads/%s" % filename)|,
          ~S|open("/uploads/{}".format(filename))|,
          ~S|file_path = base_dir + "/" + user_input; open(file_path)|
        ],
        safe: [
          ~S|open("config.json")|,
          ~S|safe_name = os.path.basename(filename); open(os.path.join("/uploads", safe_name))|,
          ~S|if os.path.commonpath([base_dir, requested_path]) == base_dir: open(requested_path)|,
          ~S|from pathlib import Path; safe_path = Path(base_dir) / Path(filename).name|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal vulnerability through Python's open() function. When user input
      is used to construct file paths without proper validation, attackers can use
      directory traversal sequences (../, ..\\) to access files outside the intended
      directory.

      The vulnerability occurs when:
      1. User input is directly concatenated or interpolated into file paths
      2. No path validation or sanitization is performed
      3. The application has permissions to read files outside the web root
      4. Error messages may reveal file existence or contents

      Common attack patterns include:
      - ../../../etc/passwd - Access system files on Unix/Linux
      - ..\\..\\..\\windows\\system32\\config\\sam - Access Windows system files
      - ../../app/config.py - Access application configuration
      - %2e%2e%2f sequences - URL-encoded traversal
      - Double encoding: %252e%252e%252f
      - Unicode/UTF-8 encoding variations
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-22",
          title: "Improper Limitation of a Pathname to a Restricted Directory",
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
          id: "path_traversal_prevention",
          title: "Path Traversal and remediation in Python",
          url: "https://osintteam.blog/path-traversal-and-remediation-in-python-0b6e126b4746"
        },
        %{
          type: :research,
          id: "file_inclusion_kb",
          title: "Local file inclusion - Python",
          url: "https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-python-123"
        }
      ],
      attack_vectors: [
        "Basic traversal: filename = '../../../etc/passwd'",
        "Encoded traversal: filename = '..%2F..%2F..%2Fetc%2Fpasswd'",
        "Double encoding: filename = '..%252F..%252F..%252Fetc%252Fpasswd'",
        "Absolute path: filename = '/etc/passwd'",
        "UNC path (Windows): filename = '\\\\server\\share\\file'",
        "Null byte injection (older Python): filename = '../etc/passwd%00.jpg'"
      ],
      real_world_impact: [
        "Unauthorized access to sensitive files (configs, keys, passwords)",
        "Source code disclosure revealing business logic and vulnerabilities",
        "Information disclosure about system architecture and installed software",
        "Access to log files containing user data or system information",
        "Potential for privilege escalation by reading privileged files",
        "Compliance violations from unauthorized data access"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-55587",
          description: "Directory Traversal in python-libarchive ZipFile methods",
          severity: "high",
          cvss: 7.5,
          note: "Improper input sanitization allows path traversal via archive extraction"
        },
        %{
          id: "CVE-2024-49766",
          description: "Directory Traversal in werkzeug bypassing os.path.isabs()",
          severity: "high",
          cvss: 7.5,
          note: "Bypass allows accessing files outside intended directory via crafted paths"
        },
        %{
          id: "CVE-2024-23334",
          description: "Path traversal vulnerability in AioHTTP <= 3.9.1",
          severity: "high",
          cvss: 8.6,
          note: "Static file serving vulnerable to directory traversal attacks"
        },
        %{
          id: "CVE-2020-25032",
          description: "Directory Traversal in flask-cors",
          severity: "medium",
          cvss: 6.5,
          note: "Improper path validation allows reading arbitrary files"
        }
      ],
      detection_notes: """
      The pattern detects:
      1. open() function calls with dynamic path construction
      2. String concatenation with + operator
      3. F-string formatting with user variables
      4. % formatting and .format() methods
      5. Variable assignment followed by open()

      Key indicators:
      - The open() function call
      - Dynamic string construction for file paths
      - User-controlled variables in path construction
      """,
      safe_alternatives: [
        "Use os.path.basename() to extract just the filename",
        "Use os.path.join() with validated components",
        "Check paths with os.path.commonpath() to ensure they stay within bounds",
        "Use pathlib.Path for modern path handling with resolve()",
        "Implement an allowlist of permitted files/directories",
        "Use os.path.realpath() to resolve symbolic links",
        "Consider using a separate directory with restricted permissions"
      ],
      additional_context: %{
        common_mistakes: [
          "Only checking for ../ but not encoded versions",
          "Not handling absolute paths that bypass the base directory",
          "Trusting file extensions without validating the full path",
          "Not considering symbolic links that can escape directories",
          "Assuming os.path.join() alone provides security"
        ],
        secure_patterns: [
          "Always validate paths stay within intended directory",
          "Use os.path.realpath() to resolve the final path",
          "Implement strict input validation with allowlists",
          "Run file operations with minimal privileges",
          "Log all file access attempts for security monitoring",
          "Consider using a file storage service instead of filesystem"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual path traversal vulnerabilities
  and legitimate file operations with hardcoded paths.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Python.PathTraversalOpen.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Python.PathTraversalOpen.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Call",
        function: "open",
        argument_analysis: %{
          check_path_construction: true,
          detect_user_input: true,
          analyze_path_validation: true
        }
      },
      context_rules: %{
        dangerous_patterns: ["request.", "input(", "argv", "POST", "GET", "params", "query"],
        validation_functions: ["os.path.basename", "os.path.commonpath", "Path().resolve"],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        exclude_if_hardcoded: true,
        safe_if_validated: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_string_construction" => 0.2,
          "in_web_context" => 0.2,
          "in_test_code" => -1.0,
          "is_hardcoded_path" => -0.8,
          "has_path_validation" => -0.5,
          "uses_safe_join" => -0.4
        }
      },
      min_confidence: 0.7
    }
  end
end
