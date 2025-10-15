defmodule Rsolv.Security.Patterns.Java.PathTraversalFileinputstream do
  @moduledoc """
  Path Traversal via FileInputStream pattern for Java code.

  Detects path traversal vulnerabilities where user input is used to construct file paths
  for FileInputStream operations, potentially allowing access to files outside the
  intended directory.

  ## Vulnerability Details

  FileInputStream path traversal occurs when untrusted user input is used to construct
  file paths without proper validation. Unlike the File constructor which is primarily
  used for file metadata operations, FileInputStream directly opens files for reading,
  making successful path traversal attacks immediately impactful for data theft.

  ### Attack Example

  ```java
  // Vulnerable code
  String filename = request.getParameter("file");
  FileInputStream fis = new FileInputStream("/var/uploads/" + filename);

  // Attack: filename = "../../etc/passwd"
  // Results in: /var/uploads/../../etc/passwd -> /etc/passwd
  // Attacker can read system password file directly
  ```

  ## References

  - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
  - OWASP A01:2021 - Broken Access Control
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "java-path-traversal-fileinputstream",
      name: "Path Traversal via FileInputStream",
      description:
        "Unsanitized file paths in FileInputStream constructor can lead to directory traversal",
      type: :path_traversal,
      severity: :high,
      languages: ["java"],
      regex: [
        # Basic new FileInputStream with concatenation - exclude comments
        ~r/^(?!.*\/\/).*new\s+FileInputStream\s*\(\s*[^)]+\+[^)]+\)/m,
        # Variable assignment (String path = ...) followed by new FileInputStream
        ~r/String\s+\w+\s*=\s*[^;]+\+[^;]+;[\s\S]*?new\s+FileInputStream\s*\(\s*\w+\s*\)/,
        # FileInputStream variable assignment with concatenation
        ~r/^(?!.*\/\/).*FileInputStream\s+\w+\s*=\s*new\s+FileInputStream\s*\([^)]+\+[^)]+\)/m,
        # Variable assignment without type prefix (e.g., fis = new FileInputStream...)
        ~r/^(?!.*\/\/).*\w+\s*=\s*new\s+FileInputStream\s*\([^)]+\+[^)]+\)/m,
        # Method calls with concatenation inside FileInputStream constructor
        ~r/new\s+FileInputStream\s*\(\s*\w+(?:\.\w+\([^)]*\))+\s*\+/,
        # Try-with-resources pattern with concatenation
        ~r/try\s*\(\s*FileInputStream\s+\w+\s*=\s*new\s+FileInputStream\s*\([^)]+\+[^)]+\)/,
        # Return statement with new FileInputStream and concatenation
        ~r/return\s+new\s+FileInputStream\s*\(.*\+.*\)/
      ],
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation:
        "Validate and sanitize file paths, use Files.newInputStream() with proper validation",
      test_cases: %{
        vulnerable: [
          ~S|FileInputStream fis = new FileInputStream(baseDir + filename);|,
          ~S|new FileInputStream("/uploads/" + userFile);|
        ],
        safe: [
          ~S|Path path = Paths.get(uploadDir, filename).normalize();
if (path.startsWith(uploadDir)) {
    InputStream is = Files.newInputStream(path);
}|,
          ~S|String safeFilename = Paths.get(filename).getFileName().toString();
FileInputStream fis = new FileInputStream(new File(uploadDir, safeFilename));|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal through FileInputStream occurs when untrusted user input is used
      to construct file paths without proper validation. The FileInputStream constructor
      directly opens files for reading, making this vulnerability particularly dangerous
      as successful attacks immediately provide access to sensitive file contents.

      The vulnerability is especially concerning because:
      - FileInputStream provides direct file access without protection mechanisms
      - Successful attacks can immediately read sensitive files like passwords, configs
      - Unlike file metadata operations, this directly exposes file contents to attackers
      - The stream can be used to read entire files, enabling large-scale data theft

      Common vulnerable patterns include:
      - Direct concatenation: new FileInputStream(baseDir + userInput)
      - Path separator joining: new FileInputStream(dir + File.separator + file)
      - Try-with-resources: try (FileInputStream fis = new FileInputStream(path + file))
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
          id: "java_fileinputstream_security",
          title: "Preventing Path Traversal Vulnerabilities in Java Applications",
          url:
            "https://medium.com/@fabionoth/real-world-example-preventing-path-traversal-vulnerabilities-in-java-applications-4d0f911b232f"
        },
        %{
          type: :research,
          id: "fortify_path_manipulation",
          title: "Fortify Issues: Path Manipulation",
          url: "https://matam-kirankumar.medium.com/fortify-issues-path-manipulation-3ac42c1d1e9a"
        },
        %{
          type: :research,
          id: "path_manipulation_mitigation",
          title: "How to Fix Path Manipulation: Understanding and Mitigating Vulnerabilities",
          url: "https://content.mobb.ai/blog/how-to-fix-path-manipulation"
        }
      ],
      attack_vectors: [
        "Basic traversal: filename = '../../../etc/passwd'",
        "Windows traversal: filename = '..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam'",
        "URL encoded: filename = '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'",
        "Double encoding: filename = '%252e%252e%252f'",
        "Unicode encoding: filename = '\\\\u002e\\\\u002e\\\\u002f'",
        "Null byte injection: filename = '../../../etc/passwd%00.jpg'",
        "Absolute path: filename = '/etc/passwd' (if not validated)",
        "Mixed separators: filename = '../..\\\\../etc/passwd' (Windows)"
      ],
      real_world_impact: [
        "Direct access to sensitive files like /etc/passwd or application configuration",
        "Read database credentials, API keys, and other secrets from config files",
        "Access source code and discover additional vulnerabilities",
        "Download backup files, logs, or version control data (.git)",
        "Read session files or temporary files containing sensitive data",
        "Access user-uploaded files from other users (privacy violation)",
        "Information disclosure leading to lateral movement and privilege escalation"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-53677",
          description: "Apache Struts path traversal vulnerability in file upload mechanism",
          severity: "critical",
          cvss: 9.1,
          note:
            "Path traversal via file upload parameters allowing RCE through malicious file upload"
        },
        %{
          id: "CVE-2024-38816",
          description:
            "Spring Framework path traversal vulnerability in static resource handling",
          severity: "high",
          cvss: 7.5,
          note:
            "Affected WebMvc.fn and WebFlux.fn frameworks allowing access to files outside web root"
        },
        %{
          id: "CVE-2024-38819",
          description: "Path traversal vulnerability in Spring functional web frameworks",
          severity: "high",
          cvss: 7.5,
          note: "Applications serving static resources vulnerable to path traversal attacks"
        }
      ],
      detection_notes: """
      This pattern detects FileInputStream constructor usage with path concatenation:
      - new FileInputStream() with string concatenation using + operator
      - Concatenation with File.separator
      - Method calls that return paths concatenated with user input
      - Variable assignments followed by FileInputStream construction
      - Try-with-resources patterns with concatenated paths

      The pattern looks for the dangerous combination of FileInputStream instantiation
      and string concatenation that could introduce user-controlled paths.
      """,
      safe_alternatives: [
        "Use Files.newInputStream() with Path validation: Files.newInputStream(Paths.get(base, user).normalize())",
        "Validate paths start with expected directory after canonicalization",
        "Use getCanonicalPath() and verify the path stays within bounds",
        "Implement allowlist of permitted filenames or patterns",
        "Use numeric IDs mapped to filenames instead of user-provided names",
        "Utilize Java NIO.2 APIs with better path handling and security",
        "Reject any input containing path traversal sequences",
        "Use a secure file storage service with proper access controls"
      ],
      additional_context: %{
        common_mistakes: [
          "Only blocking '../' but not '..\\\\' (Windows paths)",
          "Not handling URL-encoded or Unicode variants of traversal sequences",
          "Checking for '../' after concatenation (validation too late)",
          "Using blacklist instead of whitelist validation approach",
          "Not considering absolute paths as attack vector",
          "Assuming FileInputStream is safer than File constructor (it's not)"
        ],
        secure_patterns: [
          "Always resolve to canonical path before validation",
          "Ensure resolved path starts with expected base directory",
          "Use Files.newInputStream() with Path API instead of FileInputStream",
          "Validate filenames match expected patterns before file operations",
          "Store files with generated names, map to user-friendly names",
          "Use try-with-resources for automatic resource management"
        ],
        fileinputstream_notes: [
          "FileInputStream directly opens files for reading (immediate impact)",
          "Unlike File constructor, this provides direct access to file contents",
          "Consider using Files.newInputStream() for better security",
          "BufferedInputStream can wrap FileInputStream for better performance",
          "Always use try-with-resources for proper resource cleanup"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual path traversal vulnerabilities
  and safe FileInputStream operations.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Java.PathTraversalFileinputstream.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.PathTraversalFileinputstream.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Java.PathTraversalFileinputstream.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "NewExpression"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "NewExpression",
        fileinputstream_analysis: %{
          check_constructor_name: true,
          constructor_patterns: ["FileInputStream", "java.io.FileInputStream"],
          check_argument_concatenation: true,
          check_argument_count: true
        },
        concatenation_analysis: %{
          check_operators: true,
          dangerous_operators: ["+", "concat", "StringBuilder.append", "String.format"],
          check_method_calls: true,
          method_patterns: [
            "getParameter",
            "getHeader",
            "getCookie",
            "getPathInfo",
            "getRequestURI"
          ]
        },
        path_analysis: %{
          check_separators: true,
          separator_patterns: ["File.separator", "/", "\\\\"],
          check_traversal_sequences: true,
          dangerous_sequences: ["..", "..\\\\ ", "%2e%2e", "..%2f", "..%5c"]
        },
        variable_analysis: %{
          check_user_input_flow: true,
          input_methods: [
            "getParameter",
            "getHeader",
            "getQueryString",
            "getInputStream",
            "getReader",
            "getPathInfo",
            "getRequestURI",
            "getServletPath",
            "readLine"
          ],
          check_variable_usage: true
        },
        resource_management: %{
          check_try_with_resources: true,
          check_stream_usage: true,
          check_resource_cleanup: true
        }
      },
      context_rules: %{
        check_path_validation: true,
        safe_patterns: [
          "getCanonicalPath() validation",
          "Path normalization with startsWith check",
          "Whitelist validation",
          "Generated filename usage",
          "Files.newInputStream with Path validation"
        ],
        validation_methods: [
          "getCanonicalPath",
          "normalize",
          "startsWith",
          "matches",
          "isValidFilename",
          "Files.newInputStream"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_constant_paths: true,
        safe_if_no_user_input: true,
        check_nio_usage: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_string_concatenation" => 0.3,
          "has_user_input_method" => 0.3,
          "uses_file_separator" => 0.2,
          "is_try_with_resources" => 0.1,
          "has_path_validation" => -0.6,
          "uses_canonical_path" => -0.5,
          "uses_files_newinputstream" => -0.6,
          "is_constant_path" => -0.8,
          "in_test_code" => -0.9,
          "has_whitelist_check" => -0.7
        }
      },
      min_confidence: 0.7
    }
  end
end
