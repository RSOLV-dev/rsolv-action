defmodule Rsolv.Security.Patterns.Javascript.PathTraversalJoin do
  @moduledoc """
  Path Traversal via path.join in JavaScript/Node.js

  Detects dangerous patterns like:
    path.join("/uploads", req.params.filename)
    const file = path.join(baseDir, userInput)
    fs.readFile(path.join("./data", req.query.file))
    
  Safe alternatives:
    const safePath = path.join("/uploads", path.basename(filename))
    if (resolvedPath.startsWith(baseDir)) { /* safe */ }
    const file = path.join(baseDir, sanitize(userInput))
    
  The path.join() function in Node.js combines path segments using the platform-specific
  separator, but it does not validate that the resulting path stays within intended
  boundaries. Attackers can use relative path sequences like "../" to escape the
  intended directory and access files anywhere on the filesystem.

  ## Vulnerability Details

  The path.join() method concatenates path segments but performs minimal validation.
  It normalizes the path (removing redundant separators and resolving "." and "..")
  but does not prevent directory traversal attacks. When user input contains "../"
  sequences, the resulting path can escape the intended base directory.

  ### Attack Example
  ```javascript
  // Vulnerable code
  const filename = req.params.file; // User provides: "../../../etc/passwd"
  const filepath = path.join("/var/www/uploads", filename);
  // Results in: "/etc/passwd" (escaped uploads directory)
  fs.readFile(filepath, (err, data) => {
    res.send(data); // Leaks sensitive system files
  });
  ```

  ### Recent Vulnerability Context (2024)

  Node.js has seen multiple path traversal CVEs in recent years, including
  CVE-2024-21896 and CVE-2023-39331, demonstrating that even built-in path
  handling functions can have vulnerabilities. The research shows an 85% 
  increase in closed-source path traversal incidents in 2024 alone.
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  def pattern do
    %Pattern{
      id: "js-path-traversal-join",
      name: "Path Traversal via path.join",
      description: "Using path.join with user input can lead to directory traversal",
      type: :path_traversal,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex:
        ~r/(?:path\.)?join\s*\([^)]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user[A-Z]|userInput|input(?!.*sanitize)|data)/i,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation:
        "Validate and sanitize file paths. Use path.resolve and check if result is within expected directory.",
      test_cases: %{
        vulnerable: [
          ~S|path.join("/uploads", req.params.filename)|,
          ~S|const file = path.join(baseDir, userInput)|,
          ~S|fs.readFile(path.join("./data", req.query.file))|,
          ~S|const fullPath = path.join(rootDir, request.body.path)|,
          ~S|path.join(staticDir, params.file)|,
          ~S|join("/tmp", userData)|
        ],
        safe: [
          ~S|const safePath = path.join("/uploads", path.basename(filename))|,
          ~S|if (resolvedPath.startsWith(baseDir)) { /* safe */ }|,
          ~S|const file = path.join(baseDir, sanitize(userInput))|,
          ~S|path.join("/static", "images", "logo.png")|,
          ~S|const configPath = path.join(__dirname, "config.json")|,
          ~S|join(baseDir, validatedPath)|
        ]
      }
    }
  end

  @doc """
  Comprehensive vulnerability metadata for path traversal via path.join.

  This metadata documents the specific risks of using path.join() with user input,
  including recent CVE examples and comprehensive attack vectors discovered in 2024 research.
  """
  def vulnerability_metadata do
    %{
      description: """
      Path traversal via path.join() occurs when user input is passed directly to the 
      path.join() function without proper validation. While path.join() normalizes paths 
      by resolving "." and ".." segments, it does not prevent directory traversal attacks. 
      Attackers can use relative path sequences like "../" to escape the intended base 
      directory and access files anywhere on the filesystem.

      The vulnerability is particularly dangerous because path.join() is often perceived 
      as "safe" due to its path normalization features. However, normalization alone is 
      insufficient to prevent traversal attacks. The function will happily resolve 
      "../../../etc/passwd" relative to any base directory, potentially exposing 
      sensitive system files.

      Recent research (2024) shows an 85% increase in path traversal incidents, with 
      attackers increasingly targeting Node.js applications due to the prevalence of 
      file serving functionality in web applications.
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
          id: "github_scale_detection",
          title: "Eradicating the Unseen: Automated Path Traversal Detection at GitHub Scale",
          url: "https://arxiv.org/abs/2401.09512"
        },
        %{
          type: :research,
          id: "nodejs_path_security",
          title: "Node.js Path Traversal Vulnerability Research",
          url: "https://blog.securelayer7.net/understanding-path-traversal-vulnerability/"
        },
        %{
          type: :nist,
          id: "SP_800-53",
          title: "NIST Security Controls for Path Validation",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        }
      ],
      attack_vectors: [
        "Relative path sequences: userInput = '../../../etc/passwd'",
        "Multiple traversal attempts: userInput = '../../../../usr/local/bin/sensitive'",
        "Mixed separators: userInput = '..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam'",
        "Encoded traversal: userInput = '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'",
        "Double encoding: userInput = '%252e%252e%255c%252e%252e%255c'",
        "Null byte injection: userInput = '../../../etc/passwd%00.txt'",
        "Absolute path override: userInput = '/etc/passwd'",
        "Windows drive access: userInput = 'C:\\\\Windows\\\\System32\\\\config\\\\SAM'"
      ],
      real_world_impact: [
        "Confidentiality breach: Access to configuration files containing database credentials",
        "System compromise: Reading /etc/passwd, /etc/shadow for privilege escalation",
        "Source code disclosure: Accessing application source files outside web root",
        "Log file exposure: Reading application logs containing sensitive user data",
        "Backup file access: Retrieving database dumps or configuration backups",
        "SSL certificate theft: Accessing private keys and certificates",
        "Application secrets: Reading .env files or configuration containing API keys",
        "Cross-user data access: Reading files belonging to other application users"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-21896",
          description:
            "Node.js path traversal via Buffer.prototype.utf8Write manipulation affecting path.resolve()",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates that even Node.js core path functions can have vulnerabilities"
        },
        %{
          id: "CVE-2023-39331",
          description:
            "Path traversal vulnerability from overwriting built-in Node.js utility functions",
          severity: "medium",
          cvss: 6.5,
          note: "Shows how attackers can manipulate path normalization behavior"
        },
        %{
          id: "CVE-2023-26111",
          description: "Directory traversal in node-static package with no available fix",
          severity: "high",
          cvss: 7.5,
          note: "Popular npm package with persistent path traversal vulnerability"
        },
        %{
          id: "CVE-2023-32004",
          description: "Buffer handling flaw in Node.js filesystem APIs causing path traversal",
          severity: "medium",
          cvss: 5.3,
          note: "Affects fs.readFile and related functions when combined with path.join"
        }
      ],
      detection_notes: """
      This pattern detects calls to path.join() where user input appears to be passed
      as one of the path segments. Key detection indicators:

      1. Function calls to path.join() with multiple arguments
      2. Second or later arguments that match user input patterns:
         - req.params.*, req.query.*, req.body.*
         - request.* variants
         - Variables named userInput, userData, input, etc.
      3. Exclusion of obviously sanitized inputs (input.*sanitize patterns)

      The regex specifically looks for path.join calls with comma-separated arguments
      where subsequent arguments match common user input patterns. This approach
      minimizes false positives while catching the most common vulnerable patterns.

      False positives may occur when:
      - Static string literals are used that happen to match variable patterns
      - Input is properly validated before reaching path.join()
      - The detected variable is not actually user-controlled
      """,
      safe_alternatives: [
        "Use path.basename() to extract only the filename: path.join(baseDir, path.basename(userInput))",
        "Validate paths stay within bounds: const resolved = path.resolve(baseDir, userInput); if (!resolved.startsWith(baseDir)) throw new Error('Invalid path')",
        "Use allowlist validation: if (!allowedFiles.includes(userInput)) throw new Error('File not allowed')",
        "Sanitize input with path normalization: const safe = path.normalize(userInput).replace(/^(\\.\\.[\\/\\\\])+/, '')",
        "Use Express.js static middleware: app.use('/uploads', express.static('uploads', {dotfiles: 'deny'}))",
        "Implement proper access controls: Check user permissions before file access",
        "Use sandboxed file serving: Serve files through a proxy that enforces directory restrictions"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming path.join() provides security against traversal attacks",
          "Only checking for '../' without considering encoded variants",
          "Using path.normalize() alone without boundary validation",
          "Trusting client-side path validation without server-side checks",
          "Not considering Windows-style path separators in cross-platform apps",
          "Overlooking null byte injection in older Node.js versions"
        ],
        secure_patterns: [
          "Always validate resolved paths against intended base directory",
          "Use path.resolve() and startsWith() for boundary checking",
          "Implement allowlist-based file access where possible",
          "Consider using dedicated file serving libraries with built-in protections",
          "Log and monitor for path traversal attempts in security monitoring",
          "Implement proper error handling that doesn't leak path information"
        ],
        performance_considerations: [
          "Path validation adds minimal overhead compared to file I/O operations",
          "Cache allowlist validation results for frequently accessed files",
          "Consider async validation for non-blocking path checking",
          "Use filesystem permissions as defense-in-depth, not primary security"
        ]
      }
    }
  end

  @doc """
  Check if this pattern applies to a file based on its path and content.

  Applies to JavaScript/TypeScript files or any file containing path operations.
  """
  def applies_to_file?(file_path, content) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) ->
        true

      # If content is provided, check for path operations
      content != nil ->
        String.contains?(content, "path.join") || String.contains?(content, ".join(")

      # Default
      true ->
        false
    end
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual path traversal vulnerabilities and:
  - path.join() with validated/sanitized input
  - Static paths or hardcoded values
  - Paths that are checked against a base directory after join
  - Use of path.basename() or similar sanitization functions
  - Sandboxed environments (Docker, chroot)

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.PathTraversalJoin.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.PathTraversalJoin.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.PathTraversalJoin.ast_enhancement()
      iex> enhancement.ast_rules.callee.property
      "join"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.PathTraversalJoin.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.PathTraversalJoin.ast_enhancement()
      iex> "uses_path_validation" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          object: "path",
          property: "join",
          alternatives: ["resolve", "normalize"]
        },
        # Arguments must contain user input
        argument_analysis: %{
          has_user_controlled_path: true,
          not_validated: true,
          # ../ or ..\
          contains_traversal_sequences: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/build/],
        # Path validation before join
        exclude_if_validated: true,
        # chroot, Docker, etc.
        exclude_if_sandboxed: true,
        # Checked against allowed paths
        exclude_if_allowlist_checked: true,
        # path.normalize() + startsWith check
        exclude_if_normalized_and_checked: true,
        # These are safer
        safe_path_functions: ["path.basename", "path.extname"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "direct_user_path_to_join" => 0.5,
          "url_param_to_filesystem" => 0.4,
          "has_dot_dot_sequences" => 0.3,
          "uses_path_validation" => -0.8,
          # Checks if within allowed directory
          "checks_resolved_path" => -0.7,
          # path.basename() removes directory
          "uses_basename_only" => -0.9,
          # Less risky with fixed base
          "static_base_path" => -0.3,
          # Config files often use path.join safely
          "in_config_loader" => -0.6
        }
      },
      min_confidence: 0.8
    }
  end
end
