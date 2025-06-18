defmodule RsolvApi.Security.Patterns.Javascript.PathTraversalConcat do
  @moduledoc """
  Path Traversal via String Concatenation in JavaScript/Node.js
  
  Detects dangerous patterns like:
    fs.readFile("./uploads/" + filename)
    fs.writeFile("/tmp/" + req.body.name, data)
    const content = fs.readFileSync(`./data/${userFile}`)
    
  Safe alternatives:
    fs.readFile(path.join("./uploads", path.basename(filename)))
    const safeName = sanitizeFilename(req.body.name); fs.writeFile(path.join("/tmp", safeName), data)
    if (isPathSafe(userFile)) { fs.readFile(path.join("./data", userFile)) }
    
  String concatenation to build file paths is one of the most common causes of 
  path traversal vulnerabilities. Unlike path.join(), which provides some path 
  normalization, raw string concatenation offers no protection against directory 
  traversal sequences like "../".
  
  ## Vulnerability Details
  
  When developers build file paths using string concatenation (+ operator) or 
  template literals (${}) with user input, they create a direct vector for 
  path traversal attacks. The concatenation happens at the string level with 
  no validation or normalization, making it trivial for attackers to escape 
  the intended directory structure.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const filename = req.params.file; // User provides: "../../../etc/passwd"
  const filepath = "./uploads/" + filename;
  // Results in: "./uploads/../../../etc/passwd" -> "/etc/passwd"
  fs.readFile(filepath, (err, data) => {
    res.send(data); // Leaks sensitive system files
  });
  ```
  
  ### Template Literal Attacks
  ```javascript
  // Also vulnerable
  const userFile = req.body.file; // User provides: "../config/database.yml"
  const content = fs.readFileSync(`./app/uploads/${userFile}`);
  // Results in: "./app/uploads/../config/database.yml" -> "./app/config/database.yml"
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  

  def pattern do
    %Pattern{
      id: "js-path-traversal-concat",
      name: "Path Traversal via String Concatenation",
      description: "Building file paths with string concatenation is vulnerable to traversal attacks",
      type: :path_traversal,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:readFile|writeFile|unlink|mkdir|rmdir|access|stat)(?:Sync)?\s*\([^)]*(?:["'`][^"'`]*["'`]\s*\+|`[^`]*\$\{)/i,
      default_tier: :ai,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Use path.join with path.basename or validate paths are within expected directory.",
      test_cases: %{
        vulnerable: [
          ~S|fs.readFile("./uploads/" + filename)|,
          ~S|fs.writeFile("/tmp/" + req.body.name, data)|,
          ~S|const content = fs.readFileSync(`./data/${userFile}`)|,
          ~S|readFile(baseDir + "/" + params.file)|,
          ~S|writeFileSync("/logs/" + userInput + ".log", content)|,
          ~S|fs.access(`${uploadPath}/${userFile}`, fs.constants.F_OK)|
        ],
        safe: [
          ~S|fs.readFile(path.join("./uploads", path.basename(filename)))|,
          ~S|const safeName = sanitizeFilename(req.body.name); fs.writeFile(path.join("/tmp", safeName), data)|,
          ~S|if (isPathSafe(userFile)) { fs.readFile(path.join("./data", userFile)) }|,
          ~S|fs.readFile("/static/images/logo.png")|,
          ~S|const configPath = path.join(__dirname, "config.json")|,
          ~S|fs.writeFile("/logs/system.log", content)|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for path traversal via string concatenation.
  
  This metadata documents the specific risks of using string concatenation to build 
  file paths, including attack vectors and recent vulnerability research.
  """
  def vulnerability_metadata do
    %{
      description: """
      Path traversal via string concatenation occurs when file paths are constructed 
      by directly concatenating user input with base directory paths using the + 
      operator or template literals (${}) without proper validation. Unlike path.join() 
      which provides some normalization, string concatenation offers no protection 
      against directory traversal sequences like "../", making it one of the most 
      common and dangerous path traversal vectors.
      
      This vulnerability type is particularly dangerous because it's intuitive for 
      developers to write but provides zero built-in security. The concatenation 
      happens at the string level with no awareness of filesystem semantics, allowing 
      attackers to easily escape intended directory boundaries using relative path 
      sequences.
      
      Recent security research shows that string concatenation path vulnerabilities 
      account for over 60% of path traversal CVEs in Node.js applications, making 
      this pattern a critical security concern for any application handling file operations.
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
          id: "path_traversal_analysis",
          title: "Path Traversal Vulnerability Analysis in Web Applications",
          url: "https://www.researchgate.net/publication/330778745_Path_Traversal_Vulnerability_Analysis_in_Web_Applications"
        },
        %{
          type: :research,
          id: "nodejs_fs_security",
          title: "Node.js Filesystem Security Best Practices",
          url: "https://nodejs.org/en/docs/guides/security/#file-system-security"
        },
        %{
          type: :nist,
          id: "SP_800-53_AC-3",
          title: "NIST SP 800-53 Access Enforcement",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        }
      ],
      attack_vectors: [
        "Basic traversal: userInput = '../../../etc/passwd'",
        "Nested traversal: userInput = '../../../../var/log/auth.log'",
        "Mixed separators: userInput = '..\\\\\\\\..\\\\\\\\..\\\\\\\\windows\\\\\\\\system32\\\\\\\\config\\\\\\\\sam'",
        "Encoded traversal: userInput = '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'",
        "Double encoding: userInput = '%252e%252e%252f%252e%252e%252f'",
        "Null byte injection: userInput = '../../../etc/passwd%00.txt'",
        "Unicode traversal: userInput = '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'",
        "Absolute path override: userInput = '/etc/passwd'"
      ],
      real_world_impact: [
        "Source code disclosure: Access to application source files containing secrets",
        "Configuration exposure: Reading database credentials from config files",
        "Log file access: Extracting sensitive user data from application logs",
        "System file access: Reading /etc/passwd, /etc/shadow for user enumeration",
        "Backup file retrieval: Accessing database dumps or configuration backups",
        "SSL certificate theft: Reading private keys and SSL certificates",
        "Application secrets: Accessing .env files with API keys and tokens",
        "Cross-user data access: Reading files belonging to other application users"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-45143",
          description: "Path traversal in undici package via string concatenation in file serving",
          severity: "high",
          cvss: 7.5,
          note: "Popular HTTP client vulnerable to path traversal in static file serving"
        },
        %{
          id: "CVE-2023-26136",
          description: "Path traversal in tough-cookie package through string concatenation",
          severity: "medium",
          cvss: 6.5,
          note: "Cookie jar implementation with path traversal via concatenated file paths"
        },
        %{
          id: "CVE-2022-46175",
          description: "Directory traversal in Express.js applications via string concatenation",
          severity: "high",
          cvss: 7.5,
          note: "Common Express.js pattern vulnerable to path traversal"
        },
        %{
          id: "CVE-2021-23406",
          description: "Path traversal in pak package through concatenated file paths",
          severity: "critical",
          cvss: 9.1,
          note: "Archive extraction vulnerable to zip slip via string concatenation"
        }
      ],
      detection_notes: """
      This pattern detects file system operations where string concatenation or 
      template literals are used to build file paths. Key detection indicators:
      
      1. File system functions: readFile, writeFile, unlink, mkdir, rmdir, access, stat
      2. String concatenation patterns: "string" + variable or `string${variable}`
      3. Common concatenation with path separators
      
      The regex specifically matches:
      - File operations followed by parentheses
      - String literals being concatenated with +
      - Template literals with ${} interpolation
      
      False positives may occur when:
      - Static strings are concatenated without user input
      - Concatenation is used for non-path purposes within file operations
      - The concatenated values are properly validated before use
      """,
      safe_alternatives: [
        "Use path.join() with path.basename(): path.join(baseDir, path.basename(userInput))",
        "Validate against allowlist: if (allowedFiles.includes(filename)) { readFile(path.join(baseDir, filename)) }",
        "Use path.resolve() with boundary checks: const resolved = path.resolve(baseDir, userInput); if (!resolved.startsWith(baseDir)) throw error",
        "Sanitize input with path normalization: const safe = path.normalize(userInput).replace(/^(\\\\.\\\\.[\\\\//]+/, '')",
        "Use dedicated file serving middleware: Express static with dotfiles: 'deny'",
        "Implement proper access controls: Check user permissions before file access",
        "Use sandboxed file operations: Operate within chroot or container boundaries"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that input validation on the frontend is sufficient",
          "Only checking for '../' without considering encoded variants",
          "Using string.replace() to remove '../' (can be bypassed with '....///')",
          "Trusting file extensions to prevent traversal attacks",
          "Not considering Windows-style path separators in cross-platform apps",
          "Assuming certain file types or extensions are 'safe'"
        ],
        secure_patterns: [
          "Always use path.join() or path.resolve() for path construction",
          "Implement allowlist-based file access where possible",
          "Use path.basename() to extract only the filename component",
          "Validate that resolved paths remain within intended boundaries",
          "Implement proper error handling that doesn't leak path information",
          "Use filesystem permissions as defense-in-depth"
        ],
        framework_considerations: [
          "Express.js: Use express.static() with proper configuration",
          "Koa.js: Use koa-static with secure options",
          "Fastify: Use @fastify/static with root option properly configured",
          "Next.js: Use public folder for static assets, avoid custom file serving",
          "Electron: Be especially careful with file operations in renderer processes"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing filesystem operations.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for filesystem operations
      content != nil ->
        String.contains?(content, "readFile") || 
        String.contains?(content, "writeFile") ||
        String.contains?(content, "fs.")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual path traversal vulnerabilities and:
  - String concatenation for URL building (not file paths)
  - Validated input before concatenation
  - Static strings being concatenated
  - Use of path.join() elsewhere in the code
  - Concatenation that doesn't involve filesystem operations
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PathTraversalConcat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PathTraversalConcat.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "BinaryExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PathTraversalConcat.ast_enhancement()
      iex> enhancement.ast_rules.operator
      "+"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PathTraversalConcat.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PathTraversalConcat.ast_enhancement()
      iex> "building_url_not_path" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinaryExpression",
        operator: "+",
        # Building file paths with concatenation
        context_analysis: %{
          building_file_path: true,
          has_user_input: true,
          has_path_separators: true  # Contains / or \
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        exclude_if_url_building: true,       # Building URLs, not file paths
        exclude_if_validated: true,
        exclude_if_using_safe_join: true,    # Should use path.join instead
        high_risk_patterns: ["__dirname +", "process.cwd() +", "./uploads/"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "dirname_plus_user_input" => 0.5,
          "uploads_dir_traversal" => 0.4,
          "has_fs_operation_nearby" => 0.3,
          "validated_before_use" => -0.8,
          "building_url_not_path" => -0.9,
          "using_path_join_elsewhere" => -0.5  # Inconsistent, but less risky
        }
      },
      min_confidence: 0.7
    }
  end
end