defmodule RsolvApi.Security.Patterns.Ruby.PathTraversal do
  @moduledoc """
  Detects Path Traversal vulnerabilities in Ruby applications.
  
  Path traversal vulnerabilities occur when user-controlled input is used to construct
  file paths without proper validation. Attackers can use special characters like "../"
  to navigate outside intended directories and access sensitive files on the server.
  
  ## Vulnerability Details
  
  Ruby applications are vulnerable to path traversal when they use user input directly
  in file operations like File.read, File.open, send_file, or render file: without
  proper sanitization. Attackers can read configuration files, source code, or even
  system files like /etc/passwd.
  
  ### Attack Example
  ```ruby
  # Vulnerable - Direct use of params in file operations
  def download
    file_path = params[:file]
    send_file file_path
  end
  
  # Vulnerable - String interpolation with user input
  def read_document
    content = File.read("uploads/\#{params[:document]}")
    render plain: content
  end
  
  # Secure - Path validation and restriction
  def download_safe
    filename = File.basename(params[:file])
    safe_path = File.join(Rails.root, 'public', 'downloads', filename)
    
    # Ensure the final path is within allowed directory
    if safe_path.start_with?(File.join(Rails.root, 'public', 'downloads'))
      send_file safe_path
    else
      render plain: "Invalid file", status: :forbidden
    end
  end
  ```
  
  ### Real-World Impact
  - Reading sensitive configuration files (database.yml, secrets.yml)
  - Accessing source code and discovering vulnerabilities
  - Reading system files containing passwords or keys
  - Information disclosure leading to further attacks
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the Path Traversal pattern for Ruby applications.
  
  Detects file operations that use user-controlled input without proper
  validation, which could allow attackers to access files outside the
  intended directory.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.PathTraversal.pattern()
      iex> pattern.id
      "ruby-path-traversal"
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.PathTraversal.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.PathTraversal.pattern()
      iex> vulnerable = "File.read(params[:file])"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.PathTraversal.pattern()
      iex> safe = "File.read('config/static.yml')"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-path-traversal",
      name: "Path Traversal",
      description: "Detects file access operations with user-controlled paths that could allow directory traversal attacks",
      type: :path_traversal,
      severity: :high,
      languages: ["ruby"],
      regex: [
        # File.read/open with direct params
        ~r/File\.(?:read|open|readlines|binread|write|exist\?)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)/,
        
        # String interpolation in file paths
        ~r/File\.(?:read|open|readlines|binread|write)\s*\(\s*["'].*?#\{.*?(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+).*?\}/,
        
        # send_file with user input
        ~r/send_file\s+(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)/,
        
        # File.join with user input
        ~r/File\.(?:read|open|write)\s*\(\s*File\.join\s*\([^)]*(?:params|request\.(?:params|parameters)|user_[\w_]*)/,
        ~r/send_file\s+File\.join\s*\([^)]*(?:params|request\.(?:params|parameters)|user_[\w_]*)/,
        
        # IO operations with user input
        ~r/IO\.(?:read|readlines|binread|write)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)/,
        
        # Rails render file: with user input
        ~r/render\s+file:\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)/,
        ~r/render\s+file:\s*["'].*?#\{.*?(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+).*?\}/
      ],
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate file paths using File.basename, restrict access to safe directories, and verify resolved paths stay within allowed boundaries",
      test_cases: %{
        vulnerable: [
          "File.read(params[:file])",
          "send_file params[:download]",
          "File.open(\"uploads/\#{params[:file]}\")",
          "render file: params[:template]",
          "File.read(File.join(Rails.root, params[:path]))"
        ],
        safe: [
          "File.read('config/database.yml')",
          "filename = File.basename(params[:file])\nFile.read(File.join(SAFE_DIR, filename))",
          "send_file Rails.root.join('public', 'robots.txt')",
          "render file: 'shared/404'"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal vulnerabilities allow attackers to access files and directories outside the intended scope by manipulating file paths.
      In Ruby applications, this commonly occurs when user input is used directly in file operations without proper validation.
      Attackers use sequences like "../" or absolute paths to navigate the filesystem and access sensitive files such as configuration
      files, source code, or system files. This can lead to information disclosure, source code exposure, and further attacks.
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
          title: "OWASP Top 10 2021 - Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :research,
          id: "rails_path_traversal",
          title: "Rails Path Traversal Guide: Examples and Prevention - StackHawk",
          url: "https://www.stackhawk.com/blog/rails-path-traversal-guide-examples-and-prevention/"
        },
        %{
          type: :research,
          id: "owasp_path_traversal",
          title: "Path Traversal - OWASP",
          url: "https://owasp.org/www-community/attacks/Path_Traversal"
        }
      ],
      attack_vectors: [
        "Directory traversal sequences: ../../../etc/passwd",
        "URL encoded traversal: %2e%2e%2f or %252e%252e%252f (double encoding)",
        "Absolute paths: /etc/passwd or C:\\Windows\\System32\\config\\sam",
        "Null byte injection (older Ruby): file.txt%00.jpg",
        "Unicode/UTF-8 encoding: ..%c0%af or ..%ef%bc%8f",
        "Windows UNC paths: \\\\server\\share\\file",
        "Symbolic link exploitation combined with traversal"
      ],
      real_world_impact: [
        "Reading sensitive configuration files containing database credentials",
        "Accessing source code to find additional vulnerabilities",
        "Reading system files like /etc/passwd or shadow files",
        "Accessing log files containing sensitive user data",
        "Reading private keys or certificates"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-5418",
          description: "Rails Action View directory traversal via specially crafted Accept headers",
          severity: "high",
          cvss: 7.5,
          note: "Allowed reading arbitrary files by manipulating render file: paths"
        },
        %{
          id: "CVE-2018-3760",
          description: "Rails Asset Pipeline directory traversal in Sprockets",
          severity: "high",
          cvss: 7.5,
          note: "Path traversal via secondary decoding allowing access to arbitrary files"
        },
        %{
          id: "CVE-2014-0130",
          description: "Directory traversal in Rails implicit render functionality",
          severity: "medium",
          cvss: 5.0,
          note: "Allowed rendering of arbitrary files on the system"
        },
        %{
          id: "CVE-2025-27610",
          description: "Path traversal vulnerability in Rack::Static middleware",
          severity: "high",
          cvss: 7.5,
          note: "Allowed unauthenticated access to arbitrary files through improper path sanitization"
        }
      ],
      detection_notes: """
      This pattern detects common path traversal vulnerabilities in Ruby:
      - Direct use of user input in file operations (File.read, File.open, etc.)
      - String interpolation with user input in file paths
      - send_file calls with user-controlled paths
      - File.join usage that includes user input
      - Rails render file: with dynamic paths
      
      The pattern focuses on methods that access the filesystem and could be exploited
      for unauthorized file access. AST enhancement provides additional validation checks.
      """,
      safe_alternatives: [
        "Use File.basename to extract just the filename: File.basename(params[:file])",
        "Validate paths stay within allowed directories: path.start_with?(SAFE_DIR)",
        "Use Rails.root.join with hardcoded paths: Rails.root.join('public', 'downloads', filename)",
        "Implement allowlists for permitted files instead of dynamic paths",
        "Use send_data with database content instead of send_file for user uploads",
        "Sanitize paths by removing directory separators: params[:file].gsub(/[\\/]/, '')"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting File.join to prevent traversal (it doesn't)",
          "Only checking for '../' but not encoded versions",
          "Not verifying the resolved absolute path stays within bounds",
          "Allowing user input to specify file extensions"
        ],
        secure_patterns: [
          "Always use File.basename when accepting filenames",
          "Resolve to absolute paths and verify they're within allowed directories",
          "Use hardcoded paths whenever possible",
          "Implement strict allowlists for dynamic file access"
        ],
        framework_notes: %{
          rails: "Rails provides some protection but render file: and send_file need careful handling",
          sinatra: "No built-in protection - all file operations need manual validation",
          general: "Ruby's File methods don't prevent traversal - validation is always required"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for path traversal detection.

  This enhancement helps distinguish between actual vulnerabilities and safe file
  operations that don't use user input or properly validate paths.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Ruby.PathTraversal.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.PathTraversal.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.PathTraversal.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.PathTraversal.ast_enhancement()
      iex> enhancement.ast_rules.file_operations.check_file_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        file_operations: %{
          check_file_methods: true,
          file_methods: ["File.read", "File.open", "File.readlines", "File.binread", "File.write"],
          io_methods: ["IO.read", "IO.readlines", "IO.binread"],
          rails_methods: ["send_file", "render", "send_data"],
          path_methods: ["File.join", "Rails.root.join", "Pathname.new"]
        },
        user_input_analysis: %{
          input_sources: ["params", "request", "cookies", "session", "user_input", "@user", "@current_user"],
          check_path_arguments: true,
          check_string_interpolation: true,
          track_variable_assignments: true,
          check_method_chains: true
        },
        validation_analysis: %{
          check_path_validation: true,
          safe_methods: ["File.basename", "File.expand_path", "Pathname#cleanpath"],
          path_checks: ["start_with?", "include?", "match?"],
          directory_restrictions: ["Rails.root", "SAFE_DIR", "PUBLIC_DIR"],
          sanitization_patterns: ["gsub", "tr", "delete"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        exclude_if_validated: true,
        safe_if_uses: ["File.basename", "path.start_with?(SAFE_DIR)", "whitelist.include?"],
        check_static_paths: true,
        exclude_hardcoded_paths: true,
        exclude_if_within_safe_directory: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "direct_params_in_file_operation" => 0.4,
          "string_interpolation_with_user_input" => 0.3,
          "file_join_with_user_input" => 0.3,
          "render_file_with_params" => 0.3,
          "has_basename_validation" => -0.7,
          "has_path_restriction_check" => -0.6,
          "static_file_path" => -1.0,
          "in_test_code" => -1.0
        }
      },
      min_confidence: 0.7
    }
  end
end
