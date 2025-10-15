defmodule Rsolv.Security.Patterns.Elixir.PathTraversal do
  @moduledoc """
  Detects path traversal vulnerabilities in Elixir file operations.

  This pattern identifies instances where user-controlled input is used in file paths
  without proper validation, potentially allowing attackers to access files outside 
  intended directories using sequences like "../" or absolute paths.

  ## Vulnerability Details

  Path traversal vulnerabilities occur when an application uses user input to construct
  file paths without proper validation. Attackers can manipulate the input to access
  files and directories outside the intended scope, potentially reading sensitive files
  like configuration files, source code, or system files.

  ### Attack Example

  Vulnerable code:
  ```elixir
  # Controller serving user uploads
  def download(conn, %{"filename" => filename}) do
    path = "/uploads/" <> filename  # User can inject "../../../etc/passwd"
    content = File.read!(path)      # CRITICAL VULNERABILITY!
    send_download(conn, {:binary, content}, filename: filename)
  end
  ```

  An attacker could request: `/download?filename=../../../etc/passwd`

  ### Safe Alternative

  Safe code:
  ```elixir
  def download(conn, %{"filename" => filename}) do
    # Validate and sanitize the filename
    safe_name = Path.basename(filename)  # Remove directory components
    base_dir = "/uploads"
    full_path = Path.expand(safe_name, base_dir)
    
    # Ensure the resolved path is within allowed directory
    if String.starts_with?(full_path, base_dir <> "/") do
      case File.read(full_path) do
        {:ok, content} -> send_download(conn, {:binary, content}, filename: safe_name)
        {:error, _} -> send_resp(conn, 404, "File not found")
      end
    else
      send_resp(conn, 403, "Access denied")
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "elixir-path-traversal",
      name: "Path Traversal Vulnerability",
      description: "Unsanitized file paths can lead to unauthorized file access",
      type: :path_traversal,
      severity: :high,
      languages: ["elixir"],
      regex: [
        # File operations with string interpolation
        ~r/File\.(read!?|write!?|exists\?|rm!?|mkdir_p!?|stream!?|open)\s*\([^"']*["'][^"']*#\{[^}]+\}/,
        # Path.join with user input (common pattern)
        ~r/Path\.join\s*\([^,)]+,\s*(?:params|conn|socket|args|user|input|request)/,
        # File operations with concatenation
        ~r/File\.\w+!?\s*\([^"']*<>\s*[^)]+/,
        # Direct variable usage in file operations
        ~r/File\.(read!?|write!?|exists\?|rm!?)\s*\(\s*(?:params|user_|input|file|path|dir)/,
        # IO operations with user paths
        ~r/IO\.(read|write|binread|binwrite)\s*\([^"']*#\{/,
        # FileStream with interpolation
        ~r/File\.stream!?\s*\([^"']*#\{/
      ],
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation:
        "Validate and sanitize file paths. Use Path.expand/2 with a safe base directory",
      test_cases: %{
        vulnerable: [
          ~S|File.read!("/uploads/#{filename}")|,
          ~S|File.write!("#{base_path}/#{user_file}", content)|,
          ~S|Path.join("/uploads", params["file"])|
        ],
        safe: [
          ~S|safe_path = Path.expand(filename, "/uploads")
if String.starts_with?(safe_path, "/uploads/") do
  File.read!(safe_path)
end|,
          ~S|File.read!("/uploads/avatar.png")|,
          ~S|File.write!("config/prod.exs", config)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal vulnerabilities in Elixir occur when user-controlled input is used to
      construct file paths without proper validation. This allows attackers to use directory
      traversal sequences (../, ..\) or absolute paths to access files outside the intended
      directory structure. In Elixir/Phoenix applications, this commonly happens when serving
      user uploads, processing file downloads, or managing temporary files.

      The vulnerability is particularly dangerous because Elixir's File module functions are
      null-terminated, which can lead to additional security issues when combined with path
      traversal. Attackers can read sensitive configuration files, source code, system files,
      or even write malicious files to arbitrary locations.
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
          id: "guardrails_elixir",
          title: "GuardRails - Insecure File Management in Elixir",
          url: "https://docs.guardrails.io/docs/vulnerabilities/elixir/insecure_file_management"
        },
        %{
          type: :research,
          id: "sobelow_traversal",
          title: "Sobelow - Path Traversal Detection",
          url: "https://github.com/nccgroup/sobelow#traversal"
        }
      ],
      attack_vectors: [
        "Directory traversal sequences: ../../../etc/passwd",
        "URL encoded traversal: %2e%2e%2f for ../",
        "Double encoding: %252e%252e%252f",
        "Absolute paths: /etc/passwd instead of relative",
        "Null byte injection: file.txt%00.jpg (less relevant in Elixir)",
        "Windows UNC paths: \\\\server\\share\\file",
        "Symbolic link exploitation combined with traversal"
      ],
      real_world_impact: [
        "Reading sensitive configuration files (prod.secret.exs)",
        "Accessing source code and discovering vulnerabilities",
        "Reading system files (/etc/passwd, /etc/shadow)",
        "Downloading database backups or credentials",
        "Writing web shells or backdoors to web-accessible directories",
        "Overwriting critical application files",
        "Information disclosure leading to further attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-41773",
          description: "Apache HTTP Server path traversal and RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates how path traversal can escalate to RCE"
        }
      ],
      detection_notes: """
      This pattern detects:
      - File module operations with string interpolation (#{}))
      - Path.join with user-controlled input
      - Direct usage of params/user input in file operations
      - File operations with string concatenation (<>)
      - IO operations with dynamic paths
      """,
      safe_alternatives: [
        "Use Path.basename/1 to extract just the filename",
        "Use Path.expand/2 with a safe base directory",
        "Validate resolved paths start with allowed directory",
        "Use a whitelist of allowed filenames or patterns",
        "Store files with generated names, map to original names in database",
        "Use Path.safe_relative/1 when available",
        "Implement strict input validation rejecting path separators"
      ],
      additional_context: %{
        common_mistakes: [
          "Only checking for ../ but not encoded versions",
          "Not validating absolute paths",
          "Using Path.join without validating the second argument",
          "Not checking the final resolved path is within bounds"
        ],
        secure_patterns: [
          "Always use Path.expand/2 and validate the result",
          "Store uploaded files with UUID names",
          "Never use user input directly in file paths",
          "Implement comprehensive path validation functions"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing context and usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Elixir.PathTraversal.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Elixir.PathTraversal.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        file_analysis: %{
          check_file_operations: true,
          file_functions: [
            "File.read",
            "File.read!",
            "File.write",
            "File.write!",
            "File.exists?",
            "File.rm",
            "File.rm!",
            "File.mkdir_p!",
            "File.stream",
            "File.stream!",
            "File.open"
          ],
          check_path_operations: true,
          path_functions: ["Path.join", "Path.expand"],
          check_io_operations: true
        },
        input_analysis: %{
          user_input_indicators: [
            "params",
            "conn",
            "socket",
            "args",
            "user",
            "input",
            "file",
            "filename",
            "path",
            "directory",
            "upload"
          ],
          check_string_interpolation: true,
          check_concatenation: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/seeds/],
        user_input_sources: [
          "params",
          "conn.params",
          "conn.body_params",
          "socket.assigns",
          "args",
          "user_input",
          "request",
          "upload"
        ],
        safe_patterns: ["Path.expand", "Path.basename", "String.starts_with?"],
        exclude_if_validated: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_user_input" => 0.4,
          "uses_path_validation" => -0.6,
          "in_test_code" => -1.0,
          "uses_safe_patterns" => -0.5,
          "hardcoded_base_path" => -0.3
        }
      },
      min_confidence: 0.75
    }
  end
end
