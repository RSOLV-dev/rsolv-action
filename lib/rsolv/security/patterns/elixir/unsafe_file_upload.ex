defmodule Rsolv.Security.Patterns.Elixir.UnsafeFileUpload do
  @moduledoc """
  Unsafe File Upload vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects file upload operations that allow arbitrary file writes
  without proper validation, enabling path traversal attacks and RCE.

  ## Vulnerability Details

  Unsafe file upload occurs when applications accept user-provided filenames
  or file paths without proper validation and sanitization:
  - File.write operations using user-controlled filenames enable path traversal
  - Missing file type validation allows executable file uploads
  - Concatenating user input directly into file paths bypasses security boundaries
  - Using upload.filename directly allows directory traversal sequences (../)

  ## Technical Impact

  Security risks through:
  - Remote code execution via uploaded executable files (.php, .jsp, .exe)
  - Path traversal attacks accessing sensitive files outside upload directory
  - Web shell uploads enabling persistent system access
  - Configuration file overwrites leading to application compromise
  - Directory traversal allowing read/write access to arbitrary file system locations

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Direct use of user-provided filename
  File.write!("/uploads/\#{upload.filename}", upload.content)
  
  # VULNERABLE - String concatenation with user input
  File.write!("/uploads/" <> params.filename, data)
  
  # VULNERABLE - Path.join with unsanitized filename
  File.write!(Path.join(upload_dir, upload.filename), content)
  
  # VULNERABLE - No file type validation
  File.write!(upload_path <> upload.filename, content)
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Filename validation and sanitization
  if Path.extname(upload.filename) in [".jpg", ".png", ".pdf"] do
    safe_name = "\#{UUID.generate()}_\#{Path.basename(upload.filename)}"
    File.write!(Path.join(upload_dir, safe_name), upload.content)
  end
  
  # SAFE - UUID-based filename generation
  filename = "\#{UUID.generate()}\#{Path.extname(upload.filename)}"
  File.write!(Path.join(upload_dir, filename), upload.content)
  
  # SAFE - Hardcoded safe path
  File.write!("/uploads/processed_file.jpg", content)
  ```

  ## Attack Scenarios

  1. **Path Traversal**: Attacker uploads file with filename "../../../etc/passwd" 
     to overwrite system files or access sensitive data outside upload directory

  2. **Web Shell Upload**: Upload executable file (.php, .jsp) that provides 
     remote command execution capabilities on the server

  3. **Configuration Overwrite**: Upload malicious config files to alter 
     application behavior or gain elevated privileges

  ## References

  - CWE-434: Unrestricted Upload of File with Dangerous Type
  - CWE-22: Improper Limitation of a Pathname to a Restricted Directory  
  - OWASP Top 10 2021 - A01: Broken Access Control
  - Sobelow Security Scanner - Path Traversal Detection
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-unsafe-file-upload",
      name: "Unsafe File Upload",
      description: "File upload operations using unsanitized user input enable path traversal attacks and RCE",
      type: :file_upload,
      severity: :high,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # File.write operations with user filename interpolation - exclude comments
        ~r/^(?!\s*#).*File\.write!?\s*\(\s*[^,]*#\{[^}]*(?:\.filename|params\[|filename)/,
        
        # File.write with string concatenation using user input - exclude comments
        ~r/^(?!\s*#).*File\.write!?\s*\([^,]*\s*<>\s*[^,]*(?:\.filename|params\[)/,
        
        # Path.join with user-controlled filename - exclude comments
        ~r/^(?!\s*#).*Path\.join\s*\([^,\]]*,\s*[^,\]]*(?:\.filename|params\[)/,
        
        # File.write with Path.join containing user input - exclude comments
        ~r/^(?!\s*#).*File\.write!?\s*\(\s*Path\.join\s*\([^)]*(?:\.filename|params\[)[^)]*\)/,
        
        # Path.join with array notation - exclude comments
        ~r/^(?!\s*#).*Path\.join\s*\(\s*\[[^\]]*(?:\.filename|params\[)[^\]]*\]/
      ],
      cwe_id: "CWE-434",
      owasp_category: "A01:2021",
      recommendation: "Validate file types, sanitize filenames, and use safe upload directories with generated filenames",
      test_cases: %{
        vulnerable: [
          ~S|File.write!("/uploads/#{upload.filename}", upload.content)|,
          ~S|File.write("/uploads/" <> params.filename, data)|,
          ~S|File.write!(Path.join(upload_dir, upload.filename), content)|,
          ~S|File.write(Path.join("/uploads", params[:filename]), data)|
        ],
        safe: [
          ~S|File.write!("/uploads/safe_file.jpg", content)|,
          ~S|filename = "#{UUID.generate()}.jpg"; File.write!(Path.join(upload_dir, filename), content)|,
          ~S|if Path.extname(upload.filename) in [".jpg"] do safe_name = validate_filename(upload.filename); File.write!(safe_name, content) end|,
          ~S|File.write!(Path.join(upload_dir, UUID.generate()), content)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Path traversal attacks using "../" sequences in uploaded filenames to access files outside upload directory
      2. Web shell upload by bypassing file type restrictions to upload executable files (.php, .jsp, .exe)
      3. Configuration file overwrite by targeting application configuration files with malicious content
      4. Binary execution upload of malicious executables that can be triggered for remote code execution
      5. Symbolic link attacks creating symlinks to sensitive system files for unauthorized access
      """,
      business_impact: """
      High: Unsafe file upload vulnerabilities can result in:
      - Complete system compromise through remote code execution and web shell deployment
      - Data breaches via path traversal attacks accessing sensitive files and databases
      - Service disruption through malicious file uploads consuming disk space or crashing services
      - Compliance violations related to data protection and secure file handling requirements
      - Reputation damage from security incidents involving customer data or system compromise
      """,
      technical_impact: """
      High: File upload vulnerabilities enable:
      - Remote code execution through uploaded executable files and web shells
      - Directory traversal attacks bypassing access controls to read/write arbitrary files
      - Server-side file inclusion attacks leveraging uploaded malicious files
      - Configuration tampering by overwriting critical application configuration files
      - Denial of service attacks through large file uploads or disk space exhaustion
      """,
      likelihood: "High: File upload functionality is common in web applications and frequently lacks proper security controls",
      cve_examples: [
        "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "CVE-2021-44228: Log4Shell RCE via file upload vectors",
        "OWASP Top 10 A01:2021 - Broken Access Control"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "NIST Cybersecurity Framework - PR.AC: Access Control",
        "ISO 27001 - A.9.4: System and application access control",
        "PCI DSS - Requirement 6.5: Address common vulnerabilities in software development"
      ],
      remediation_steps: """
      1. Implement file type validation using whitelist of allowed extensions
      2. Generate unique filenames using UUIDs instead of user-provided names
      3. Store uploaded files outside web-accessible directories
      4. Validate file content matches declared file type using magic number detection
      5. Implement file size restrictions to prevent disk space exhaustion
      6. Use secure upload libraries that handle validation automatically
      """,
      prevention_tips: """
      1. Never use user-provided filenames directly in File.write operations
      2. Validate file extensions against strict whitelist of allowed types
      3. Generate secure filenames using UUID.generate() or similar secure methods
      4. Store uploads in isolated directories with restricted permissions
      5. Implement content-type validation beyond just file extension checking
      6. Use Phoenix built-in file upload validation helpers and sanitize all user input
      """,
      detection_methods: """
      1. Static code analysis scanning for File.write operations with user input
      2. Dynamic testing with path traversal payloads in filename parameters
      3. Security scanners like Sobelow checking for insecure file operations
      4. Code reviews focusing on file upload functionality and input validation
      5. Penetration testing with malicious file upload attempts
      """,
      safe_alternatives: """
      1. UUID-based filename generation: filename = "\#{UUID.generate()}\#{Path.extname(upload.filename)}"
      2. Phoenix file upload validation with changeset validate and file type checking
      3. Dedicated upload libraries like ExAws.S3 for cloud storage with built-in security
      4. Secure file handling patterns with validate functions and sanitization
      5. Content-based file type detection using libraries like ExMagic
      6. Isolated upload directories with proper file permissions and access controls
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        file_write_functions: [
          "File.write",
          "File.write!",
          "File.open",
          "File.stream!",
          "IO.write"
        ],
        user_input_sources: [
          "upload.filename",
          "params.filename", 
          "params[:filename]",
          "upload_params.filename",
          "file_params.filename",
          "conn.params"
        ],
        safe_filename_patterns: [
          "UUID.generate",
          "Ecto.UUID.generate",
          "validate_filename",
          "sanitize_filename",
          "secure_filename"
        ],
        dangerous_extensions: [
          ".php", ".jsp", ".exe", ".sh", ".bat", ".cmd", ".scr",
          ".vbs", ".jar", ".war", ".py", ".rb", ".pl"
        ]
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          user_filename_bonus: 0.2,
          path_traversal_bonus: 0.15,
          sanitized_input_penalty: -0.6,
          uuid_filename_penalty: -0.8,
          extension_validation_penalty: -0.5,
          hardcoded_path_penalty: -0.3
        }
      },
      ast_rules: %{
        node_type: "file_upload_analysis",
        file_path_analysis: %{
          check_file_operations: true,
          file_functions: ["File.write", "File.write!", "File.open", "File.stream!"],
          check_path_construction: true,
          detect_user_input: true
        },
        user_input_validation: %{
          check_filename_sources: true,
          detect_interpolation: true,
          detect_concatenation: true,
          check_path_join: true
        },
        security_validation: %{
          check_extension_validation: true,
          check_filename_sanitization: true,
          check_uuid_generation: true,
          detect_hardcoded_paths: true
        }
      }
    }
  end
end
