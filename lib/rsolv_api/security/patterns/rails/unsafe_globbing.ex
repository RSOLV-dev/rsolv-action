defmodule RsolvApi.Security.Patterns.Rails.UnsafeGlobbing do
  @moduledoc """
  Rails Unsafe Globbing pattern for Rails applications.
  
  This pattern detects path traversal vulnerabilities in Rails route globbing 
  that can lead to arbitrary file disclosure. Glob routes use wildcard parameters 
  like '*path' to capture multiple path segments, but without proper constraints 
  they can be exploited to access files outside the intended directory.
  
  ## Background
  
  Rails glob routes are designed to capture multiple path segments into a single
  parameter. For example, `get "files/*path", to: "files#show"` will capture
  everything after "/files/" into the :path parameter. However, this can be
  dangerous when the captured path is used to access files without validation.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. Glob routes lack proper path constraints
  2. The glob parameter is used directly in file operations
  3. No validation prevents path traversal sequences (../)
  4. Format constraints are disabled allowing arbitrary file extensions
  5. Controllers render files based on glob parameters without sanitization
  
  ## Known CVEs
  
  - CVE-2014-0130: Directory traversal in Rails actionpack with route globbing (CVSS 5.0)
  - CVE-2019-5418: File content disclosure in Action View with render file (CVSS 7.5)
  - Multiple path traversal vulnerabilities in Rails applications using unsafe globbing
  - ActionPack implicit render vulnerabilities with glob routes
  
  ## Examples
  
      # Critical - No constraints on glob route
      get "files/*path", to: "files#show"
      
      # Critical - Generic catch-all route
      match "*anything" => "default#handler"
      
      # Critical - Disabled format constraints
      get "download/*file", to: "download#serve", format: false
      
      # Safe - Proper path constraints
      get "files/*path", to: "files#show", constraints: { path: /[^.]/ }
      
      # Safe - Specific validation
      get "assets/*filename", to: "assets#serve", constraints: { filename: /\\A[\\w\\.-\\/]+\\z/ }
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-unsafe-globbing",
      name: "Unsafe Route Globbing",
      description: "Glob routes that allow path traversal attacks without proper constraints",
      type: :path_traversal,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Basic glob routes
        ~r/get\s+["'].*?\*\w+["']\s*,\s*to:/,
        ~r/post\s+["'].*?\*\w+["']\s*,\s*to:/,
        ~r/put\s+["'].*?\*\w+["']\s*,\s*to:/,
        ~r/delete\s+["'].*?\*\w+["']\s*,\s*to:/,
        
        # Match routes with both syntaxes
        ~r/match\s+["'].*?\*\w+["']\s*,\s*to:/,
        ~r/match\s+["'].*?\*\w+["']\s*=>/,
        
        # Generic catch-all routes (very dangerous)
        ~r/get\s+["']\*\w+["']\s*,\s*to:/,
        ~r/match\s+["']\*\w+["']\s*=>/,
        ~r/get\s+["']\*all["']/,
        ~r/get\s+["']\*path["']/,
        ~r/get\s+["']\*splat["']/,
        ~r/match\s+["']\*anything["']/,
        
        # Patterns with => syntax
        ~r/get\s+['"].*?\*\w+['"]\s*=>/,
        ~r/match\s+['"].*?\*\w+['"]\s*=>/,
        
        # Specific dangerous patterns from CVE research
        ~r/get\s+["']files\/\*path["']/,
        ~r/get\s+["']download\/\*\w+["']/,
        ~r/get\s+["']serve\/\*\w+["']/,
        ~r/get\s+["']assets\/\*\w+["']/,
        ~r/get\s+["']media\/\*\w+["']/,
        ~r/get\s+["']content\/\*\w+["']/,
        ~r/get\s+["']uploads\/\*\w+["']/,
        ~r/get\s+["']documents\/\*\w+["']/,
        ~r/get\s+["']storage\/\*\w+["']/,
        ~r/get\s+["']backup\/\*\w+["']/,
        
        # Routes with format: false (disables format constraints)
        ~r/get\s+["'].*?\*\w+["'].*?format:\s*false/,
        ~r/match\s+["'].*?\*\w+["'].*?format:\s*false/,
        ~r/get\s+["'].*?\*\w+["'].*?defaults:\s*\{.*?format:\s*nil/,
        
        # Nested route patterns that can be dangerous
        ~r/namespace\s+:\w+\s+do.*?get\s+["'].*?\*\w+["']/s,
        ~r/scope\s+:\w+\s+do.*?get\s+["'].*?\*\w+["']/s,
        ~r/resources\s+:\w+\s+do.*?get\s+["'].*?\*\w+["']/s
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Add path constraints to glob routes. Validate glob parameters and restrict file access to safe directories.",
      test_cases: %{
        vulnerable: [
          "get \"files/*path\", to: \"files#show\"",
          "match \"*path\" => \"files#show\"", 
          "get \"download/*file\", to: \"download#serve\", format: false",
          "get \"*all\", to: \"application#catch_all\""
        ],
        safe: [
          "get \"files/*path\", to: \"files#show\", constraints: { path: /[^.]/ }",
          "get \"assets/*filename\", to: \"assets#serve\", constraints: { filename: /\\\\A[\\\\w\\\\.-\\\\/]+\\\\z/ }",
          "get \"files/:id\", to: \"files#show\"",
          "get \"files\", to: \"files#index\""
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe Route Globbing in Rails applications represents a critical path traversal vulnerability where 
      glob routes (using wildcard parameters like '*path') lack proper constraints, allowing attackers 
      to access arbitrary files on the server. Glob routes are designed to capture multiple path 
      segments into a single parameter, making them convenient for file serving or catch-all routes, 
      but they become dangerous when the captured path is used directly in file operations.
      
      The vulnerability is particularly severe because:
      1. It can lead to complete server file system disclosure
      2. Attackers can read sensitive configuration files, source code, and data
      3. It bypasses traditional directory restrictions through path traversal
      4. Many applications use glob routes for file serving without realizing the security implications
      5. Rails' implicit rendering can automatically serve files based on glob parameters
      """,
      
      attack_vectors: ~S"""
      1. **Basic Path Traversal**: GET /files/../../../etc/passwd (reads /etc/passwd)
      2. **Configuration File Access**: GET /files/../../../config/database.yml (database credentials)
      3. **Source Code Disclosure**: GET /files/../../../app/models/user.rb (application source)
      4. **Log File Access**: GET /files/../../../log/production.log (application logs)
      5. **SSH Key Theft**: GET /files/../../../home/user/.ssh/id_rsa (private SSH keys)
      6. **Environment Variables**: GET /files/../../../proc/self/environ (process environment)
      7. **Application Secrets**: GET /files/../../../config/secrets.yml (Rails secret keys)
      8. **Database Files**: GET /files/../../../db/production.sqlite3 (SQLite databases)
      9. **Backup File Access**: GET /files/../../../backup/db_backup.sql (database backups)
      10. **Certificate Theft**: GET /files/../../../etc/ssl/private/server.key (SSL certificates)
      11. **Memory Dumps**: GET /files/../../../proc/self/maps (process memory layout)
      12. **System Information**: GET /files/../../../proc/version (system version info)
      """,
      
      business_impact: """
      - Complete server compromise through file disclosure
      - Database credential theft leading to data breaches
      - Source code disclosure exposing intellectual property
      - Customer data exposure through configuration file access
      - Regulatory compliance violations (GDPR, HIPAA, PCI DSS)
      - Legal liability from data breaches and privacy violations
      - Reputation damage from security incidents
      - Business disruption from system compromise
      - Competitive intelligence theft through source code access
      - Financial fraud through exposed API keys and credentials
      """,
      
      technical_impact: """
      - Arbitrary file read access across the entire server
      - Application source code and configuration disclosure
      - Database credentials and connection string exposure
      - API keys, secrets, and authentication token theft
      - SSL certificate and private key disclosure
      - System configuration and network topology discovery
      - Application logs revealing user behavior and system internals
      - Backup files and database dumps accessible
      - Environment variables containing sensitive information
      - Complete bypass of application access controls
      """,
      
      likelihood: "High - Glob routes are commonly used for file serving and many developers don't realize the security implications",
      
      cve_examples: """
      CVE-2014-0130 - Directory traversal in Rails actionpack/lib/abstract_controller/base.rb (CVSS 5.0)
      CVE-2019-5418 - File Content Disclosure in Action View with render file (CVSS 7.5)
      CVE-2016-0752 - Directory traversal vulnerability in Action View (related to path handling)
      CVE-2018-3760 - Path traversal in Sprockets via path normalization bypass
      HackerOne #312918 - Path traversal in Rails applications via glob routes
      Multiple path traversal vulnerabilities in Rails applications using unsafe globbing
      ActionPack implicit render vulnerabilities with glob route parameters
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-22: Path Traversal", 
        "CWE-200: Information Exposure",
        "PCI DSS 6.5.8 - Improper access control",
        "NIST SP 800-53 - AC-3 Access Enforcement",
        "ISO 27001 - A.9.4.1 Information access restriction",
        "ASVS 4.0 - V12.1 File and Resource Verification Requirements",
        "SANS Top 25 - CWE-22 Path Traversal"
      ],
      
      remediation_steps: """
      1. **Add Path Constraints (Critical)**:
         ```ruby
         # NEVER do this - allows arbitrary file access
         get "files/*path", to: "files#show"           # DANGEROUS
         
         # Always add path constraints
         get "files/*path", to: "files#show", 
             constraints: { path: /[^.]/ }             # Excludes dot files
         
         get "files/*path", to: "files#show",
             constraints: { path: /\\A[\\w\\/-]+\\z/ }   # Alphanumeric + / and -
         
         get "assets/*filename", to: "assets#serve",
             constraints: { filename: /\\A[\\w\\.\\-\\/]+\\z/ } # Specific file chars
         ```
      
      2. **Controller-Level Validation**:
         ```ruby
         class FilesController < ApplicationController
           SAFE_PATH_PATTERN = /\\A[\\w\\.\\/\\-]+\\z/.freeze
           ALLOWED_EXTENSIONS = %w[.jpg .png .pdf .txt].freeze
           
           def show
             file_path = params[:path]
             
             # Validate path format
             unless file_path.match?(SAFE_PATH_PATTERN)
               render status: :bad_request and return
             end
             
             # Check for path traversal
             if file_path.include?('../') || file_path.include?('..\\\\')
               render status: :bad_request and return
             end
             
             # Validate file extension
             extension = File.extname(file_path).downcase
             unless ALLOWED_EXTENSIONS.include?(extension)
               render status: :bad_request and return
             end
             
             # Ensure file is within safe directory
             safe_path = Rails.root.join('public', 'files', file_path)
             canonical_path = File.expand_path(safe_path)
             safe_directory = File.expand_path(Rails.root.join('public', 'files'))
             
             unless canonical_path.start_with?(safe_directory)
               render status: :bad_request and return
             end
             
             if File.exist?(canonical_path) && File.file?(canonical_path)
               send_file(canonical_path)
             else
               render status: :not_found
             end
           end
         end
         ```
      
      3. **Use Whitelist-Based Routing**:
         ```ruby
         # Instead of glob routes, use predefined file lists
         class FilesController < ApplicationController
           ALLOWED_FILES = {
             'user-guide' => 'public/docs/user-guide.pdf',
             'privacy-policy' => 'public/legal/privacy.pdf',
             'terms' => 'public/legal/terms.pdf'
           }.freeze
           
           def show
             file_key = params[:file]
             file_path = ALLOWED_FILES[file_key]
             
             if file_path && File.exist?(Rails.root.join(file_path))
               send_file(Rails.root.join(file_path))
             else
               render status: :not_found
             end
           end
         end
         
         # Routes
         get "files/:file", to: "files#show", 
             constraints: { file: /\\\#{Regexp.union(ALLOWED_FILES.keys)}/ }
         ```
      
      4. **Secure File Serving Helper**:
         ```ruby
         module SecureFileHelper
           def secure_file_path(user_path, safe_directory)
             # Remove any path traversal attempts
             cleaned_path = user_path.gsub(/\\.\\.[\\/\\\\]/, '')
             
             # Join with safe directory
             full_path = File.join(safe_directory, cleaned_path)
             
             # Get canonical path
             canonical_path = File.expand_path(full_path)
             safe_dir = File.expand_path(safe_directory)
             
             # Ensure it's within the safe directory
             return nil unless canonical_path.start_with?(safe_dir)
             return nil unless File.exist?(canonical_path)
             return nil unless File.file?(canonical_path)
             
             canonical_path
           end
         end
         ```
      """,
      
      prevention_tips: """
      - Always add path constraints to glob routes
      - Never use glob parameters directly in file operations
      - Implement server-side path validation and sanitization
      - Use whitelists of allowed files instead of glob routes where possible
      - Validate file extensions and restrict to safe types
      - Ensure files are served from designated safe directories only
      - Use Rails' built-in send_file method with proper path validation
      - Implement comprehensive logging for file access attempts
      - Regular security audits of route definitions and file serving logic
      - Use Content Security Policy to limit resource loading
      - Implement rate limiting on file serving endpoints
      - Monitor for unusual file access patterns
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects unsafe glob routes)
      - Manual code review focusing on route.rb files and glob patterns
      - Grep/ripgrep patterns: \\*\\w+.*to:, match.*\\*, format:.*false
      - Dynamic testing with path traversal payloads: ../../etc/passwd
      - Web application security scanners with path traversal modules
      - Penetration testing with directory traversal attack vectors
      - Automated security scanning with custom Rails glob detection rules
      - Code analysis tools specifically designed for Rails route security
      - Runtime application security monitoring for file access anomalies
      - Log analysis for suspicious file access patterns
      """,
      
      safe_alternatives: """
      # 1. Use specific route parameters instead of globs
      # Bad
      get "files/*path", to: "files#show"
      
      # Good - Specific parameters
      get "files/:category/:filename", to: "files#show",
          constraints: { 
            category: /[a-z]+/, 
            filename: /[\\w\\.\\-]+/ 
          }
      
      # 2. Implement secure file serving controller
      class SecureFilesController < ApplicationController
        SAFE_DIRECTORIES = {
          'docs' => Rails.root.join('public', 'documents'),
          'images' => Rails.root.join('public', 'images'),
          'downloads' => Rails.root.join('public', 'downloads')
        }.freeze
        
        ALLOWED_EXTENSIONS = %w[.pdf .jpg .png .txt .doc].freeze
        
        def show
          category = params[:category]
          filename = params[:filename]
          
          safe_dir = SAFE_DIRECTORIES[category]
          return render_not_found unless safe_dir
          
          extension = File.extname(filename).downcase
          return render_not_found unless ALLOWED_EXTENSIONS.include?(extension)
          
          file_path = safe_dir.join(filename)
          canonical_path = file_path.realpath
          
          # Ensure file is within safe directory
          unless canonical_path.to_s.start_with?(safe_dir.realpath.to_s)
            return render_not_found
          end
          
          if File.exist?(canonical_path) && File.file?(canonical_path)
            send_file(canonical_path, disposition: 'inline')
          else
            render_not_found
          end
        end
        
        private
        
        def render_not_found
          render status: :not_found, plain: 'File not found'
        end
      end
      
      # Routes
      get "files/:category/:filename", to: "secure_files#show",
          constraints: { 
            category: /docs|images|downloads/, 
            filename: /[\\w\\.\\-]+/ 
          }
      
      # 3. Use Rails' Active Storage for file management
      class Document < ApplicationRecord
        has_one_attached :file
        
        validates :category, inclusion: { in: %w[docs images downloads] }
        validates :file, presence: true
        
        def self.find_by_public_id(public_id)
          find_by(public_id: public_id)
        end
      end
      
      # Controller
      class DocumentsController < ApplicationController
        def show
          document = Document.find_by_public_id(params[:id])
          return render_not_found unless document
          
          redirect_to rails_blob_path(document.file, disposition: "inline")
        end
      end
      
      # Routes  
      get "files/:id", to: "documents#show",
          constraints: { id: /[a-zA-Z0-9\\-]+/ }
      
      # 4. Environment-based file serving restrictions
      class FilesController < ApplicationController
        before_action :check_environment
        
        private
        
        def check_environment
          unless Rails.env.development?
            render status: :forbidden, plain: 'File serving disabled'
          end
        end
      end
      
      # 5. Use CDN or external file storage
      class FilesController < ApplicationController
        def show
          file_id = params[:id]
          
          # Validate file ID format
          unless file_id.match?(/\\A[a-zA-Z0-9\\-]+\\z/)
            return render status: :bad_request
          end
          
          # Redirect to CDN
          cdn_url = "https://cdn.example.com/files/\#{file_id}"
          redirect_to cdn_url
        end
      end
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Glob route patterns that are dangerous
        glob_patterns: [
          "*path", "*file", "*filename", "*all", "*splat", "*anything",
          "*asset", "*resource", "*content", "*upload", "*download"
        ],
        
        # Route definition methods
        route_methods: [
          "get", "post", "put", "delete", "patch", "match", "resources", "resource"
        ],
        
        # Dangerous file-serving controllers/actions
        file_serving_patterns: [
          "files#show", "files#serve", "download#serve", "assets#serve",
          "static#serve", "media#show", "uploads#serve", "documents#show"
        ],
        
        # Format constraint indicators
        format_patterns: [
          "format: false", "format: nil", "defaults: { format: nil }"
        ],
        
        # Safe constraint patterns
        safe_constraint_patterns: [
          ~r/constraints:\s*\{\s*\w+:\s*\/[^\/]+\//,  # Has constraints with regex
          ~r/constraints:\s*\{\s*path:\s*\/[^\.]\/\}/,  # Excludes dots
          ~r/constraints.*\\A.*\\z/,                    # Anchored patterns
          ~r/constraints.*[a-z0-9]/                     # Character classes
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # Very high confidence for dangerous patterns
          unsafe_glob_route: +0.5,
          format_disabled: +0.4,
          file_serving_controller: +0.3,
          catch_all_route: +0.6,
          nested_glob_route: +0.2,
          
          # Lower confidence for safer patterns
          has_path_constraints: -0.7,
          specific_file_extensions: -0.4,
          whitelist_validation: -0.5,
          development_only: -0.6,
          
          # Context-based adjustments
          in_test_file: -0.8,
          commented_route: -0.9,
          has_authentication: -0.2,
          uses_active_storage: -0.3
        }
      },
      
      ast_rules: %{
        # Route definition analysis
        route_analysis: %{
          check_glob_parameters: true,
          detect_missing_constraints: true,
          analyze_file_serving_patterns: true,
          check_format_constraints: true
        },
        
        # Path parameter tracking
        parameter_analysis: %{
          track_glob_parameters: true,
          check_parameter_validation: true,
          detect_path_traversal_potential: true,
          analyze_file_access_patterns: true
        },
        
        # Security validation
        security_validation: %{
          check_constraint_presence: true,
          validate_path_restrictions: true,
          detect_unsafe_file_operations: true,
          check_directory_restrictions: true
        },
        
        # Controller action analysis
        controller_analysis: %{
          file_serving_methods: ["send_file", "render", "File.read"],
          dangerous_path_usage: ["params[:path]", "params[:file]"],
          safe_validation_methods: ["File.expand_path", "realpath", "start_with?"]
        }
      }
    }
  end
  
  @impl true
  def applies_to_file?(file_path, frameworks \\ nil) do
    # Apply to Ruby files in Rails projects, especially route definitions
    is_ruby_file = String.ends_with?(file_path, ".rb")
    
    # Rails framework check
    frameworks_list = frameworks || []
    is_rails = "rails" in frameworks_list
    
    # Apply to route files and controllers primarily
    # Glob routes are mainly in config/routes.rb but can be in controllers
    _is_rails_file = String.contains?(file_path, "config/routes") ||
                     String.contains?(file_path, "app/controllers/") ||
                     String.contains?(file_path, "config/application") ||
                     String.contains?(file_path, "lib/")
    
    # If no frameworks specified but it looks like Rails, include it
    inferred_rails = frameworks_list == [] && (
      String.contains?(file_path, "config/routes") ||
      String.contains?(file_path, "app/")
    )
    
    is_ruby_file && (is_rails || inferred_rails)
  end
end