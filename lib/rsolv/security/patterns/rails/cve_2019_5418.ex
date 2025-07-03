defmodule Rsolv.Security.Patterns.Rails.Cve20195418 do
  @moduledoc """
  CVE-2019-5418 - File Content Disclosure vulnerability pattern for Rails applications.
  
  This pattern detects the critical path traversal vulnerability in Rails Action View 
  (versions <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 and v3) where specially crafted 
  Accept headers combined with render file: calls can expose arbitrary files from 
  the server's filesystem.
  
  ## Background
  
  CVE-2019-5418 is a file content disclosure vulnerability that allows attackers to
  read arbitrary files by manipulating the Accept header and exploiting the render
  file: functionality in Rails controllers.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. Controllers use render file: with user-controlled input
  2. Controllers use render template: or render partial: with user input
  3. Path parameters from users are incorporated into file paths
  4. No proper validation or whitelisting of allowed files
  
  ## Examples
  
      # VULNERABLE - Direct file path from params
      render file: params[:template]
      
      # VULNERABLE - Path construction with user input
      render file: "\#{Rails.root}/public/\#{params[:file]}"
      
      # VULNERABLE - Template path from params
      render template: params[:template_path]
      
      # SAFE - Static file path
      render file: Rails.root.join('app', 'views', 'reports', 'annual.html.erb')
      
      # SAFE - Whitelisted templates
      ALLOWED_TEMPLATES = %w[user admin guest]
      render template: "templates/\#{template}" if ALLOWED_TEMPLATES.include?(template)
  """
  
  use Rsolv.Security.Patterns.PatternBase
  
  def pattern do
    %Rsolv.Security.Pattern{
      id: "rails-cve-2019-5418",
      name: "CVE-2019-5418 - File Content Disclosure",
      description: "Path traversal vulnerability in render file allowing arbitrary file disclosure",
      type: :path_traversal,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Direct render file with params (exclude comments)
        ~r/^(?!.*#).*render\s+file:\s*params\[/m,
        
        # Render file with string interpolation containing params (handle escaped)
        ~r/^(?!.*#).*render\s+file:\s*["'`].*?\\*#\{[^}]*params/m,
        
        # Render template with params (any params usage)
        ~r/^(?!.*#).*render\s+template:\s*params\[/m,
        
        # Render partial with directory traversal patterns (handle escaped)
        ~r/^(?!.*#).*render\s+partial:\s*["'`]\.\.\/\\*#\{[^}]*params/m,
        
        # Variable assignment with params followed by render file
        ~r/(?:file_path|path|template)\s*=\s*.*?params\[[\s\S]*?render\s+file:/m,
        
        # File.join with params used in render
        ~r/File\.join\(.*?params\[[\s\S]*?render\s+file:/m,
        
        # Rails.root with params interpolation (handle escaped)
        ~r/^(?!.*#).*render\s+file:\s*["'`].*?Rails\.root.*?\\*#\{[^}]*params/m,
        
        # Variable assignment to params then used in render
        ~r/(\w+)\s*=\s*params\[[\s\S]*?render\s+(?:file|template|partial):\s*\1/m,
        
        # Render file with variable containing path
        ~r/^(?!.*#).*render\s+file:\s*\w*[pP]ath/m,
        
        # Variable assignment with path traversal then render partial
        ~r/\w+_path\s*=\s*["'`].*?\.\.\/.*?\\*#\{.*?params[\s\S]*?render\s+partial:/m
      ],
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Never use user input directly in Rails render file/template. Use predefined Rails templates or validate against allowlist.",
      test_cases: %{
        vulnerable: [
          "render file: params[:template]"
        ],
        safe: [
          "allowed = [\"user\", \"admin\"]\nrender template: allowed.include?(params[:type]) ? params[:type] : \"default\""
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      CVE-2019-5418 is a critical file content disclosure vulnerability in Rails Action View
      that allows attackers to read arbitrary files from the server's filesystem. The 
      vulnerability exists in Action View versions <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 
      and v3. By crafting a malicious Accept header and exploiting render file: calls with 
      user-controlled input, attackers can traverse directories and access sensitive files 
      including database configurations, secrets, source code, and system files.
      
      The vulnerability is particularly dangerous because:
      1. It provides direct file system access
      2. Can expose database credentials and API keys
      3. Allows reading application source code
      4. Can access system files like /etc/passwd
      5. Often chained with other vulnerabilities for RCE
      """,
      
      attack_vectors: """
      1. **Malicious Accept Header**: Crafting Accept headers like "../../../../../etc/passwd{{"
      2. **Direct Parameter Injection**: Manipulating template parameters to include path traversal
      3. **Path Traversal Sequences**: Using ../ sequences to navigate to sensitive files
      4. **Absolute Path Access**: Providing absolute paths like /etc/passwd
      5. **Rails.root Manipulation**: Exploiting string interpolation with Rails.root
      6. **Template Path Injection**: Injecting paths via template or partial parameters
      7. **File Extension Bypass**: Manipulating extensions to access non-template files
      8. **Null Byte Injection**: Using null bytes to bypass file extension checks
      9. **URL Encoding**: Using encoded traversal sequences like %2e%2e%2f
      10. **Double Encoding**: Bypassing filters with double-encoded sequences
      """,
      
      business_impact: """
      - Complete source code disclosure exposing intellectual property
      - Database credential theft leading to data breaches
      - API key and secret exposure compromising third-party services
      - Customer data exposure violating privacy regulations
      - Competitive disadvantage from disclosed business logic
      - Legal liability and regulatory fines (GDPR, CCPA, PCI-DSS)
      - Reputation damage and loss of customer trust
      - Financial losses from incident response and remediation
      - Potential for follow-up attacks using disclosed information
      - Service disruption if exploited for denial of service
      """,
      
      technical_impact: """
      - Arbitrary file reading from the filesystem
      - Source code disclosure including business logic
      - Configuration file exposure (database.yml, secrets.yml)
      - Credential disclosure (passwords, API keys, tokens)
      - Private key exposure (SSL certificates, SSH keys)
      - System file access (/etc/passwd, /etc/shadow on misconfigured systems)
      - Application architecture and infrastructure disclosure
      - Potential for privilege escalation using disclosed credentials
      - Information gathering for targeted attacks
      - Possible chaining with CVE-2019-5420 for RCE
      """,
      
      likelihood: "High - Many Rails applications use dynamic template rendering and the vulnerability is easy to exploit with basic HTTP requests",
      
      cve_details: """
      CVE ID: CVE-2019-5418
      CVSS Score: 7.5 (HIGH)
      CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
      
      Affected Versions:
      - Rails 5.2.0 to 5.2.2.0 (fixed in 5.2.2.1)
      - Rails 5.1.0 to 5.1.6.1 (fixed in 5.1.6.2)
      - Rails 5.0.0 to 5.0.7.1 (fixed in 5.0.7.2)
      - Rails 4.2.0 to 4.2.11.0 (fixed in 4.2.11.1)
      - All Rails 3.x versions
      
      Discovery: Reported by John Hawthorn of GitHub
      Disclosure Date: March 13, 2019
      
      Related Vulnerabilities:
      - Often chained with CVE-2019-5420 (DoubleTap RCE)
      - Similar to CVE-2016-0752 (older Rails directory traversal)
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-22: Path Traversal",
        "CWE-35: Path Traversal: '.../...//'",
        "CWE-40: Path Traversal: '\\\\..\\\\filename'",
        "PCI DSS 6.5.8 - Improper file uploads",
        "NIST SP 800-53 - AC-3 Access Enforcement",
        "ISO 27001 - A.9.4.1 Information access restriction",
        "ASVS 4.0 - V5.2 File Upload Requirements",
        "SANS Top 25 - CWE-22 Path Traversal"
      ],
      
      remediation_steps: """
      1. **Immediate Patching (Critical)**:
         ```bash
         # Update Rails to patched versions
         # For Rails 5.2.x
         gem 'rails', '>= 5.2.2.1'
         
         # For Rails 5.1.x
         gem 'rails', '>= 5.1.6.2'
         
         # For Rails 5.0.x
         gem 'rails', '>= 5.0.7.2'
         
         # For Rails 4.2.x
         gem 'rails', '>= 4.2.11.1'
         
         # Then run
         bundle update rails
         ```
      
      2. **Code Remediation - Never Use User Input in File Paths**:
         ```ruby
         # NEVER DO THIS - Direct user input
         class ReportsController < ApplicationController
           def show
             render file: params[:template]  # VULNERABLE!
           end
         
         # SAFE - Use predefined templates
         class ReportsController < ApplicationController
           ALLOWED_REPORTS = {
             'monthly' => 'reports/monthly',
             'annual' => 'reports/annual',
             'quarterly' => 'reports/quarterly'
           }.freeze
           
           def show
             report_type = params[:type]
             template = ALLOWED_REPORTS[report_type] || 'reports/default'
             render template: template
           end
         end
         ```
      
      3. **Whitelist Approach**:
         ```ruby
         class DocumentsController < ApplicationController
           # Define allowed documents
           ALLOWED_DOCUMENTS = %w[
             terms_of_service
             privacy_policy
             user_agreement
           ].freeze
           
           def show
             doc_name = params[:document]
             
             unless ALLOWED_DOCUMENTS.include?(doc_name)
               render plain: "Document not found", status: 404
               return
             end
             
             # Safe to render from predefined location
             render file: Rails.root.join('app', 'views', 'documents', "\#{doc_name}.html.erb")
           end
         end
         ```
      
      4. **Use Rails Conventions**:
         ```ruby
         class ReportsController < ApplicationController
           # Instead of render file:, use Rails conventions
           def monthly
             @report = Report.monthly
             render :monthly  # Renders app/views/reports/monthly.html.erb
           end
           
           def annual
             @report = Report.annual
             # Implicit render - Rails automatically renders annual.html.erb
           end
         end
         ```
      
      5. **Input Validation and Sanitization**:
         ```ruby
         class SecureController < ApplicationController
           before_action :validate_template_param, only: [:show]
           
           private
           
           def validate_template_param
             # Strict validation - alphanumeric and underscores only
             unless params[:template] =~ /\\A[a-zA-Z0-9_]+\\z/
               render plain: "Invalid template name", status: 400
             end
         end
         ```
      """,
      
      prevention_tips: """
      - Always update Rails to the latest patched version
      - Never use user input directly in file paths
      - Use whitelisting for any dynamic template selection
      - Follow Rails conventions for rendering views
      - Implement strict input validation
      - Use static analysis tools to detect vulnerable patterns
      - Regular security audits of render calls
      - Monitor for suspicious file access patterns
      - Implement proper logging and alerting
      - Use Content Security Policy headers
      - Disable file rendering in production when not needed
      - Implement rate limiting to prevent exploitation attempts
      """,
      
      detection_methods: """
      - Static code analysis for render file: patterns with user input
      - Grep for vulnerable render patterns in codebase
      - Dynamic testing with path traversal payloads
      - Monitor application logs for traversal sequences
      - File access monitoring for unusual file reads
      - Web Application Firewall (WAF) rules for path traversal
      - Automated security scanning with tools like Brakeman
      - Manual code review of all render calls
      - Penetration testing with Accept header manipulation
      - Runtime Application Self-Protection (RASP) solutions
      """,
      
      safe_alternatives: """
      # 1. Use Implicit Rendering
      class UsersController < ApplicationController
        def show
          @user = User.find(params[:id])
          # Rails automatically renders app/views/users/show.html.erb
        end
      
      # 2. Explicit Action Rendering
      class ReportsController < ApplicationController
        def summary
          @data = generate_summary_data
          render :summary  # Renders app/views/reports/summary.html.erb
        end
      
      # 3. Conditional Rendering with Whitelist Approach
      class DocumentsController < ApplicationController
        # Use a whitelist to control allowed templates
        TEMPLATES = {
          'tos' => 'documents/terms_of_service',
          'privacy' => 'documents/privacy_policy'
        }.freeze
        
        def show
          template = TEMPLATES[params[:doc]] || 'documents/not_found'
          render template: template
        end
      
      # 4. Secure File Downloads
      class DownloadsController < ApplicationController
        def file
          # Use send_file with predefined paths
          filename = params[:file]
          
          # Validate filename
          unless filename =~ /\\A[a-zA-Z0-9_-]+\\.pdf\\z/
            head :not_found
            return
          end
          
          file_path = Rails.root.join('secure_downloads', filename)
          
          if File.exist?(file_path)
            send_file file_path, disposition: 'attachment'
          else
            head :not_found
          end
        end
      
      # 5. API Responses (No File Rendering)
      class ApiController < ApplicationController
        def data
          result = process_request(params[:query])
          render json: result  # Safe - no file system access
        end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Render methods that can be vulnerable
        render_methods: [
          "render", "render_to_string", "render_to_body"
        ],
        
        # Dangerous render options
        dangerous_options: [
          "file:", "template:", "partial:", "layout:"
        ],
        
        # Path manipulation methods
        path_methods: [
          "File.join", "Rails.root.join", "Pathname.new",
          ".join", "+", "<<", "concat"
        ],
        
        # Safe render patterns
        safe_patterns: [
          ~r/render\s+:[\w_]+/,                    # Symbol rendering
          ~r/render\s+json:/,                      # JSON rendering
          ~r/render\s+xml:/,                       # XML rendering
          ~r/render\s+plain:/,                     # Plain text
          ~r/render\s+status:/,                    # Status only
          ~r/ALLOWED_\w+\.include\?/               # Whitelist check
        ],
        
        # User input sources
        user_inputs: [
          "params[", "params.", "request.params",
          "cookies[", "session[", "request.env"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous patterns
          params_in_file_path: +0.7,
          template_from_params: +0.6,
          path_traversal_sequence: +0.5,
          rails_root_with_params: +0.6,
          
          # Medium confidence
          indirect_params_usage: +0.3,
          partial_with_dynamic_path: +0.4,
          
          # Lower confidence for safer patterns
          whitelist_check_present: -0.6,
          static_file_path: -0.8,
          symbol_render: -0.9,
          validation_present: -0.5,
          
          # Context adjustments
          in_controller: +0.2,
          in_view: +0.1,
          in_helper: +0.1,
          
          # File location adjustments
          in_test_file: -0.9,
          in_spec_file: -0.9,
          commented_line: -1.0
        }
      },
      
      ast_rules: %{
        # Render analysis
        render_analysis: %{
          detect_file_option: true,
          detect_template_option: true,
          detect_partial_option: true,
          check_option_values: true,
          analyze_path_construction: true
        },
        
        # Path analysis
        path_analysis: %{
          detect_traversal_sequences: true,
          check_path_joins: true,
          analyze_string_interpolation: true,
          detect_absolute_paths: true
        },
        
        # Input tracking
        input_analysis: %{
          track_params_usage: true,
          track_variable_flow: true,
          detect_indirect_usage: true,
          check_sanitization: true
        },
        
        # Safe pattern detection
        safe_analysis: %{
          detect_whitelists: true,
          check_validations: true,
          identify_static_paths: true,
          recognize_safe_methods: true
        }
      }
    }
  end
  
end

