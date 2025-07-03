defmodule Rsolv.Security.Patterns.Rails.ActionmailerInjection do
  use Rsolv.Security.Patterns.PatternBase
  
  def pattern do
    %Rsolv.Security.Pattern{
      id: "rails-actionmailer-injection",
      name: "ActionMailer Injection",
      description: "Email header injection through ActionMailer with unvalidated input",
      type: :template_injection,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Direct params usage in mail() method fields (exclude comments)
        ~r/^(?!.*#).*mail\s*\(\s*to:\s*params\[/,
        ~r/^(?!.*#).*mail\s*\(\s*.*?from:\s*params\[/,
        ~r/^(?!.*#).*mail\s*\(\s*.*?cc:\s*params\[/,
        ~r/^(?!.*#).*mail\s*\(\s*.*?bcc:\s*params\[/,
        ~r/^(?!.*#).*mail\s+to:\s*params\[/,
        ~r/^(?!.*#).*mail\s+from:\s*params\[/,
        ~r/^(?!.*#).*mail\s+cc:\s*params\[/,
        ~r/^(?!.*#).*mail\s+bcc:\s*params\[/,
        
        # Hash syntax for mail() method
        ~r/mail\s*\(\s*:to\s*=>\s*params\[/,
        ~r/mail\s*\(\s*:from\s*=>\s*params\[/,
        ~r/mail\s*\(\s*:cc\s*=>\s*params\[/,
        ~r/mail\s*\(\s*:bcc\s*=>\s*params\[/,
        
        # String interpolation with params in email headers (exclude sanitized)
        ~r/mail\s*\(\s*.*?subject:\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        ~r/mail\s*\(\s*.*?from:\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        ~r/mail\s+subject:\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        ~r/mail\s+from:\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        
        # Hash syntax with string interpolation (exclude sanitized)
        ~r/mail\s*\(\s*:subject\s*=>\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        ~r/mail\s*\(\s*:from\s*=>\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/,
        
        # ERB template usage with params in body (with and without parens)
        ~r/mail\s*\(\s*.*?body:\s*ERB\.new\s*\(\s*params\[/,
        ~r/mail\s*\(\s*.*?body:\s*ERB\.new\s+params\[/,
        ~r/mail\s+body:\s*ERB\.new\s*\(\s*params\[/,
        ~r/mail\s+body:\s*ERB\.new\s+params\[/,
        ~r/mail\s*\(\s*:body\s*=>\s*ERB\.new\s*\(\s*params\[/,
        ~r/mail\s*\(\s*:body\s*=>\s*ERB\.new\s+params\[/,
        
        # Template name from params
        ~r/mail\s*\(\s*.*?template_name:\s*params\[/,
        ~r/mail\s+template_name:\s*params\[/,
        ~r/mail\s*\(\s*:template_name\s*=>\s*params\[/,
        
        # Multiline mail configurations (allow newlines with 'm' flag, exclude sanitized and comments)
        ~r/^(?!\s*#).*mail\s*\([\s\S]*?subject:\s*[\"'`].*?#\{(?!.*sanitize)[^}]*params/m,
        ~r/^(?!\s*#).*mail\s*\([\s\S]*?body:\s*ERB\.new\s*\(\s*params\[/m,
        ~r/^(?!\s*#).*mail\s*\([\s\S]*?to:\s*params\[/m
      ],
      cwe_id: "CWE-117",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize email headers. Use address validation for email fields.",
      test_cases: %{
        vulnerable: [
          "mail(to: params[:email], subject: \"Hello \#{params[:name]}\")",
          "mail(from: \"\#{params[:sender]} <noreply@example.com>\")",
          "mail(body: ERB.new(params[:template]))",
          "mail(template_name: params[:email_template])"
        ],
        safe: [
          "mail(to: validate_email(params[:email]), subject: \"Hello \#{sanitize(params[:name])}\")",
          "mail(from: 'noreply@example.com')",
          "mail(body: render_template('welcome'))",
          "mail(template_name: 'welcome_email')"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      ActionMailer Injection in Rails applications occurs when unvalidated user 
      input is directly used in ActionMailer method calls, particularly in email 
      headers like to, from, subject, cc, and bcc fields. This vulnerability 
      allows attackers to inject arbitrary email headers through CRLF injection, 
      leading to email spoofing, spam injection, and phishing attacks.
      """,
      attack_vectors: """
      1. Email Header Injection via CRLF: Injecting CRLF sequences to add new headers
      2. Sender Spoofing: Manipulating From header to impersonate trusted senders
      3. Subject Line Injection: Injecting malicious content into email subjects
      4. Email Body Template Injection: Using ERB templates with unsanitized params
      """,
      business_impact: """
      - Brand reputation damage from spam and phishing emails
      - Legal liability for facilitating unauthorized communications
      - Email server blacklisting affecting legitimate delivery
      - Customer trust erosion from fraudulent emails
      """,
      technical_impact: """
      - Complete control over email headers and content
      - SMTP server abuse for unauthorized emails
      - Email authentication bypass through header manipulation
      - Email delivery system compromise
      """,
      likelihood: "Medium - ActionMailer injection is common in applications that directly use params in email methods",
      cve_examples: """
      CVE-2024-47889 - Possible ReDoS vulnerability in ActionMailer block_format helper
      CVE-2020-8163 - Code injection in Rails Action View render affecting ActionMailer
      GHSA-rg5m-3fqp-6px8 - ActionMailer email address processing causes Denial of Service
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-117: Improper Output Neutralization for Logs",
        "CWE-93: Improper Neutralization of CRLF Sequences",
        "PCI DSS 6.5.1 - Injection flaws including SMTP injection"
      ],
      remediation_steps: """
      1. Validate and sanitize all email addresses before using in mail() methods
      2. Use allowlists for template names and email types  
      3. Implement proper CRLF filtering for email headers
      4. Use model attributes instead of raw request parameters
      5. Implement email rate limiting to prevent abuse
      """,
      prevention_tips: """
      - Never use params directly in ActionMailer method calls
      - Always validate email addresses before using them
      - Sanitize user input used in email subjects and content
      - Use allowlists for template names
      - Implement proper error handling without information disclosure
      """,
      detection_methods: """
      - Static analysis with Brakeman scanner
      - Manual code review of mailer classes
      - Dynamic testing with crafted email input containing CRLF sequences
      - Email header analysis in test environments
      - Penetration testing with email injection payloads
      """,
      safe_alternatives: """
      # Safe email validation and composition
      mail(
        to: validate_email(params[:email]),
        subject: "Welcome \#{sanitize(params[:name])}",
        from: 'noreply@example.com'
      )
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        # Email-related methods and fields
        email_fields: [
          "to", "from", "cc", "bcc", "subject", "body", "template_name"
        ],
        
        # Dangerous sources of user input
        dangerous_sources: [
          "params", "request", "session", "cookies"
        ],
        
        # ActionMailer methods that can be vulnerable
        mail_methods: [
          "mail", "deliver", "deliver_now", "deliver_later"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/validate_email\s*\(/,                      # Email validation
          ~r/sanitize\s*\(/,                           # Content sanitization
          ~r/User\.find\([^}]*\)\.email/,              # Model-based email
          ~r/current_user\.email/,                     # Current user email
          ~r/[A-Z_]+EMAIL/,                            # Constant emails
          ~r/['"][^'"]*@[^'"]*['"]/                    # Static email addresses
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous patterns
          direct_params_usage: +0.4,
          string_interpolation_params: +0.3,
          erb_template_params: +0.5,
          multiple_vulnerable_fields: +0.3,
          
          # Lower confidence for safer patterns
          email_validation_present: -0.4,
          content_sanitization: -0.5,
          model_based_email: -0.6,
          static_email_values: -0.7,
          
          # Context-based adjustments
          in_mailer_class: +0.2,
          in_test_file: -0.8
        }
      },
      
      ast_rules: %{
        # Email analysis
        email_analysis: %{
          check_mail_method_calls: true,
          detect_email_field_injection: true,
          validate_email_sources: true,
          check_template_usage: true
        },
        
        # Input validation
        input_validation: %{
          check_params_usage: true,
          detect_user_input: true,
          validate_sanitization: true,
          check_validation_methods: true
        }
      }
    }
  end
  
end

