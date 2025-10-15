defmodule Rsolv.Security.Patterns.Ruby.OpenRedirect do
  @moduledoc """
  Detects Open Redirect vulnerabilities in Ruby applications.

  Open redirect vulnerabilities occur when an application redirects users to a URL
  specified by user input without proper validation. Attackers can exploit this to
  redirect victims to malicious websites for phishing or other attacks.

  ## Vulnerability Details

  Ruby on Rails applications are vulnerable when using redirect_to with untrusted
  input such as params, request.referer, or :back without validation. While Rails 7.0+
  provides some protection, developers must still be careful with redirect destinations.

  ### Attack Example
  ```ruby
  # Vulnerable - Direct use of params
  def logout
    redirect_to params[:return_url]
  end

  # Vulnerable - Using request.referer
  def cancel
    redirect_to request.referer || root_path
  end

  # Vulnerable - String interpolation
  def switch_site
    redirect_to "https://\#{params[:subdomain]}.example.com"
  end

  # Secure - Validation with allowlist
  def logout_safe
    safe_urls = [root_path, login_path, dashboard_path]
    return_url = params[:return_url]
    
    if safe_urls.include?(return_url)
      redirect_to return_url
    else
      redirect_to root_path
    end
  end
  ```

  ### Real-World Impact
  - Phishing attacks by redirecting to lookalike domains
  - Credential theft through malicious login pages
  - OAuth token theft via redirect manipulation
  - Bypassing security filters and access controls
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the Open Redirect pattern for Ruby applications.

  Detects redirect operations that use user-controlled input without
  proper validation, which could allow attackers to redirect users to
  malicious websites.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Ruby.OpenRedirect.pattern()
      iex> pattern.id
      "ruby-open-redirect"
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.OpenRedirect.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.OpenRedirect.pattern()
      iex> vulnerable = "redirect_to params[:return_url]"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = Rsolv.Security.Patterns.Ruby.OpenRedirect.pattern()
      iex> safe = "redirect_to root_path"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-open-redirect",
      name: "Open Redirect",
      description:
        "Detects unvalidated redirect destinations that could allow attackers to redirect users to malicious sites",
      type: :open_redirect,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        # redirect_to with direct params
        ~r/redirect_to\s+(?:params|request\.(?:params|parameters))\[/,
        ~r/redirect_to\s+@(?:user|current_user|account|session)[\w_]*(?:\s|$|,)/,

        # redirect_to with request.referer/referrer
        ~r/redirect_to\s+request\.(?:referer|referrer)/,
        ~r/redirect_to\s+request\.env\[['"]HTTP_REFERER['"]\]/,
        ~r/redirect_to\s+request\.headers\[['"]Referer['"]\]/,

        # redirect_to :back (with or without parentheses)
        ~r/redirect_to\s*\(?\s*:back/,

        # redirect_back with user-controlled fallback
        ~r/redirect_back.*fallback_location:\s*(?:params|request\.(?:params|parameters)|user_|@\w+)/,

        # String interpolation in URLs
        ~r/redirect_to\s+["'].*?#\{.*?(?:params|request\.(?:params|parameters)|user_|@\w+).*?\}/,
        ~r/redirect_to\s+["'](?:https?:)?\/\/.*?#\{/,

        # URL construction with user input (must come from user)
        ~r/(?:url|redirect_url|target)\s*=\s*(?:params|request\.(?:params|parameters)|user[\w_]*|@user)[\[\.]/,
        ~r/redirect_to\s+(?:url|redirect_url|target)(?:\s|$)/
      ],
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation:
        "Validate redirect URLs against an allowlist or use URL parsing to ensure redirects stay within your domain",
      test_cases: %{
        vulnerable: [
          "redirect_to params[:return_url]",
          "redirect_to request.referer",
          "redirect_to :back",
          "redirect_back fallback_location: params[:url]",
          "redirect_to \"https://\#{params[:subdomain]}.example.com\""
        ],
        safe: [
          "redirect_to root_path",
          "redirect_to login_url",
          "safe_urls = [root_path, dashboard_path]\nif safe_urls.include?(params[:return_url])\n  redirect_to params[:return_url]\nend",
          "redirect_back fallback_location: root_path"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Open redirect vulnerabilities allow attackers to redirect users from a legitimate website to a malicious one.
      This occurs when applications accept user-controlled input for redirect destinations without proper validation.
      In Ruby on Rails, this commonly happens with redirect_to when using params, request.referer, or :back.
      Attackers exploit this for phishing attacks, OAuth token theft, and bypassing security controls.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-601",
          title: "URL Redirection to Untrusted Site ('Open Redirect')",
          url: "https://cwe.mitre.org/data/definitions/601.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :research,
          id: "rails_open_redirect",
          title: "Rails Open Redirect Guide: Examples and Prevention - StackHawk",
          url: "https://www.stackhawk.com/blog/rails-open-redirect-guide-examples-and-prevention/"
        },
        %{
          type: :research,
          id: "owasp_unvalidated_redirects",
          title: "Unvalidated Redirects and Forwards - OWASP Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Phishing via redirect: example.com/logout?return_url=http://evil.com/fake-login",
        "Protocol-relative URLs: //attacker.com (bypasses some filters)",
        "URL encoding: %2f%2fattacker.com or %252f%252fattacker.com",
        "Subdomain manipulation: http://attacker.com@example.com",
        "OAuth token theft: /oauth/callback?redirect_uri=http://attacker.com",
        "Referer header manipulation for redirect_to request.referer",
        "JavaScript URLs: javascript:alert(document.cookie)"
      ],
      real_world_impact: [
        "Phishing attacks leading to credential theft",
        "OAuth token interception and account takeover",
        "Bypassing authentication by redirecting after login",
        "SEO manipulation and reputation damage",
        "Malware distribution through trusted domain redirects"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-22797",
          description:
            "Rails Action Pack open redirect vulnerability in redirect_to with untrusted input",
          severity: "medium",
          cvss: 6.1,
          note: "Bypass of Rails 7.0 open redirect protection with specially crafted URLs"
        },
        %{
          id: "CVE-2021-22903",
          description: "Rails Action Pack open redirect via specially crafted Host headers",
          severity: "medium",
          cvss: 6.1,
          note: "Host header manipulation allowing redirect to attacker-controlled sites"
        },
        %{
          id: "CVE-2021-22942",
          description: "Rails Host Authorization middleware open redirect vulnerability",
          severity: "medium",
          cvss: 6.1,
          note: "Specially crafted X-Forwarded-Host headers causing malicious redirects"
        },
        %{
          id: "CVE-2023-28362",
          description: "Rails redirect_to XSS vulnerability with user-supplied values",
          severity: "medium",
          cvss: 5.4,
          note: "Allows XSS through redirect_to when downstream services enforce RFC compliance"
        }
      ],
      detection_notes: """
      This pattern detects common open redirect vulnerabilities in Ruby:
      - Direct use of user input in redirect_to (params, request parameters)
      - Unsafe use of request.referer without validation
      - redirect_to :back usage (deprecated but still found)
      - redirect_back with user-controlled fallback locations
      - String interpolation in redirect URLs
      - URL construction with user input before redirection

      The pattern focuses on identifying redirect methods that accept untrusted input
      without validation. AST enhancement provides additional context analysis.
      """,
      safe_alternatives: [
        "Use an allowlist of safe redirect URLs: safe_urls.include?(params[:return_url])",
        "Parse and validate URLs: URI.parse(url).host == request.host",
        "Use Rails route helpers instead of raw URLs: redirect_to root_path",
        "Set allow_other_host: false in Rails 7+: redirect_to url, allow_other_host: false",
        "Implement a safe redirect helper that validates destinations",
        "Use signed URLs for return destinations"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting request.referer without validation",
          "Using params directly in redirect_to",
          "Not validating protocol (http vs https vs javascript)",
          "Allowing subdomain redirects without checking the domain"
        ],
        secure_patterns: [
          "Always validate redirect destinations against an allowlist",
          "Use URI parsing to ensure same-host redirects",
          "Prefer named routes over dynamic URLs",
          "Implement centralized redirect validation"
        ],
        framework_notes: %{
          rails: "Rails 7.0+ has allow_other_host protection but can be bypassed",
          sinatra: "No built-in protection - all redirects need manual validation",
          general: "Never trust user input for redirect destinations"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for open redirect detection.

  This enhancement helps distinguish between actual vulnerabilities and safe redirect
  patterns that use validated URLs or internal routes.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.OpenRedirect.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.OpenRedirect.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.OpenRedirect.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.OpenRedirect.ast_enhancement()
      iex> enhancement.ast_rules.redirect_analysis.check_redirect_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        redirect_analysis: %{
          check_redirect_methods: true,
          redirect_methods: ["redirect_to", "redirect_back", "redirect_back_or_to"],
          dangerous_sources: ["params", "request.referer", "request.referrer", ":back"],
          check_string_interpolation: true,
          check_url_construction: true
        },
        user_input_analysis: %{
          input_sources: [
            "params",
            "request",
            "cookies",
            "session",
            "user_input",
            "@user",
            "@current_user"
          ],
          check_url_construction: true,
          check_variable_assignment: true,
          track_tainted_variables: true,
          check_method_arguments: true
        },
        validation_analysis: %{
          check_url_validation: true,
          safe_redirect_patterns: ["_path", "_url", "root_path", "login_path", "dashboard_path"],
          validation_methods: ["include?", "match?", "start_with?", "URI.parse", "url_for"],
          allowlist_patterns: ["safe_urls", "allowed_urls", "whitelist"],
          rails_protection: ["allow_other_host: false"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        exclude_if_validated: true,
        safe_if_uses: ["safe_urls.include?", "allowed_redirects.include?", "URI.parse"],
        check_static_redirects: true,
        exclude_route_helpers: true,
        exclude_if_allowlisted: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "direct_params_redirect" => 0.4,
          "referer_redirect" => 0.3,
          "back_redirect" => 0.2,
          "string_interpolation_url" => 0.3,
          "has_validation_check" => -0.7,
          "uses_route_helper" => -0.8,
          "static_redirect_path" => -1.0,
          "in_test_code" => -1.0,
          "rails_7_protection" => -0.3
        }
      },
      min_confidence: 0.6
    }
  end
end
