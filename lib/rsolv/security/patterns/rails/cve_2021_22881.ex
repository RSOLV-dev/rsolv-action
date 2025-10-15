defmodule Rsolv.Security.Patterns.Rails.Cve202122881 do
  @moduledoc """
  CVE-2021-22881 - Host Authorization Open Redirect vulnerability in Rails.

  Detects open redirect vulnerabilities in Rails Host Authorization middleware where
  specially crafted Host headers can be used to redirect users to malicious websites.

  ## Vulnerability Details

  This vulnerability affects Rails applications using the Host Authorization middleware
  in Action Pack before versions 6.1.2.1 and 6.0.3.5. When an allowed host contains
  a leading dot, specially crafted Host headers in combination with certain "allowed host"
  formats can cause the Host Authorization middleware to redirect users to a malicious website.

  ### Attack Example
  ```ruby
  # Vulnerable: Using request.host in redirects
  redirect_to request.protocol + request.host + "/callback"

  # Vulnerable: Host header injection
  config.hosts << ".\#{params[:domain]}"

  # Safe: Static redirect URLs
  redirect_to "/dashboard"
  ```

  ## Real-World Impact

  - Phishing attacks through trusted domain redirects
  - Session hijacking via malicious redirects
  - OAuth/authentication flow manipulation
  - Business logic bypass through URL manipulation
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  def pattern do
    %Pattern{
      id: "rails-cve-2021-22881",
      name: "CVE-2021-22881 - Host Authorization Open Redirect",
      description:
        "Open redirect vulnerability in Host Authorization middleware allowing malicious redirects via Host header injection",
      type: :open_redirect,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Direct usage of request.host/protocol in redirects (exclude commented lines)
        ~r/^(?!\s*#)(?!\s*\/\/).*redirect_to.*?request\.(?:protocol|host|url|original_url)/,
        # Host header string interpolation in redirects
        ~r/^(?!\s*#)(?!\s*\/\/).*redirect_to.*?#\{request\.(?:protocol|host)\}/,
        # url_for with request.host parameter (broader pattern)
        ~r/^(?!\s*#)(?!\s*\/\/).*url_for\s*\([^)]*host:\s*request\.host(?:_with_port)?/,
        # redirect_to with url_for and host parameter
        ~r/^(?!\s*#)(?!\s*\/\/).*redirect_to.*?url_for\s*\([^)]*host:\s*params\[/,
        # root_url with host parameter from params
        ~r/^(?!\s*#)(?!\s*\/\/).*redirect_to.*?root_url\s*\([^)]*host:\s*params\[/,
        # Dynamic host configuration with user input (broader pattern)
        ~r/config\.hosts.*?=.*?\[.*?"\#\{request\.host\}/,
        # Host configuration with user input append
        ~r/config\.hosts.*?<<.*?"\.\#\{(?:params|request)\[/,
        # Host authorization bypass patterns
        ~r/Rails\.application\.config\.hosts.*?<<.*?request\.host/,
        # X-Forwarded-Host usage in redirects
        ~r/redirect_to.*?request\.headers\[['"]X-Forwarded-Host['"]]/,
        # Host header patterns (for header detection)
        ~r/^Host:\s*\w+/,
        # X-Forwarded-Host header patterns
        ~r/^X-Forwarded-Host:\s*\w+/
      ],
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation:
        "Use static redirect URLs or validate Host headers against an allowlist. Never use user-controlled Host headers directly in redirects.",
      test_cases: %{
        vulnerable: [
          "redirect_to request.protocol + request.host + \"/path\"",
          "redirect_to \"\#{request.protocol}\#{request.host}/callback\"",
          "url_for(host: request.host, path: params[:path])",
          "config.hosts << \".\#{params[:domain]}\""
        ],
        safe: [
          "redirect_to root_url",
          "redirect_to '/dashboard'",
          "redirect_to home_path",
          "config.hosts = ['example.com', 'www.example.com']"
        ]
      }
    }
  end

  def vulnerability_metadata do
    %{
      description: """
      CVE-2021-22881 is a Host Authorization open redirect vulnerability in Rails Action Pack
      that affects applications using the Host Authorization middleware. The vulnerability occurs
      when specially crafted Host headers are used in combination with certain allowed host formats,
      particularly when allowed hosts contain leading dots. This can cause the Host Authorization
      middleware to redirect users to malicious websites, enabling phishing attacks and session hijacking.
      """,
      references: [
        %{
          type: :cve,
          id: "CVE-2021-22881",
          title: "Host Authorization Open Redirect in Rails Action Pack",
          url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22881"
        },
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
          type: :advisory,
          id: "GHSA-qphc-hf5q-v8fc",
          title: "Rails Host Authorization Open Redirect Advisory",
          url: "https://github.com/advisories/GHSA-qphc-hf5q-v8fc"
        },
        %{
          type: :research,
          id: "rails_host_header_injection",
          title: "Rails Host Header Injection Guide",
          url:
            "https://guides.rubyonrails.org/security.html#dns-rebinding-and-host-header-attacks"
        }
      ],
      attack_vectors: [
        "Host header manipulation: Set Host: evil.com to redirect to attacker-controlled domain",
        "X-Forwarded-Host injection: Use proxy headers to bypass host validation",
        "Leading dot exploitation: Leverage config.hosts patterns like '.example.com' to redirect to subdomains",
        "OAuth flow hijacking: Redirect authentication callbacks to capture tokens",
        "Password reset poisoning: Manipulate password reset links to point to attacker domains"
      ],
      real_world_impact: [
        "Phishing attacks through trusted domain redirects enabling credential theft",
        "Session hijacking via malicious redirects that capture authentication tokens",
        "OAuth authentication flow manipulation allowing account takeover",
        "Business logic bypass through redirect URL manipulation",
        "Brand reputation damage from hosting redirects to malicious content"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-22881",
          description: "Host Authorization open redirect in Rails Action Pack middleware",
          severity: "medium",
          cvss: 6.1,
          note:
            "Specially crafted Host headers can redirect to malicious websites when allowed hosts contain leading dots"
        }
      ],
      detection_notes: """
      This pattern detects Host Authorization open redirect vulnerabilities by identifying:
      1. Direct usage of request.host, request.protocol, or request.url in redirect_to calls
      2. String interpolation of request headers in redirect URLs
      3. url_for calls that use request.host with user-controlled parameters
      4. Dynamic host configuration that includes user input
      5. Usage of X-Forwarded-Host headers in redirects

      The detection excludes commented code and focuses on actual vulnerable redirect patterns.
      """,
      safe_alternatives: [
        "Use static redirect URLs: redirect_to '/dashboard' instead of dynamic host-based URLs",
        "Implement host allowlist validation: validate redirect hosts against a predefined list",
        "Use Rails built-in helpers: prefer root_url, home_path over manual URL construction",
        "Configure Host Authorization properly: set config.hosts to specific allowed domains",
        "Validate redirect URLs: implement URL validation before any redirect operations"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting request.host header without validation",
          "Using leading dots in config.hosts without understanding implications",
          "Assuming X-Forwarded-Host headers are safe in load-balanced environments"
        ],
        secure_patterns: [
          "Always validate redirect destinations against an allowlist",
          "Use relative URLs for internal redirects when possible",
          "Implement proper Host Authorization middleware configuration"
        ],
        rails_specific_notes: [
          "Affects Rails >= 6.0.0 with Host Authorization middleware enabled",
          "Fixed in Rails 6.1.2.1 and 6.0.3.5",
          "Related to DNS rebinding attack protection mechanisms"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual Host Authorization vulnerabilities
  and safe redirect patterns in Rails applications.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Rails.Cve202122881.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Rails.Cve202122881.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Rails.Cve202122881.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"

      iex> enhancement = Rsolv.Security.Patterns.Rails.Cve202122881.ast_enhancement()
      iex> "redirect_to" in enhancement.ast_rules.redirect_analysis.redirect_methods
      true
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        redirect_analysis: %{
          redirect_methods: ["redirect_to", "url_for", "redirect_back"],
          check_host_usage: true,
          check_request_headers: true,
          dangerous_headers: ["Host", "X-Forwarded-Host", "X-Forwarded-Proto"]
        },
        host_configuration: %{
          config_patterns: ["config.hosts", "Rails.application.config.hosts"],
          check_dynamic_assignment: true,
          user_input_sources: ["params", "request", "headers"]
        },
        url_construction: %{
          check_string_interpolation: true,
          dangerous_methods: ["request.host", "request.protocol", "request.url"],
          safe_methods: ["root_url", "home_path", "static_paths"]
        }
      },
      context_rules: %{
        exclude_patterns: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/\.example/, ~r/\.sample/],
        check_host_validation: true,
        safe_host_patterns: [
          "localhost",
          "127.0.0.1",
          "example.com",
          "static_domain"
        ],
        exclude_if_validated: true,
        safe_redirect_patterns: [
          # Static relative URLs
          ~r/redirect_to\s+['"]\/[^"']*['"]/,
          # Rails path helpers
          ~r/redirect_to\s+\w+_path/,
          # Rails URL helpers (when not using request.host)
          ~r/redirect_to\s+\w+_url/
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "uses_request_host" => 0.2,
          "string_interpolation_host" => 0.15,
          "dynamic_host_config" => 0.2,
          "has_host_validation" => -0.3,
          "uses_static_redirect" => -0.4,
          "in_test_code" => -0.5,
          "has_allowlist_validation" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
