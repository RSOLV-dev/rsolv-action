defmodule RsolvApi.Security.Patterns.Elixir.UnsafeRedirect do
  @moduledoc """
  Open Redirect Vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects Phoenix controllers that perform redirects to untrusted URLs
  provided by user input, which can lead to phishing attacks and social engineering.

  ## Vulnerability Details

  Open redirect vulnerabilities occur when:
  - Using `redirect(conn, external: user_input)` without validation
  - Redirecting to URLs from request parameters without allowlist checking
  - String interpolation including user data in external redirect URLs
  - Missing validation of redirect destinations against trusted domains
  - Accepting arbitrary URLs from query parameters, form data, or headers

  ## Technical Impact

  Security risks through:
  - Phishing attacks using the trusted domain to redirect to malicious sites
  - Social engineering campaigns leveraging organizational reputation
  - Bypassing security controls through trusted domain redirection
  - Credential harvesting through convincing phishing pages
  - Malware distribution via trusted redirect chains

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - direct user input redirection
  def callback(conn, %{"return_to" => url}) do
    redirect(conn, external: url)
  end
  
  # VULNERABLE - parameter-based external redirect
  def redirect_user(conn, params) do
    redirect(conn, external: params["redirect_url"])
  end
  
  # VULNERABLE - header-based redirection
  def return_redirect(conn, _params) do
    referer = get_req_header(conn, "referer") |> List.first()
    redirect(conn, external: referer)
  end
  
  # VULNERABLE - string interpolation with user data
  def custom_redirect(conn, %{"path" => path}) do
    redirect(conn, external: "https://api.example.com/" <> path)
  end
  ```

  Safe alternatives:
  ```elixir
  # SAFE - allowlist validation
  def callback(conn, %{"return_to" => url}) do
    if URI.parse(url).host in @allowed_hosts do
      redirect(conn, external: url)
    else
      redirect(conn, to: Routes.home_path(conn, :index))
    end
  end
  
  # SAFE - local redirects only
  def redirect_user(conn, %{"path" => path}) do
    redirect(conn, to: Routes.page_path(conn, :show, path))
  end
  
  # SAFE - hardcoded external redirects
  def oauth_redirect(conn, _params) do
    redirect(conn, external: "https://oauth.trusted-provider.com/authorize")
  end
  
  # SAFE - validation function
  def safe_redirect(conn, %{"url" => url}) do
    case validate_redirect_url(url) do
      {:ok, safe_url} -> redirect(conn, external: safe_url)
      :error -> redirect(conn, to: "/")
    end
  end
  ```

  ## Attack Scenarios

  1. **Phishing Campaign**: Attacker crafts URL like `https://trusted-site.com/redirect?url=https://evil-site.com/login`
     that redirects users to a fake login page harvesting credentials

  2. **Social Engineering**: Using trusted domain reputation in emails or messages
     to redirect users to malicious content or malware downloads

  3. **OAuth Exploitation**: Manipulating OAuth callback URLs to redirect
     authorization codes to attacker-controlled endpoints

  4. **SEO Manipulation**: Using trusted domains to boost malicious site rankings
     through redirect chains and link manipulation

  ## References

  - CVE-2017-1000163: Phoenix Framework Arbitrary URL Redirect
  - CWE-601: URL Redirection to Untrusted Site (Open Redirect)
  - OWASP Top 10 2021 - A01: Broken Access Control
  - Phoenix Security Advisory: https://github.com/advisories/GHSA-cmfh-8f8r-fj96
  - OWASP Unvalidated Redirects and Forwards Cheat Sheet
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-unsafe-redirect",
      name: "Open Redirect Vulnerability",
      description: "Unvalidated redirects to user-controlled URLs can enable phishing attacks and social engineering",
      type: :open_redirect,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # Parameter-based redirects with user input (bracket notation) - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*params\[/m,
        # Parameter-based redirects with user input (dot notation) - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*params\./m,
        # Conn params redirects - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*conn\s*\.\s*(?:params|query_params|body_params)/m,
        
        # Variable-based redirects from user input - exclude comments and single 'url' variable
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*(?:user_|redirect_|return_|next_|callback_)\w+/m,
        # Variable-based redirects with compound names - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*\w+_(?:url|path)\w*/m,
        
        # Request header based redirects - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*get_req_header/m,
        
        # String interpolation patterns - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*[^,)]*#\{[^}]+\}/m,
        
        # String concatenation patterns - exclude comments
        ~r/^(?!\s*#).*redirect\s*\(\s*conn\s*,[\s\n]*external:\s*[^,)]*<>\s*(?:params|path|url|user_|redirect_)/m
      ],
      default_tier: :ai,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against an allowlist of trusted domains or use local redirects with :to option",
      test_cases: %{
        vulnerable: [
          ~S|redirect(conn, external: params["return_to"])|,
          ~S|redirect(conn, external: user_url)|,
          ~S|redirect(conn, external: redirect_url)|,
          ~S|redirect(conn, external: "https://api.example.com/" <> params[:path])|,
          ~S|redirect(conn, external: get_req_header(conn, "referer"))|
        ],
        safe: [
          ~S|redirect(conn, to: Routes.home_path(conn, :index))|,
          ~S|redirect(conn, external: "https://trusted-site.com")|,
          ~S|if URI.parse(url).host in @allowed_hosts do
  redirect(conn, external: url)
else
  redirect(conn, to: Routes.home_path(conn, :index))
end|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. phishing attacks: Redirect users from trusted domain to malicious login pages
      2. Social Engineering: Leverage organizational reputation for credible malicious links
      3. OAuth Manipulation: Redirect authorization codes to attacker-controlled endpoints
      4. Malware Distribution: Use trusted domains to distribute malicious software
      """,
      business_impact: """
      Medium: Open redirects can lead to:
      - reputation damage from association with phishing campaigns
      - Customer credential theft through convincing phishing pages
      - Regulatory compliance issues if used for data harvesting
      - SEO manipulation affecting search rankings
      - Loss of customer trust and confidence in security
      """,
      technical_impact: """
      Medium: Unvalidated redirects can cause:
      - Bypassing of security controls through trusted domain exploitation
      - Credential harvesting through sophisticated phishing attacks
      - OAuth token theft via callback manipulation
      - Potential escalation to more serious security breaches
      - Analytics pollution and false traffic metrics
      """,
      likelihood: "Medium: Common when developers don't validate redirect destinations",
      cve_examples: [
        "CVE-2017-1000163: Phoenix Framework Arbitrary URL Redirect",
        "CWE-601: URL Redirection to Untrusted Site (Open Redirect)",
        "OWASP Top 10 A01:2021 - Broken Access Control",
        "General pattern in web applications accepting redirect parameters"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "NIST Cybersecurity Framework - PR.AC: Access Control",
        "ISO 27001 - A.14.2: Security in development and support processes"
      ],
      remediation_steps: """
      1. Implement allowlist validation for external redirect URLs
      2. Use local redirects with :to option whenever possible
      3. Validate redirect URLs against trusted domain patterns
      4. Implement URL parsing and host verification before redirects
      5. Log and monitor redirect attempts for suspicious patterns
      6. Use relative URLs for internal redirects when possible
      """,
      prevention_tips: """
      1. Always validate external redirect URLs against an allowlist
      2. Use Phoenix's :to option for internal redirects
      3. Implement URL parsing to check domain/host before redirecting
      4. Never trust user input for redirect destinations
      5. Consider using POST requests for sensitive redirects
      6. Implement proper error handling for invalid redirect URLs
      """,
      detection_methods: """
      1. Static code analysis for redirect patterns with user input
      2. Code review focusing on redirect() calls with external option
      3. Dynamic testing with malicious redirect URLs
      4. Security scanning for open redirect vulnerabilities
      5. Manual testing of all redirect endpoints with external URLs
      """,
      safe_alternatives: """
      1. Use allowlist validation: if URI.parse(url).host in @allowed_hosts
      2. Implement local redirects: redirect(conn, to: Routes.path())
      3. Use hardcoded external redirects for known safe destinations
      4. Implement validation functions for redirect URL checking
      5. Use relative paths for internal application redirects
      6. Consider POST-based redirects for sensitive operations
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        user_input_patterns: [
          "params",
          "user_",
          "input",
          "request", 
          "data",
          "conn.params",
          "conn.query_params",
          "conn.body_params"
        ],
        redirect_indicators: [
          "redirect_",
          "return_",
          "next_",
          "callback_",
          "url",
          "path"
        ],
        safe_validation_patterns: [
          "URI.parse",
          "validate_",
          "allowed_hosts",
          "whitelist",
          "allowlist"
        ],
        check_user_input: true,
        check_validation_presence: true,
        exclude_comments: true,
        exclude_string_literals: true,
        exclude_if_within_conditional: true
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          test_context_penalty: -0.5,
          user_input_bonus: 0.2,
          parameter_access_bonus: 0.15,
          interpolation_bonus: 0.1,
          validation_penalty: -0.4,
          hardcoded_url_penalty: -0.6
        }
      },
      ast_rules: %{
        node_type: "redirect_analysis",
        redirect_analysis: %{
          check_redirect_calls: true,
          check_external_option: true,
          redirect_functions: ["redirect"],
          external_option_pattern: "external:",
          safe_option_pattern: "to:"
        },
        url_analysis: %{
          check_url_source: true,
          check_string_interpolation: true
        }
      }
    }
  end
end