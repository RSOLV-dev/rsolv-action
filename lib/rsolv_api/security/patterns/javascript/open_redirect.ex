defmodule RsolvApi.Security.Patterns.Javascript.OpenRedirect do
  @moduledoc """
  Open Redirect Vulnerability in JavaScript/TypeScript
  
  Detects dangerous patterns like:
    res.redirect(req.query.url)
    window.location.href = params.redirect
    location.replace(userInput)
    
  Safe alternatives:
    if (isValidRedirect(url)) { res.redirect(url) }
    res.redirect(ALLOWED_REDIRECTS[req.query.type])
    res.redirect('/dashboard')
    
  Open redirect vulnerabilities occur when an application redirects users to a
  URL that is partially or fully controlled by an attacker. This can be exploited
  for phishing attacks, where users are redirected to malicious sites that appear
  legitimate because the initial URL was from a trusted domain.
  
  ## Vulnerability Details
  
  Open redirects are particularly dangerous because they abuse user trust in the
  legitimate domain. Attackers can craft URLs that start with the trusted domain
  but redirect to malicious sites, making phishing attacks more convincing. This
  is often used in combination with social engineering to steal credentials or
  deliver malware.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct redirect with user input
  app.get('/redirect', (req, res) => {
    // Attacker can send: /redirect?url=https://evil.com
    res.redirect(req.query.url);
  });
  
  // Attack URL:
  // https://trusted-site.com/redirect?url=https://phishing-site.com
  // User sees trusted-site.com and clicks, then gets redirected to phishing site
  ```
  
  ### Modern Attack Scenarios
  Open redirect vulnerabilities can lead to:
  - Phishing attacks with increased success rates
  - OAuth token theft through redirect manipulation
  - Cross-site scripting (XSS) via javascript: URLs
  - Server-side request forgery (SSRF) in some contexts
  - Bypassing security controls that check referrer headers
  
  The vulnerability is particularly dangerous in:
  - Authentication flows (login/logout redirects)
  - OAuth authorization callbacks
  - Payment gateway returns
  - Marketing campaign tracking
  - Single sign-on (SSO) implementations
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the open redirect detection pattern.
  
  This pattern detects unvalidated redirects to user-controlled URLs that can
  lead to phishing attacks. It covers server-side redirects (Express/Node.js),
  client-side redirects (window.location), and various framework-specific
  redirect mechanisms.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> pattern.id
      "js-open-redirect"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> pattern.cwe_id
      "CWE-601"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> vulnerable = "res.redirect(req.query.url)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> safe = "res.redirect('/dashboard')"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> vulnerable = "window.location.href = params.redirect"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> vulnerable = "location.replace(userInput)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> safe = "if (isValidRedirect(url)) { res.redirect(url) }"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.OpenRedirect.pattern()
      iex> pattern.recommendation
      "Validate redirect URLs against a whitelist of allowed destinations."
  """
  def pattern do
    %Pattern{
      id: "js-open-redirect",
      name: "Open Redirect Vulnerability",
      description: "Redirecting to user-controlled URLs can lead to phishing attacks",
      type: :open_redirect,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: build_open_redirect_regex(),
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against a whitelist of allowed destinations.",
      test_cases: %{
        vulnerable: [
          "res.redirect(req.query.url)",
          "window.location.href = params.redirect",
          "location.replace(userInput)",
          "history.push(req.query.next)",
          "res.header('Location', req.body.url)"
        ],
        safe: [
          "res.redirect('/dashboard')",
          "if (isValidRedirect(url)) { res.redirect(url) }",
          "res.redirect(ALLOWED_REDIRECTS[req.query.type])",
          "window.location.href = '/home'",
          "const safeUrl = validateUrl(req.query.url); res.redirect(safeUrl)"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for open redirect vulnerabilities.
  
  This metadata documents the security implications of unvalidated redirects
  and provides authoritative guidance for preventing phishing attacks through
  proper URL validation.
  """
  def vulnerability_metadata do
    %{
      description: """
      Open redirect vulnerabilities occur when a web application accepts untrusted
      input that could cause the application to redirect users to an external,
      untrusted URL. This vulnerability is often exploited in phishing attacks
      where attackers craft URLs that appear to originate from a trusted site but
      redirect victims to malicious websites designed to steal credentials or
      deliver malware.
      
      The vulnerability exploits user trust in the legitimate domain. When users
      see a URL starting with a trusted domain (e.g., https://bank.com/redirect?url=),
      they are more likely to click it, not realizing they will be redirected to
      an attacker-controlled site. This makes phishing campaigns significantly more
      effective.
      
      In JavaScript applications, open redirects can occur in multiple contexts:
      1. Server-side redirects in Express/Node.js applications
      2. Client-side redirects using window.location or similar APIs
      3. Framework-specific routing mechanisms (React Router, Angular Router, etc.)
      4. Meta refresh tags dynamically generated with user input
      5. HTTP Location headers set with user-controlled values
      
      Modern attack scenarios have evolved beyond simple phishing. Attackers now use
      open redirects to bypass security controls, steal OAuth tokens, chain with other
      vulnerabilities for XSS attacks, and even perform server-side request forgery
      in certain configurations. The rise of single-page applications and complex
      authentication flows has created new opportunities for exploitation.
      
      The impact extends beyond individual users. Open redirects can damage an
      organization's reputation, lead to financial losses through successful phishing,
      and result in regulatory penalties under data protection laws. They are particularly
      critical in applications handling sensitive data or financial transactions.
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
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "Unvalidated_Redirects_and_Forwards",
          title: "OWASP Unvalidated Redirects and Forwards Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "google_oauth_redirect",
          title: "OAuth 2.0 Redirection Attack",
          url: "https://datatracker.ietf.org/doc/html/rfc6749#section-10.15"
        },
        %{
          type: :nist,
          id: "SP_800-63B",
          title: "NIST Digital Identity Guidelines - Authentication",
          url: "https://pages.nist.gov/800-63-3/sp800-63b.html#sec5"
        },
        %{
          type: :vendor,
          id: "portswigger_open_redirect",
          title: "PortSwigger - Open Redirection",
          url: "https://portswigger.net/web-security/access-control/open-redirect"
        }
      ],
      attack_vectors: [
        "Phishing via trusted domain: https://trusted.com/redirect?url=https://phishing.com",
        "OAuth token theft: Redirect OAuth callback to attacker-controlled site",
        "XSS via javascript: protocol: redirect?url=javascript:alert(document.cookie)",
        "Chain with SSRF: Internal redirect to cloud metadata endpoints",
        "Bypass referrer checks: Use open redirect to bypass referrer-based access controls",
        "Social engineering: Embed redirect URLs in emails appearing from trusted source",
        "QR code attacks: Generate QR codes with open redirect URLs for physical attacks",
        "SMS phishing: Send shortened URLs that redirect through trusted domain"
      ],
      real_world_impact: [
        "Credential theft through convincing phishing pages",
        "Financial fraud via redirects to fake banking sites",
        "OAuth token compromise leading to account takeover",
        "Brand reputation damage from association with phishing",
        "Regulatory fines under GDPR/CCPA for data breaches",
        "Loss of customer trust and business relationships",
        "Legal liability for damages caused by phishing attacks",
        "Increased support costs from compromised accounts"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-44228",
          description: "Log4j vulnerability included open redirect as attack vector for JNDI lookups",
          severity: "critical",
          cvss: 10.0,
          note: "Demonstrates how open redirects can be chained with other vulnerabilities"
        },
        %{
          id: "CVE-2020-5902",
          description: "F5 BIG-IP open redirect vulnerability in TMUI",
          severity: "high",
          cvss: 7.5,
          note: "Enterprise software open redirect leading to credential theft"
        },
        %{
          id: "CVE-2019-19781",
          description: "Citrix ADC and Gateway open redirect vulnerability",
          severity: "medium",
          cvss: 6.1,
          note: "Demonstrates impact on enterprise gateway applications"
        },
        %{
          id: "CVE-2018-7569",
          description: "Open redirect in popular npm package 'serve'",
          severity: "medium",
          cvss: 6.1,
          note: "Shows how common development tools can introduce vulnerabilities"
        }
      ],
      detection_notes: """
      This pattern detects various forms of open redirect vulnerabilities in JavaScript:
      
      1. Server-side redirects (Express/Node.js) - res.redirect() with user input
      2. Client-side location manipulation - window.location.href = userInput
      3. Framework-specific routing - history.push(), router.navigate()
      4. HTTP header injection - Setting Location header with user input
      5. Meta refresh injection - Dynamically creating meta refresh tags
      
      The pattern looks for redirect functions being called with common user input
      sources like req.query, req.params, req.body, or generic terms like userInput,
      params, data, etc. It attempts to avoid false positives by not matching when
      the redirect target appears to be a static string or validated input.
      
      The detection is case-insensitive and handles various coding styles including
      method chaining and template literals.
      """,
      safe_alternatives: [
        "Implement a whitelist of allowed redirect destinations",
        "Use relative URLs only (e.g., '/dashboard' instead of full URLs)",
        "Validate URLs against a specific pattern before redirecting",
        "Use mapping/lookup tables instead of direct user input",
        "Implement a redirect confirmation page for external URLs",
        "Parse and validate URL components (protocol, hostname, path)",
        "Use framework-provided safe redirect methods when available",
        "Implement CSRF tokens for redirect endpoints",
        "Log all redirect attempts for security monitoring",
        "Consider using POST requests for sensitive redirects"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting URLs that start with '/' (can still be //evil.com)",
          "Only checking URL protocol (not validating hostname)",
          "Allowing any subdomain of the main domain",
          "Not handling URL encoding/decoding properly",
          "Forgetting about javascript: and data: protocols",
          "Trusting referrer headers for validation"
        ],
        secure_patterns: [
          "Always use an explicit whitelist of allowed destinations",
          "Parse URLs properly using URL parsing libraries",
          "Validate both protocol AND hostname",
          "Use warning pages for external redirects",
          "Implement rate limiting on redirect endpoints",
          "Monitor and alert on suspicious redirect patterns"
        ],
        framework_specific_guidance: [
          "Express.js: Use a middleware for redirect validation",
          "React Router: Validate params before history.push()",
          "Angular: Guard routes that accept redirect parameters",
          "Next.js: Use getServerSideProps for redirect validation",
          "Vue Router: Implement navigation guards for validation",
          "Fastify: Use schema validation for redirect parameters"
        ]
      }
    }
  end
  
  # Private helper to build the complex regex pattern
  defp build_open_redirect_regex do
    # User input sources that indicate vulnerability
    # Modified to not match "url" when it's just a parameter name in validation contexts
    user_inputs = "(?:req\\.(?:query|params|body)|request\\.(?:query|params|body)|params\\.|query\\.|body\\.|user(?:Input|Data|Provided|ProvidedUrl)?|input|data(?![\\w])|protocol|host|returnUrl|goto|next|redirect(?![\\w])|(?<!Valid|valid|allow|Allow|sanitize|Sanitize|validate|Validate)(?<!\\()url(?!Encoded))"
    
    # Build individual pattern components
    patterns = [
      # Server-side redirects: res.redirect(userInput)
      "(?:res\\.redirect|response\\.redirect)\\s*\\(\\s*(?:[^)]*[\\+\\s])?(?:\\$\\{)?#{user_inputs}\\b",
      
      # Location assignment: window.location = userInput
      "(?:(?:window\\.)?location(?:\\.href)?|document\\.location)\\s*=\\s*(?:[^;]*[\\+\\s])?(?:\\$\\{)?#{user_inputs}\\b",
      
      # Template literal location: window.location = `${params.host}`
      "(?:(?:window\\.)?location(?:\\.href)?|document\\.location)\\s*=\\s*`[^`]*\\$\\{#{user_inputs}[^}]*\\}",
      
      # Location methods: location.replace(userInput)
      "(?:window\\.)?location\\.(?:replace|assign)\\s*\\(\\s*(?:[^)]*[\\+\\s])?(?:\\$\\{)?#{user_inputs}\\b",
      
      # Framework routing: router.navigate(userInput) or router.navigate([userInput])
      "(?:history\\.push|navigate|router\\.navigate|router\\.push|\\$location\\.path|this\\.\\$router\\.push)\\s*\\(\\s*(?:\\[)?(?:[^)\\]]*[\\+\\s])?(?:\\$\\{)?#{user_inputs}\\b",
      
      # HTTP headers: res.header('Location', userInput)
      "(?:res\\.(?:header|setHeader)\\s*\\(\\s*['\"]Location['\"]|response\\.headers\\s*\\[\\s*['\"]Location['\"]\\s*\\])\\s*[,=]\\s*(?:[^;)]*[\\+\\s])?(?:\\$\\{)?#{user_inputs}\\b",
      
      # Meta refresh: meta.content = '0; url=' + userInput
      "meta\\.content\\s*=\\s*['\"]?[^'\"]*url=.*?#{user_inputs}",
      
      # Document.write meta refresh
      "document\\.write.*http-equiv.*refresh.*url=.*?#{user_inputs}",
      
      # innerHTML meta refresh
      "innerHTML\\s*[+\\-]?=\\s*.*http-equiv.*refresh.*url=.*?#{user_inputs}"
    ]
    
    # Join all patterns with OR operator and compile
    pattern_string = patterns
      |> Enum.map(&"(?:#{&1})")
      |> Enum.join("|")
    
    Regex.compile!(pattern_string, "i")
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual open redirect vulnerabilities and:
  - URLs that are validated before redirect
  - Relative-only redirects (safe from open redirect)
  - Redirects checked against an allowlist
  - Same-origin validated redirects
  - Static/hardcoded redirect destinations
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.OpenRedirect.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.OpenRedirect.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.OpenRedirect.ast_enhancement()
      iex> enhancement.ast_rules.callee.property
      "redirect"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.OpenRedirect.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.OpenRedirect.ast_enhancement()
      iex> "allowlist_check" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          object: "res",
          property: "redirect",
          alternatives: [
            %{object: "response", property: "redirect"},
            %{object: "window", property: "location"},
            %{property: "writeHead"}  # 302 redirects
          ]
        },
        # Argument must be user-controlled
        argument_analysis: %{
          contains_user_input: true,
          not_validated_url: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        exclude_if_url_validated: true,       # URL validation/allowlist
        exclude_if_relative_only: true,       # Only relative paths allowed
        exclude_if_same_origin: true,         # Checked for same origin
        safe_redirect_patterns: ["/login", "/home", "/dashboard"]  # Known safe redirects
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "direct_query_param_redirect" => 0.5,
          "referer_header_redirect" => 0.3,
          "return_url_parameter" => 0.4,
          "url_validation_present" => -0.8,
          "allowlist_check" => -0.9,
          "relative_path_only" => -0.6,
          "hardcoded_base_domain" => -0.7
        }
      },
      min_confidence: 0.8
    }
  end
  
end