defmodule RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection do
  @moduledoc """
  Detects missing CSRF protection in Express.js and similar Node.js frameworks.
  
  Cross-Site Request Forgery (CSRF) occurs when a malicious website tricks a user's
  browser into making unwanted requests to another site where the user is authenticated.
  This can lead to unauthorized state changes like fund transfers or account modifications.
  
  ## Vulnerability Details
  
  CSRF attacks exploit the trust that a web application has in the user's browser.
  Since browsers automatically include cookies with requests, an attacker can create
  a malicious page that submits forms or makes requests to the vulnerable application.
  
  ### Attack Example
  ```html
  <!-- Malicious site tricks user into transferring money -->
  <form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  ```
  
  ### Vulnerable Code
  ```javascript
  // No CSRF protection on state-changing endpoint
  app.post('/api/transfer', (req, res) => {
    transferFunds(req.body.amount, req.body.to);
    res.json({success: true});
  });
  ```
  
  ### Safe Code
  ```javascript
  // Using CSRF middleware
  const csrf = require('csurf');
  app.use(csrf());
  
  app.post('/api/transfer', (req, res) => {
    // CSRF token automatically validated by middleware
    transferFunds(req.body.amount, req.body.to);
    res.json({success: true});
  });
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the pattern definition for missing CSRF protection.
  
  Note: AST enhancement can leverage Kagi MCP for researching framework-specific
  CSRF protection patterns and modern security middleware configurations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.pattern()
      iex> pattern.id
      "js-missing-csrf"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.pattern()
      iex> vulnerable = ~S|app.post('/transfer', (req, res) => { transfer(req.body) })|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.pattern()
      iex> safe = ~S|app.post('/transfer', csrfProtection, (req, res) => {})|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-missing-csrf",
      name: "Missing CSRF Protection",
      description: "State-changing endpoints without CSRF protection are vulnerable to cross-site request forgery attacks",
      type: :csrf,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Detects POST/PUT/PATCH/DELETE routes without CSRF middleware
      regex: ~r/
        # Express\/Node.js route definitions
        (?:app|router|apiRouter|adminRouter)\.
        (?:post|put|patch|delete)\s*\(
        \s*
        # Route path
        ['"`][^'"`]+['"`]\s*,
        \s*
        # Handler without CSRF middleware
        (?!.*(?:csrf|CSRF|csrfProtection|verifyCsrf|validateCsrf|checkCsrf))
        (?:
          # Direct handler function
          (?:async\s+)?\([^)]*\)\s*=>\s*\{
          |
          # Named handler reference
          \w+
        )
      /x,
      default_tier: :public,
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Implement CSRF protection using tokens, SameSite cookies, or double-submit cookies. Verify the Origin/Referer headers.",
      test_cases: %{
        vulnerable: [
          ~S|app.post('/api/transfer', (req, res) => { transferMoney(req.body) })|,
          ~S|router.put('/user/profile', async (req, res) => { await updateProfile(req.body) })|,
          ~S|app.delete('/account/:id', (req, res) => { deleteAccount(req.params.id) })|,
          ~S|apiRouter.post('/submit', handleSubmit)|
        ],
        safe: [
          ~S|app.post('/api/transfer', csrfProtection, (req, res) => {})|,
          ~S|app.post('/submit', csrf(), handleSubmit)|,
          ~S|app.get('/api/users', (req, res) => { res.json(users) })|,
          ~S|app.post('/api/action', verifyCsrfToken, processAction)|
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for CSRF.
  """
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Request Forgery (CSRF) is an attack that tricks authenticated users
      into executing unwanted actions on a web application. The attack works because:
      
      1. Browsers automatically include cookies with every request to a domain
      2. The server trusts requests with valid session cookies
      3. The server cannot distinguish between legitimate and forged requests
      
      CSRF attacks can result in unauthorized state changes like:
      - Financial transactions
      - Email/password changes
      - Administrative actions
      - Data modifications
      
      Modern frameworks provide built-in CSRF protection, but it must be properly
      configured and applied to all state-changing endpoints.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-352",
          title: "Cross-Site Request Forgery (CSRF)",
          url: "https://cwe.mitre.org/data/definitions/352.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "CSRF_Prevention",
          title: "OWASP CSRF Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "node_csrf_guide",
          title: "Node.js CSRF Protection Guide",
          url: "https://www.stackhawk.com/blog/node-js-csrf-protection-guide-examples-and-how-to-enable-it/"
        }
      ],
      attack_vectors: [
        "Malicious <img> tag: <img src='https://bank.com/transfer?amount=1000&to=attacker'>",
        "Auto-submitting form: <form action='https://victim.com/delete' method='POST'>",
        "XMLHttpRequest from malicious site (if CORS misconfigured)",
        "Clickjacking combined with CSRF for complex attacks",
        "Login CSRF to force user into attacker's account"
      ],
      real_world_impact: [
        "Unauthorized fund transfers in banking applications",
        "Account takeover through email/password changes",
        "Privilege escalation by modifying user roles",
        "Data corruption or deletion",
        "Malicious actions performed on behalf of administrators",
        "Social media actions (posting, following, liking) without consent"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-50164",
          description: "Apache Struts CSRF vulnerability allowing remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "CSRF combined with file upload led to RCE"
        },
        %{
          id: "CVE-2022-29464",
          description: "WSO2 API Manager CSRF vulnerability in admin portal",
          severity: "high",
          cvss: 8.8,
          note: "Allowed attackers to perform admin actions via CSRF"
        },
        %{
          id: "CVE-2021-39174",
          description: "Cachet status page CSRF vulnerability",
          severity: "high",
          cvss: 8.1,
          note: "Enabled unauthorized modification of status pages"
        },
        %{
          id: "CVE-2020-13927",
          description: "Airflow CSRF vulnerability in experimental API",
          severity: "high",
          cvss: 8.8,
          note: "Allowed triggering of DAGs without authentication"
        }
      ],
      detection_notes: """
      This pattern detects missing CSRF protection by looking for:
      1. State-changing HTTP methods (POST, PUT, PATCH, DELETE)
      2. Absence of CSRF middleware in the route definition
      3. Express.js and similar framework routing patterns
      
      Note: This regex-based approach has limitations:
      - Cannot detect app-wide CSRF middleware (app.use(csrf()))
      - May miss custom CSRF implementations
      - Framework-specific patterns may vary
      
      AST enhancement significantly improves accuracy by analyzing the
      middleware chain and framework configuration.
      """,
      safe_alternatives: [
        "Use synchronizer token pattern: Generate unique token per session",
        "Implement double-submit cookies: Token in both cookie and request body",
        "Set SameSite cookie attribute: Prevents cross-site cookie submission",
        "Verify Origin/Referer headers: Check request source",
        "Use custom headers: Leverage CORS preflight for protection",
        "Implement CAPTCHA for sensitive operations",
        "Re-authenticate for critical actions",
        "Use framework CSRF middleware: csurf for Express, built-in for modern frameworks"
      ],
      additional_context: %{
        common_mistakes: [
          "Only protecting POST requests (PUT/PATCH/DELETE also need protection)",
          "Not protecting AJAX endpoints",
          "Relying only on authentication (authenticated != authorized)",
          "Using predictable tokens",
          "Not rotating tokens after login",
          "Exposing tokens in URLs"
        ],
        secure_patterns: [
          "Enable CSRF protection globally, disable for specific safe routes",
          "Use per-request tokens for high-value operations",
          "Combine with other defenses (CAPTCHA, re-authentication)",
          "Log and monitor CSRF token failures",
          "Use SameSite=Strict for session cookies",
          "Implement proper CORS configuration"
        ],
        framework_specific: %{
          express: [
            "const csrf = require('csurf'); app.use(csrf());",
            "Note: csurf is deprecated, use alternative libraries"
          ],
          koa: [
            "const CSRF = require('koa-csrf'); app.use(new CSRF());"
          ],
          fastify: [
            "await fastify.register(require('@fastify/csrf-protection'));"
          ],
          nestjs: [
            "Use built-in CSRF protection with @Csrf() decorator"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual CSRF vulnerabilities and:
  - Routes protected by app-wide CSRF middleware
  - API endpoints using token-based authentication
  - CORS-protected endpoints with preflight checks
  - Routes using custom header validation
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.ast_enhancement()
      iex> Map.keys(enhancement)
      [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection.ast_enhancement()
      iex> "has_global_csrf" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        # Express route methods
        callee: %{
          object_patterns: ["app", "router", "apiRouter", "adminRouter"],
          property_patterns: ["post", "put", "patch", "delete"]
        },
        # Check for CSRF middleware
        route_analysis: %{
          has_state_changing_method: true,
          middleware_chain_excludes: ["csrf", "csrfProtection", "verifyCsrf", "validateCsrf"],
          not_in_middleware_chain: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/examples/, ~r/docs/],
        exclude_if_app_wide_csrf: true,      # app.use(csrf()) configured globally
        exclude_if_api_only: true,           # API endpoints often use different auth
        exclude_if_has_cors_preflight: true, # CORS preflight provides CSRF protection
        safe_if_readonly_operation: true,    # GET/HEAD are safe
        exclude_if_custom_header_check: true # Custom header checking (X-Requested-With)
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "state_changing_no_csrf" => 0.4,
          "modifies_database" => 0.3,
          "handles_payments" => 0.3,
          "has_global_csrf" => -0.9,
          "is_api_endpoint" => -0.6,         # APIs often use tokens instead
          "requires_custom_header" => -0.7,   # X-Requested-With provides protection
          "uses_double_submit" => -0.8,      # Double-submit cookie pattern
          "requires_api_key" => -0.5         # API key auth is different
        }
      },
      min_confidence: 0.8
    }
  end
end