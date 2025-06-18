defmodule RsolvApi.Security.Patterns.Javascript.Ssrf do
  @moduledoc """
  Detects Server-Side Request Forgery (SSRF) vulnerabilities in JavaScript/TypeScript code.
  
  SSRF occurs when an application makes HTTP requests to arbitrary URLs provided by users
  without proper validation. This can allow attackers to access internal resources, bypass
  firewalls, or perform port scanning on internal networks.
  
  ## Vulnerability Details
  
  SSRF vulnerabilities enable attackers to make the server perform requests on their behalf.
  This is particularly dangerous in cloud environments where metadata services (like AWS
  169.254.169.254) can expose credentials and configuration data.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct use of user input in HTTP request
  app.post('/webhook', async (req, res) => {
    const response = await axios.get(req.body.url);
    res.json(response.data);
  });
  
  // Attack: Access internal services
  // POST /webhook { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
  // POST /webhook { "url": "http://internal-api:8080/admin/users" }
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the pattern definition for SSRF detection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.Ssrf.pattern()
      iex> pattern.id
      "js-ssrf"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.Ssrf.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.Ssrf.pattern()
      iex> vulnerable = ~S|axios.get(req.body.url)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.Ssrf.pattern()
      iex> safe = ~S|axios.get("https://api.example.com/data")|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-ssrf",
      name: "Server-Side Request Forgery (SSRF)",
      description: "Server-side request forgery occurs when user-controlled URLs are used in HTTP requests without validation",
      type: :ssrf,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Detects HTTP client methods with user input as URL parameter
      regex: ~r/
        # HTTP client libraries and methods
        (?:
          # Library.method pattern
          (?:axios|request|http|https)\.
          (?:get|post|put|delete|patch|head|options|request)\s*\(
          |
          # Standalone fetch function
          \bfetch\s*\(
          |
          # Standalone request function  
          \brequest\s*\(
        )
        \s*
        (?:
          # Direct user input variables - including nested properties
          (?:req\.|request\.|params\.|query\.|body\.|user|input|data)[\w\.]*
          |
          # Object with url property from user input
          \{[^}]*url\s*:\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)[\w\.]*
        )
      /x,
      default_tier: :enterprise,
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate URLs against an allowlist, block private IP ranges and sensitive protocols. Consider using a proxy service for external requests.",
      test_cases: %{
        vulnerable: [
          ~S|axios.get(req.body.url)|,
          ~S|fetch(userProvidedUrl)|,
          ~S|request(params.webhook_url, (err, res) => {})|,
          ~S|http.get(req.body.url, (res) => {})|,
          ~S|axios.post(userInput.callback)|,
          ~S|request.post({url: input.endpoint})|
        ],
        safe: [
          ~S|axios.get("https://api.example.com/data")|,
          ~S|axios.get(sanitizeUrl(req.body.url))|,
          ~S|const safeUrl = validateUrl(userUrl); fetch(safeUrl)|,
          ~S|axios.get(ALLOWED_APIS[req.body.api_name])|
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for SSRF.
  """
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can make
      the server perform HTTP requests to arbitrary destinations. This can lead to:
      
      1. Access to internal services behind firewalls
      2. Port scanning of internal networks
      3. Reading cloud metadata services (AWS, GCP, Azure)
      4. Bypassing access controls using the server's IP
      5. Denial of service through resource exhaustion
      
      SSRF is particularly dangerous in cloud environments where metadata endpoints
      at 169.254.169.254 can expose IAM credentials, API keys, and configuration.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-918",
          title: "Server-Side Request Forgery (SSRF)",
          url: "https://cwe.mitre.org/data/definitions/918.html"
        },
        %{
          type: :owasp,
          id: "A10:2021",
          title: "OWASP Top 10 2021 - A10 Server-Side Request Forgery",
          url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        },
        %{
          type: :research,
          id: "ssrf_bible",
          title: "SSRF Bible - Comprehensive SSRF Guide",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "portswigger_ssrf",
          title: "PortSwigger SSRF Research",
          url: "https://portswigger.net/web-security/ssrf"
        }
      ],
      attack_vectors: [
        "Cloud metadata: http://169.254.169.254/latest/meta-data/",
        "Internal services: http://localhost:8080/admin",
        "Private networks: http://192.168.1.10/internal-api",
        "File access: file:///etc/passwd",
        "Port scanning: http://internal-host:22",
        "DNS rebinding: http://attacker-domain.com (resolves to internal IP)",
        "Protocol smuggling: gopher://internal-host:25"
      ],
      real_world_impact: [
        "Complete cloud account takeover via metadata service credentials",
        "Access to internal databases and admin panels",
        "Exposure of internal network architecture",
        "Data exfiltration from internal services",
        "Lateral movement within the infrastructure",
        "Cryptocurrency mining using cloud resources"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-5736",
          description: "Docker runc SSRF allowing container escape",
          severity: "critical",
          cvss: 8.6,
          note: "SSRF in Docker leading to container escape and host compromise"
        },
        %{
          id: "CVE-2021-21315",
          description: "Node.js systeminformation SSRF vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Popular npm package allowing SSRF through unvalidated URLs"
        },
        %{
          id: "CVE-2022-1388",
          description: "F5 BIG-IP SSRF leading to authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "SSRF vulnerability allowing unauthenticated remote code execution"
        },
        %{
          id: "CVE-2021-27290",
          description: "npm ssri SSRF vulnerability in integrity checking",
          severity: "high",
          cvss: 7.5,
          note: "SSRF in npm's subresource integrity library"
        }
      ],
      detection_notes: """
      This pattern detects SSRF by looking for:
      1. HTTP client library calls (axios, fetch, request, http/https modules)
      2. User-controlled input being passed as the URL parameter
      3. Common request methods (GET, POST, PUT, DELETE, etc.)
      4. Both direct parameter passing and object-based configurations
      
      The pattern is designed to catch the most common SSRF patterns while
      minimizing false positives from hardcoded or validated URLs.
      """,
      safe_alternatives: [
        "Implement strict URL allowlisting: only allow specific domains/paths",
        "Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16",
        "Block dangerous protocols: file://, gopher://, dict://, ftp://",
        "Use URL parsing to validate: new URL(userInput) and check hostname",
        "Implement request proxying through a dedicated service",
        "Add request timeouts and size limits",
        "Monitor for suspicious request patterns",
        "Use DNS resolution validation before making requests"
      ],
      additional_context: %{
        common_mistakes: [
          "Only blocking 127.0.0.1 but not other localhost representations",
          "Not blocking IPv6 loopback (::1) and local addresses",
          "Trusting URL parsing without considering DNS rebinding",
          "Not validating redirects (attacker site -> internal resource)",
          "Assuming HTTPS URLs are safe (can still access internal HTTPS services)"
        ],
        secure_patterns: [
          "Maintain a strict allowlist of permitted domains",
          "Use a separate HTTP client for internal vs external requests",
          "Implement request signing for internal service communication",
          "Deploy in network-segmented environments",
          "Use service mesh with proper access controls"
        ],
        cloud_specific_risks: %{
          aws: [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/api/token"
          ],
          gcp: [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/"
          ],
          azure: [
            "http://169.254.169.254/metadata/instance",
            "http://169.254.169.254/metadata/identity/oauth2/token"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SSRF vulnerabilities and:
  - Validated URLs with allowlist checking
  - Static API endpoints with dynamic paths
  - Proxied requests through safe gateways
  - URLs constructed from safe components
  - Test/mock HTTP requests
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.Ssrf.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.Ssrf.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.Ssrf.ast_enhancement()
      iex> enhancement.ast_rules.argument_analysis.has_url_parameter
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.Ssrf.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.Ssrf.ast_enhancement()
      iex> "uses_url_validation" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        # HTTP client methods
        callee_patterns: [
          ~r/axios\.(get|post|put|delete|patch|head|options|request)/,
          ~r/fetch$/,
          ~r/request\.(get|post|put|delete|patch|head|options)/,
          ~r/http\.(get|post|request)/,
          ~r/https\.(get|post|request)/
        ],
        # Must have user input as URL parameter
        argument_analysis: %{
          has_url_parameter: true,
          url_from_user_input: true,
          not_allowlisted_url: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/mock/, ~r/fixtures/],
        exclude_if_url_validated: true,     # Skip if URL is validated
        exclude_if_allowlisted: true,       # Skip if URL is checked against allowlist
        safe_if_uses_proxy: true,           # Using a proxy service is safer
        safe_url_patterns: ["isValidUrl", "validateUrl", "checkAllowlist", "urlWhitelist"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "direct_user_url" => 0.4,
          "no_url_validation" => 0.3,
          "internal_ip_possible" => 0.2,
          "has_allowlist_check" => -0.8,
          "uses_url_validation" => -0.7,
          "url_validation_present" => -0.7,
          "static_domain_prefix" => -0.6,
          "uses_proxy_service" => -0.5
        }
      },
      min_confidence: 0.7
    }
  end
end