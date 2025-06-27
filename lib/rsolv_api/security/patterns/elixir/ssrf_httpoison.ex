defmodule RsolvApi.Security.Patterns.Elixir.SsrfHttpoison do
  @moduledoc """
  Detects Server-Side Request Forgery (SSRF) vulnerabilities via HTTPoison and other HTTP clients.
  
  This pattern identifies instances where user-controlled input is used directly in HTTP
  requests without proper validation, potentially allowing attackers to make requests to
  internal services or arbitrary external URLs.
  
  ## Vulnerability Details
  
  SSRF vulnerabilities occur when an application makes HTTP requests to URLs provided by
  users without proper validation. This can lead to:
  - Access to internal services (localhost, internal IPs)
  - Port scanning of internal networks
  - Interaction with cloud metadata services (169.254.169.254)
  - Bypass of firewalls and access controls
  - Data exfiltration through controlled endpoints
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  def fetch_webhook(conn, %{"url" => url}) do
    case HTTPoison.get!(url) do  # SSRF vulnerability!
      %{status_code: 200, body: body} ->
        json(conn, %{data: body})
      _ ->
        json(conn, %{error: "Failed to fetch"})
    end
  end
  ```
  
  An attacker could:
  - Access internal services: `http://localhost:9200/_cat/indices`
  - Read cloud metadata: `http://169.254.169.254/latest/meta-data/`
  - Scan internal network: `http://192.168.1.1:22`
  
  ### Safe Alternative
  
  Safe code:
  ```elixir
  @allowed_hosts ["api.example.com", "webhook.partner.com"]
  
  def fetch_webhook(conn, %{"url" => url}) do
    uri = URI.parse(url)
    
    if uri.host in @allowed_hosts and uri.scheme in ["https"] do
      case HTTPoison.get(url, [], timeout: 5000, recv_timeout: 5000) do
        {:ok, %{status_code: 200, body: body}} ->
          json(conn, %{data: body})
        _ ->
          json(conn, %{error: "Failed to fetch"})
      end
    else
      json(conn, %{error: "Invalid URL"})
    end
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-ssrf-httpoison",
      name: "SSRF via HTTPoison",
      description: "Unvalidated URLs in HTTP requests can lead to SSRF",
      type: :ssrf,
      severity: :high,
      languages: ["elixir"],
      regex: [
        # HTTPoison with variable URLs (not string literals) - exclude comments
        ~r/^(?!.*#).*HTTPoison\.(get!?|post!?|put!?|delete!?|request!?|patch!?|head!?|options!?)\s*\(\s*[^"']/m,
        # Piped variable to HTTPoison - exclude comments
        ~r/^(?!.*#).*\|>\s*HTTPoison\.(get!?|post!?|put!?|delete!?|request!?)/m,
        # HTTPoison with params/user input - exclude comments
        ~r/^(?!.*#).*HTTPoison\.\w+!?\s*\(\s*(params|conn|socket|args|user|input|url|endpoint|webhook|callback)/m,
        # Tesla HTTP client with variables - exclude comments
        ~r/^(?!.*#).*Tesla\.(get!?|post!?|put!?|delete!?)\s*\(\s*[^,]+,\s*[^"']/m,
        # Req HTTP client with user input - exclude comments
        ~r/^(?!.*#).*Req\.(get!?|post!?|put!?|delete!?)\s*\(\s*url:\s*(params|user|input|url)/m,
        # :hackney with variables - exclude comments
        ~r/^(?!.*#).*:hackney\.(request|get|post|put|delete)\s*\(\s*[^,]+,\s*[^"']/m,
        # Finch with user input - exclude comments
        ~r/^(?!.*#).*Finch\.build\s*\(\s*:\w+,\s*[^"']/m
      ],
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate URLs against an allowlist before making HTTP requests",
      test_cases: %{
        vulnerable: [
          ~S|HTTPoison.get!(user_provided_url)|,
          ~S|HTTPoison.post!(params["webhook_url"], body)|,
          "url |> HTTPoison.get!()",
          ~S|HTTPoison.request!(:get, endpoint, "")|,
          ~S|Tesla.get!(client, user_url)|,
          ~S|Req.get!(url: params["endpoint"])|
        ],
        safe: [
          ~S|HTTPoison.get!("https://api.example.com/data")|,
          ~S|HTTPoison.get!("#{@base_url}/api/v1/data")|,
          ~S|# HTTPoison.get!(user_url) - disabled for security|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Server-Side Request Forgery (SSRF) vulnerabilities in Elixir applications occur when
      user-controlled input is used to make HTTP requests without proper validation. This
      is particularly dangerous in Elixir/Phoenix applications that integrate with webhooks,
      external APIs, or implement proxy functionality.
      
      HTTPoison, being the most popular HTTP client in the Elixir ecosystem, is frequently
      involved in SSRF vulnerabilities. Other clients like Tesla, Req, Finch, and direct
      :hackney usage are also susceptible. The vulnerability allows attackers to use the
      application as a proxy to access internal resources, cloud metadata services, or
      perform port scanning.
      
      The BEAM VM's robust networking capabilities make it an attractive target for SSRF
      attacks, as compromised applications can efficiently make many concurrent requests.
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
          id: "portswigger_ssrf",
          title: "PortSwigger - Server-side request forgery (SSRF)",
          url: "https://portswigger.net/web-security/ssrf"
        },
        %{
          type: :research,
          id: "ssrf_bible",
          title: "SSRF Bible - A collection of SSRF attack vectors",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Internal service access: http://localhost:9200/_search",
        "Cloud metadata: http://169.254.169.254/latest/meta-data/",
        "Internal network scanning: http://192.168.1.1:22",
        "File access via file:// protocol: file:///etc/passwd",
        "Internal APIs: http://internal-api.local/admin/users",
        "Redis/Memcached via gopher:// protocol",
        "Bypass WAF using redirects: http://evil.com/redirect?url=internal",
        "DNS rebinding attacks"
      ],
      real_world_impact: [
        "Access to internal services and admin interfaces",
        "Reading cloud provider metadata and stealing IAM credentials",
        "Port scanning and network topology discovery",
        "Data exfiltration from internal databases",
        "Bypassing firewalls and network segmentation",
        "Triggering internal functionality not exposed externally",
        "Potential for chaining with other vulnerabilities"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-1211",
          description: "SSRF in hackney HTTP client affecting Erlang/Elixir apps",
          severity: "high",
          cvss: 7.5,
          note: "URL parsing vulnerability allowed bypassing SSRF protections"
        },
        %{
          id: "CVE-2019-11510",
          description: "Pulse Secure VPN SSRF leading to authentication bypass",
          severity: "critical",
          cvss: 10.0,
          note: "SSRF vulnerability allowed reading arbitrary files"
        },
        %{
          id: "CVE-2021-21315",
          description: "Node.js systeminformation SSRF vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Similar pattern of unvalidated HTTP requests"
        }
      ],
      detection_notes: """
      This pattern detects:
      - HTTPoison function calls with non-literal URLs
      - Variable URLs piped to HTTPoison functions
      - HTTP requests using user-controlled parameters
      - Other HTTP clients (Tesla, Req, Finch, hackney)
      - Common parameter names indicating user input
      """,
      safe_alternatives: [
        "Implement URL allowlist validation before making requests",
        "Use URI.parse/1 to validate and restrict hosts/schemes",
        "Restrict protocols to HTTP/HTTPS only",
        "Implement timeout controls to prevent slow requests",
        "Use separate HTTP clients for internal vs external requests",
        "Deploy in network-segmented environments",
        "Consider using a proxy service for external requests",
        "Validate SSL certificates and reject self-signed certs"
      ],
      additional_context: %{
        common_mistakes: [
          "Only checking URL prefix without proper parsing",
          "Allowing redirects without validation",
          "Not considering DNS rebinding attacks",
          "Forgetting about alternative protocols (file://, gopher://)",
          "Trusting X-Forwarded-* headers"
        ],
        secure_patterns: [
          "Always parse URLs with URI.parse/1",
          "Maintain strict allowlists of permitted hosts",
          "Use :verify_peer for SSL connections",
          "Set reasonable timeouts for all HTTP requests",
          "Log all external HTTP requests for monitoring"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SSRF vulnerabilities and
  legitimate HTTP client usage.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SsrfHttpoison.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SsrfHttpoison.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        http_analysis: %{
          check_httpoison: true,
          check_tesla: true,
          check_req: true,
          check_finch: true,
          check_hackney: true,
          http_functions: ["get", "get!", "post", "post!", "put", "put!", 
                          "delete", "delete!", "request", "request!",
                          "patch", "patch!", "head", "head!", "options", "options!"]
        },
        url_analysis: %{
          check_literal_urls: true,
          check_variable_urls: true,
          check_interpolated_urls: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/factories/],
        user_input_sources: ["params", "conn.params", "conn.body_params", 
                            "socket.assigns", "args", "user", "input", "request",
                            "url", "endpoint", "webhook", "callback", "target"],
        safe_patterns: ["URI.parse", "@allowed_hosts", "in @whitelist", 
                       "validate_url", "sanitize_url"],
        exclude_if_validated: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_url_validation" => -0.6,
          "in_test_code" => -1.0,
          "hardcoded_url" => -0.8,
          "has_allowlist_check" => -0.7,
          "internal_api_pattern" => -0.4
        }
      },
      min_confidence: 0.7
    }
  end
end
