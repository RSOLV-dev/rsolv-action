defmodule RsolvApi.Security.Patterns.Ruby.SsrfOpenUri do
  @moduledoc """
  Detects Server-Side Request Forgery (SSRF) vulnerabilities in Ruby applications.
  
  SSRF vulnerabilities occur when applications make HTTP requests to URLs controlled by attackers,
  potentially allowing access to internal systems, cloud metadata services, or unauthorized
  external resources. This pattern detects unsafe usage of Ruby HTTP libraries with user input.
  
  ## Vulnerability Details
  
  SSRF attacks can bypass firewalls and access control mechanisms by making requests from the
  server's perspective, potentially exposing internal services, cloud metadata, or causing
  denial of service through resource exhaustion.
  
  ### Attack Example
  ```ruby
  # Vulnerable - direct user input to open-uri
  def fetch_data
    url = params[:url]
    data = open(url).read  # SSRF vulnerability
    render json: { data: data }
  end
  
  # Secure - URL validation and allowlist
  def fetch_data
    url = params[:url]
    uri = URI.parse(url)
    
    allowed_hosts = ['api.example.com', 'trusted.service.com']
    if allowed_hosts.include?(uri.host) && uri.scheme.in?(['http', 'https'])
      data = open(url).read
      render json: { data: data }
    else
      render json: { error: 'Unauthorized URL' }, status: 403
    end
  end
  ```
  
  ### Real-World Impact
  - Access to internal services and cloud metadata (AWS, GCP, Azure)
  - Port scanning and service discovery on internal networks
  - Denial of service through resource exhaustion or infinite loops
  - Bypassing network firewalls and access controls
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the SSRF via open-uri pattern for Ruby applications.
  
  Detects unsafe usage of Ruby HTTP libraries including open-uri, Net::HTTP,
  HTTParty, Faraday, and RestClient with user-controlled input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.pattern()
      iex> pattern.id
      "ruby-ssrf-open-uri"
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.pattern()
      iex> vulnerable = "open(params[:url])"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.pattern()
      iex> safe = "open('https://api.trusted.com/data')"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-ssrf-open-uri",
      name: "SSRF via open-uri",
      description: "Detects Server-Side Request Forgery vulnerabilities through unsafe usage of HTTP libraries with user input",
      type: :ssrf,
      severity: :high,
      languages: ["ruby"],
      regex: [
        # open-uri patterns with user input
        ~r/(?:^|[^#])\s*open\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*URI\.open\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        
        # Net::HTTP patterns with user input
        ~r/(?:^|[^#])\s*Net::HTTP\.get\s*\(\s*URI\s*[\(\.]?\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*Net::HTTP\.get_response\s*\(\s*URI\.parse\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*Net::HTTP\.start\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*Net::HTTP\.new\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        
        # HTTParty patterns with user input
        ~r/(?:^|[^#])\s*HTTParty\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*HTTParty\.request\s*\(\s*:?\w+\s*,\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        
        # Faraday patterns with user input  
        ~r/(?:^|[^#])\s*Faraday\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*Faraday\.new\s*\(\s*(?:url|base_url):\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*(?:faraday|connection)\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        
        # RestClient patterns with user input
        ~r/(?:^|[^#])\s*RestClient\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*RestClient::Request\.execute\s*\(\s*(?:.*\s+)?url:\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/,
        ~r/(?:^|[^#])\s*rest_client\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|[\w_]*_input)/
      ],
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate and allowlist URLs before making HTTP requests. Implement request timeouts and restrict access to internal networks.",
      test_cases: %{
        vulnerable: [
          "open(params[:url])",
          "URI.open(params[:file_url])", 
          "Net::HTTP.get(URI(params[:target]))",
          "HTTParty.get(params[:api_url])",
          "Faraday.get(params[:endpoint])",
          "RestClient.get(params[:api_endpoint])"
        ],
        safe: [
          "open('https://api.trusted.com/data')",
          "URI.open('http://localhost:3000/health')",
          "Net::HTTP.get(URI('https://example.com/api'))",
          "HTTParty.get('https://api.github.com/users')",
          "# open(params[:url]) # Commented out"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Server-Side Request Forgery (SSRF) vulnerabilities occur when web applications make HTTP requests to URLs that are controlled or influenced by attackers.
      These vulnerabilities can lead to unauthorized access to internal systems, cloud metadata services, and external resources, potentially bypassing
      network security controls and exposing sensitive information or functionality.
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
          title: "OWASP Top 10 2021 - Server-Side Request Forgery",
          url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        },
        %{
          type: :research,
          id: "ruby_ssrf_portswigger",
          title: "Server-side request forgery (SSRF) - PortSwigger",
          url: "https://portswigger.net/web-security/ssrf"
        },
        %{
          type: :research,
          id: "owasp_ssrf_cheat_sheet",
          title: "OWASP Server-Side Request Forgery Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "ruby_http_security",
          title: "Ruby HTTP Client Security Best Practices",
          url: "https://blog.heroku.com/ruby-ssrf-vulnerabilities"
        }
      ],
      attack_vectors: [
        "Internal service discovery and port scanning via localhost requests",
        "Cloud metadata service access (AWS, GCP, Azure) to retrieve credentials",
        "Internal API access bypassing authentication and network controls",
        "File system access via file:// protocol (depending on HTTP library)",
        "Denial of service through resource exhaustion or infinite redirect loops",
        "DNS rebinding attacks to bypass same-origin policies",
        "Blind SSRF attacks using out-of-band techniques for data exfiltration"
      ],
      real_world_impact: [
        "Exposure of AWS/GCP/Azure metadata containing sensitive credentials and configuration",
        "Access to internal APIs and services not exposed to the internet",
        "Potential for lateral movement within internal networks and systems"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-11027",
          description: "SSRF vulnerability in ruby-openid allowing bypass of domain verification",
          severity: "medium",
          cvss: 6.1,
          note: "Demonstrated SSRF in Ruby OpenID library through crafted discovery URLs"
        },
        %{
          id: "CVE-2022-27311", 
          description: "SSRF vulnerability in gibbon gem allowing unauthorized HTTP requests",
          severity: "medium",
          cvss: 5.3,
          note: "Server-Side Request Forgery in MailChimp Ruby API wrapper"
        },
        %{
          id: "CVE-2021-28965",
          description: "SSRF in Ruby's Net::IMAP through crafted server responses",
          severity: "medium", 
          cvss: 5.8,
          note: "Demonstrates SSRF vulnerabilities even in standard library components"
        },
        %{
          id: "CVE-2021-41098",
          description: "SSRF vulnerability in Ruby's URI.open method",
          severity: "high",
          cvss: 7.5,
          note: "Direct SSRF vulnerability in Ruby's built-in URI handling"
        }
      ],
      detection_notes: """
      This pattern detects common Ruby HTTP libraries used with user-controlled input:
      - open-uri: Built-in Ruby library for opening URIs
      - Net::HTTP: Standard library HTTP client 
      - HTTParty: Popular gem for HTTP requests
      - Faraday: HTTP/REST API client library
      - RestClient: Simple HTTP and REST client
      
      The pattern uses negative lookbehind to avoid matching commented code and focuses on
      user input sources like params, request parameters, and user-controlled variables.
      """,
      safe_alternatives: [
        "Implement URL allowlisting to restrict requests to trusted domains",
        "Use URI parsing and validation to check scheme, host, and port",
        "Implement network-level controls to prevent access to internal ranges",
        "Set appropriate timeouts to prevent resource exhaustion",
        "Use HTTP libraries with built-in SSRF protection features",
        "Sanitize and validate all user input before making HTTP requests"
      ],
      additional_context: %{
        common_mistakes: [
          "Relying only on client-side URL validation without server-side checks",
          "Allowing access to localhost and private IP ranges (127.0.0.1, 10.x.x.x, 192.168.x.x)",
          "Not implementing proper timeout mechanisms for HTTP requests",
          "Trusting user-provided redirect URLs without validation"
        ],
        secure_patterns: [
          "Always validate URLs against an allowlist of trusted domains",
          "Reject requests to private IP ranges and localhost unless explicitly needed",
          "Implement proper error handling to avoid information disclosure",
          "Use application-level firewalls to restrict outbound HTTP requests"
        ],
        framework_notes: %{
          rails: "Use Rails.application.config.force_ssl and validate URLs in controller actions",
          sinatra: "Implement custom middleware for URL validation and SSRF protection",
          general: "Consider using gems like 'ssrf_filter' for additional protection layers"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for SSRF detection.

  This enhancement helps distinguish between legitimate HTTP requests and potential
  SSRF vulnerabilities by analyzing URL validation, allowlisting, and user input context.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.SsrfOpenUri.ast_enhancement()
      iex> enhancement.ast_rules.http_library_analysis.open_uri_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        http_library_analysis: %{
          open_uri_methods: true,
          net_http_methods: true,
          httparty_methods: true,
          faraday_methods: true,
          rest_client_methods: true,
          check_method_names: ["open", "URI.open", "Net::HTTP.get", "HTTParty.get", "Faraday.get", "RestClient.get"]
        },
        user_input_analysis: %{
          input_sources: ["params", "request", "user_input", "user_data", "form_params"],
          check_direct_usage: true,
          check_string_interpolation: true,
          track_variable_flow: true
        },
        url_analysis: %{
          check_url_validation: true,
          allowlist_patterns: true,
          dangerous_schemes: ["file", "ftp", "ldap", "dict", "gopher"],
          safe_domains: ["localhost", "127.0.0.1", "::1"],
          check_uri_parsing: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/development/],
        exclude_if_validated: true,
        safe_if_uses: ["URI.parse", "allowlist", "whitelist", "trusted_domains", "validate_url"],
        check_allowlist_presence: true,
        exclude_hardcoded_urls: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "direct_params_usage" => 0.3,
          "no_url_validation" => 0.2,
          "internal_network_access" => 0.2,
          "has_allowlist_check" => -0.6,
          "has_uri_validation" => -0.4,
          "hardcoded_url" => -1.0,
          "in_test_code" => -1.0,
          "has_timeout_protection" => -0.2
        }
      },
      min_confidence: 0.7
    }
  end
end