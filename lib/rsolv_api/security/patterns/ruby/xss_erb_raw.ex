defmodule RsolvApi.Security.Patterns.Ruby.XssErbRaw do
  @moduledoc """
  Detects Cross-Site Scripting (XSS) vulnerabilities in Ruby ERB templates.
  
  XSS vulnerabilities in ERB templates occur when user-controlled data is rendered directly
  into HTML without proper escaping. This commonly happens when using `raw`, `html_safe`,
  or the `<%==` syntax with untrusted input, allowing attackers to inject malicious scripts.
  
  ## Vulnerability Details
  
  Rails provides automatic HTML escaping by default, but certain methods and syntaxes bypass
  this protection. When developers use these unsafe methods with user input, they create
  XSS vulnerabilities that can lead to session hijacking, data theft, and malicious actions.
  
  ### Attack Example
  ```erb
  <!-- Vulnerable - raw bypasses HTML escaping -->
  <div class="content">
    <%= raw params[:content] %>
  </div>
  
  <!-- Vulnerable - html_safe marks string as safe -->
  <p>Welcome <%= params[:name].html_safe %>!</p>
  
  <!-- Vulnerable - double equals syntax bypasses escaping -->
  <span><%== user_input %></span>
  
  <!-- Secure - default HTML escaping -->
  <div class="content">
    <%= params[:content] %>
  </div>
  
  <!-- Secure - explicit sanitization -->
  <p>Welcome <%= sanitize(params[:name]) %>!</p>
  ```
  
  ### Real-World Impact
  - Session hijacking through stolen authentication cookies
  - Defacement of web pages and content manipulation
  - Phishing attacks and credential harvesting
  - Malware distribution and drive-by downloads
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the XSS in ERB Templates pattern for Ruby applications.
  
  Detects unsafe usage of raw, html_safe, and double equals syntax in ERB
  templates that can lead to XSS vulnerabilities when used with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.XssErbRaw.pattern()
      iex> pattern.id
      "ruby-xss-erb-raw"
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.XssErbRaw.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.XssErbRaw.pattern()
      iex> vulnerable = "<%= raw params[:content] %>"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.XssErbRaw.pattern()
      iex> safe = "<%= params[:content] %>"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-xss-erb-raw",
      name: "XSS in ERB Templates",
      description: "Detects Cross-Site Scripting vulnerabilities in ERB templates through unsafe usage of raw, html_safe, and unescaped output",
      type: :xss,
      severity: :high,
      languages: ["ruby"],
      regex: [
        # raw with user input - various user input patterns
        ~r/<%=\s*raw\s+(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)/,
        ~r/<%=\s*raw\s+@?\w*\[['"]?\w*['"]?\]/,
        
        # html_safe with any content - simplified to catch more cases
        ~r/<%=\s*.*\.html_safe\s*%>/,
        
        # Double equals syntax (unescaped output)
        ~r/<%==\s*(?:params|request\.(?:params|parameters)|user_[\w_]*|@?\w*)/,
        
        # String concatenation or interpolation with html_safe
        ~r/<%=\s*\([^)]*(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)[^)]*\)\.html_safe/,
        ~r/<%=\s*["'][^"']*#\{[^}]*(?:params|request\.(?:params|parameters)|user_[\w_]*|@\w+)[^}]*\}[^"']*["']\.html_safe/,
        
        # Comment detection for limitation testing
        ~r/#.*<%=\s*raw\s+params/
      ],
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use Rails' default HTML escaping. If HTML content is needed, use sanitize() helper or validate/allowlist the content.",
      test_cases: %{
        vulnerable: [
          "<%= raw params[:content] %>",
          "<%= params[:name].html_safe %>",
          "<%== user_input %>",
          "<%= (\"<div>\" + params[:content] + \"</div>\").html_safe %>",
          "<%= params[:content].strip.html_safe %>",
          "<%= \"Hello \#{params[:name]}!\".html_safe %>"
        ],
        safe: [
          "<%= params[:content] %>",
          "<%= sanitize(params[:content]) %>",
          "<%= h(user_input) %>",
          "<%= html_escape(params[:message]) %>",
          "<%= raw \"<div>Static HTML</div>\" %>",
          "<%= \"Static content\".html_safe %>"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) vulnerabilities in ERB templates occur when user-controlled data is rendered into HTML without proper escaping.
      While Rails provides automatic HTML escaping by default, certain methods like `raw`, `html_safe`, and the `<%==` syntax bypass this protection.
      When these unsafe methods are used with untrusted input, they create opportunities for attackers to inject malicious scripts into web pages,
      leading to session hijacking, data theft, and other client-side attacks.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-79",
          title: "Cross-site Scripting (XSS)",
          url: "https://cwe.mitre.org/data/definitions/79.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "rails_xss_prevention",
          title: "XSS Prevention for Ruby on Rails - Semgrep",
          url: "https://semgrep.dev/docs/cheat-sheets/rails-xss"
        },
        %{
          type: :research,
          id: "owasp_rails_cheat_sheet",
          title: "Ruby on Rails Security Cheat Sheet - OWASP",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "rails_xss_examples",
          title: "Rails XSS: Examples and Prevention - StackHawk",
          url: "https://www.stackhawk.com/blog/rails-xss-examples-and-prevention/"
        }
      ],
      attack_vectors: [
        "Script injection through unescaped user input in ERB templates",
        "HTML injection via raw() method with user-controlled content",
        "Attribute injection through html_safe() on user input",
        "Event handler injection in HTML attributes (onclick, onload, etc.)",
        "CSS injection through style attributes and stylesheets",
        "Meta tag manipulation for redirection and refresh attacks",
        "Form manipulation and CSRF token extraction"
      ],
      real_world_impact: [
        "Session hijacking through cookie theft and authentication bypass",
        "Credential harvesting via fake login forms and phishing pages",
        "Malware distribution through malicious script injection and redirects"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-26143",
          description: "XSS vulnerability in Rails translation helpers when using keys ending in '_html' with untrusted user input",
          severity: "medium",
          cvss: 6.1,
          note: "Affects Rails >= 7.0.0, demonstrates template-level XSS vulnerabilities in Rails applications"
        },
        %{
          id: "CVE-2024-39308",
          description: "XSS vulnerability in RailsAdmin list view through improperly-escaped HTML title attribute",
          severity: "medium",
          cvss: 5.4,
          note: "Shows how template escaping failures can affect admin interfaces and management tools"
        },
        %{
          id: "CVE-2015-3226",
          description: "XSS vulnerability in ActiveSupport JSON encoding allowing script injection via crafted Hash",
          severity: "medium",
          cvss: 4.3,
          note: "Demonstrates how data serialization can lead to XSS when rendered in templates"
        },
        %{
          id: "CVE-2022-32209",
          description: "XSS vulnerability in Rails::Html::Sanitizer allowing bypass of sanitization",
          severity: "medium",
          cvss: 6.1,
          note: "Shows importance of proper sanitization even when using Rails security helpers"
        }
      ],
      detection_notes: """
      This pattern detects common XSS vulnerabilities in ERB templates:
      - raw() method usage with user input parameters
      - html_safe() method calls on user-controlled data
      - Double equals (<%==) syntax for unescaped output
      - String concatenation and interpolation with html_safe()
      - Method chaining ending in html_safe() on user input
      
      The pattern focuses on user input sources like params, request parameters, and instance variables
      that commonly contain user data. AST enhancement provides additional context analysis.
      """,
      safe_alternatives: [
        "Use Rails' default HTML escaping: <%= user_input %> instead of <%= raw user_input %>",
        "Use sanitize() helper for rich content: <%= sanitize(user_content) %>",
        "Use html_escape() or h() for explicit escaping: <%= h(user_input) %>",
        "Validate and allowlist HTML content before marking as html_safe",
        "Use content_tag() helper for generating HTML with user data",
        "Implement Content Security Policy (CSP) headers as additional protection"
      ],
      additional_context: %{
        common_mistakes: [
          "Using raw() or html_safe() with any user-controlled input",
          "Concatenating user input with HTML and calling html_safe()",
          "Using <%== syntax without understanding its security implications",
          "Assuming that basic string manipulation makes content safe"
        ],
        secure_patterns: [
          "Always use default Rails escaping unless absolutely necessary",
          "If HTML is needed, use sanitize() with appropriate allowlists",
          "Validate and filter user input before any HTML rendering",
          "Use CSP headers to limit script execution sources"
        ],
        framework_notes: %{
          rails: "Rails auto-escapes by default. Avoid raw(), html_safe(), and <%== unless necessary",
          erb: "ERB itself doesn't provide XSS protection - rely on Rails helpers and proper escaping",
          general: "Template security depends on consistent use of framework escaping mechanisms"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for ERB XSS detection.

  This enhancement helps distinguish between safe usage of raw/html_safe with static
  content and dangerous usage with user-controlled input.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Ruby.XssErbRaw.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.XssErbRaw.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.XssErbRaw.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "ERBNode"
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.XssErbRaw.ast_enhancement()
      iex> enhancement.ast_rules.erb_analysis.unsafe_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "ERBNode",
        erb_analysis: %{
          unsafe_methods: true,
          double_equals_syntax: true,
          check_method_calls: ["raw", "html_safe"],
          output_expressions: true,
          expression_type_analysis: true
        },
        user_input_analysis: %{
          input_sources: ["params", "request", "user_input", "user_data", "@user", "@current_user"],
          check_direct_usage: true,
          check_method_chaining: true,
          check_string_interpolation: true,
          track_variable_flow: true
        },
        sanitization_analysis: %{
          check_sanitization_methods: true,
          safe_methods: ["sanitize", "html_escape", "h", "strip_tags"],
          escape_methods: ["CGI.escapeHTML", "ERB::Util.html_escape"],
          content_security_methods: ["content_tag", "link_to", "button_to"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        exclude_if_sanitized: true,
        safe_if_uses: ["sanitize", "html_escape", "h", "strip_tags", "content_tag"],
        check_static_content: true,
        exclude_static_strings: true,
        check_template_context: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "direct_params_usage" => 0.3,
          "user_instance_variable" => 0.2,
          "method_chaining_on_user_input" => 0.2,
          "string_interpolation_with_user_data" => 0.3,
          "has_sanitization" => -0.8,
          "static_string_content" => -1.0,
          "in_test_code" => -1.0,
          "has_content_security_policy" => -0.2
        }
      },
      min_confidence: 0.7
    }
  end
end