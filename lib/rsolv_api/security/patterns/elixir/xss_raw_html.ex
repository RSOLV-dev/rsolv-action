defmodule RsolvApi.Security.Patterns.Elixir.XssRawHtml do
  @moduledoc """
  Detects Cross-Site Scripting (XSS) vulnerabilities via raw/html_safe in Phoenix.
  
  This pattern identifies dangerous usage of `Phoenix.HTML.raw/1`, `html_safe/0`, and
  related functions that bypass Phoenix's automatic HTML escaping, potentially allowing
  attackers to inject malicious JavaScript.
  
  ## Vulnerability Details
  
  Phoenix automatically escapes HTML content by default to prevent XSS attacks. However,
  developers can bypass this protection using `raw/1` or `html_safe/0` functions. When
  these functions are used with user-controlled input, it creates XSS vulnerabilities.
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  # In controller
  user_input = params["content"]
  
  # In template
  <%= raw(user_input) %>
  ```
  
  If user_input contains `<script>alert('XSS')</script>`, it will execute in the browser.
  
  ### Safe Alternative
  
  Safe code:
  ```elixir
  # Let Phoenix auto-escape
  <%= user_input %>
  
  # Or use Phoenix.HTML.escape/1 explicitly
  <%= Phoenix.HTML.escape(user_input) %>
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-xss-raw-html",
      name: "XSS via raw/html_safe in Phoenix",
      description: "Detects XSS vulnerabilities through unsafe HTML rendering in Phoenix",
      type: :xss,
      severity: :high,
      languages: ["elixir"],
      regex: [
        # Phoenix.HTML.raw with dynamic content (variables, params, assigns)
        ~r/Phoenix\.HTML\.raw\s*\(\s*(?:@?[a-zA-Z_][a-zA-Z0-9_]*|params\[|assigns\[|conn\.)/,
        # raw() function with dynamic content
        ~r/(?<!Phoenix\.HTML\.)raw\s*\(\s*(?:@?[a-zA-Z_][a-zA-Z0-9_]*|params\[|assigns\[|conn\.)/,
        # html_safe on dynamic content
        ~r/(?:@?[a-zA-Z_][a-zA-Z0-9_]*|params\[|assigns\[|conn\.)[^|]*\|>\s*html_safe\s*\(\s*\)/,
        # .html_safe() method style
        ~r/(?:@?[a-zA-Z_][a-zA-Z0-9_]*|params\[|assigns\[|conn\.).*?\.html_safe\s*\(\s*\)/,
        # raw in template with @ variables
        ~r/<%=\s*raw\s*\(\s*@[a-zA-Z_][a-zA-Z0-9_]*/,
        # raw with assigns access
        ~r/<%=\s*raw\s*\(\s*assigns\[:?\w+\]/,
        # Phoenix.HTML.html_safe with dynamic content
        ~r/Phoenix\.HTML\.html_safe\s*\(\s*(?:@?[a-zA-Z_][a-zA-Z0-9_]*|params\[|assigns\[|conn\.)/
      ],
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use Phoenix's automatic HTML escaping or Phoenix.HTML.escape/1 for user input",
      test_cases: %{
        vulnerable: [
          ~S|Phoenix.HTML.raw(user_input)|,
          ~S|raw(params["content"])|,
          ~S"user_content |> html_safe()",
          ~S|<%= raw(@user_content) %>|,
          ~S|<%= raw(assigns[:content]) %>|,
          ~S|Phoenix.HTML.html_safe(user_generated)|
        ],
        safe: [
          ~S|Phoenix.HTML.escape(user_input)|,
          ~S|raw("<strong>Static Content</strong>")|,
          ~S|<%= @user_input %>|,
          ~S|content_tag(:div, user_input)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) in Phoenix occurs when user-controlled input is rendered
      without proper HTML escaping. Phoenix provides automatic escaping by default, but
      developers can bypass this protection using Phoenix.HTML.raw/1 or html_safe/0 functions.
      When these functions are used with untrusted input, attackers can inject malicious
      JavaScript that executes in users' browsers, potentially stealing cookies, session
      tokens, or performing actions on behalf of the victim.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-79",
          title: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
          url: "https://cwe.mitre.org/data/definitions/79.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "phoenix_xss_patterns",
          title: "Cross Site Scripting (XSS) Patterns in Phoenix",
          url: "https://paraxial.io/blog/xss-phoenix"
        },
        %{
          type: :research,
          id: "elixir_security_checklist",
          title: "Elixir and Phoenix Security Checklist",
          url: "https://paraxial.io/blog/elixir-best"
        }
      ],
      attack_vectors: [
        "Script injection: <script>alert('XSS')</script> executed via raw()",
        "Event handler injection: <img src=x onerror='alert(1)'> via html_safe()",
        "JavaScript URL injection: <a href='javascript:alert(1)'>Click</a> via raw()",
        "SVG injection: <svg onload='alert(1)'></svg> via html_safe()",
        "HTML attribute injection: \" onmouseover=\"alert(1) in unquoted attributes"
      ],
      real_world_impact: [
        "Session hijacking through cookie theft via document.cookie",
        "Account takeover by changing user email/password via XSS",
        "Phishing attacks by injecting fake login forms",
        "Cryptocurrency wallet theft in blockchain applications",
        "Defacement and reputation damage"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-46871",
          description: "Phoenix.HTML before 3.0.4 XSS in HEEx class attributes",
          severity: "high",
          cvss: 6.1,
          note: "XSS vulnerability in Phoenix HTML tag generation allowing script injection via class attributes"
        },
        %{
          id: "CVE-2020-15169",
          description: "Action View XSS vulnerability in escape_javascript",
          severity: "medium",
          cvss: 4.0,
          note: "Similar pattern in Rails showing risks of improper escaping in web frameworks"
        }
      ],
      detection_notes: """
      This pattern detects uses of raw/1 and html_safe/0 with dynamic content including:
      - Variables (user_input, @content)
      - Parameter access (params["key"], conn.params)
      - Assigns in templates (@variable, assigns[:key])
      - Piped operations leading to html_safe()
      """,
      safe_alternatives: [
        "Use default Phoenix HTML escaping: <%= @user_input %>",
        "Use Phoenix.HTML.escape/1 for explicit escaping",
        "Use content_tag/3 which auto-escapes content",
        "Sanitize HTML with libraries like HtmlSanitizeEx if rich text needed",
        "Use Content Security Policy (CSP) headers as defense-in-depth"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that basic string filtering prevents XSS",
          "Using raw() for user-generated 'safe' HTML without proper sanitization",
          "Trusting data from 'internal' sources that could be compromised",
          "Not escaping in JavaScript contexts (different rules than HTML)"
        ],
        secure_patterns: [
          "Always use auto-escaping for user input",
          "Only use raw() with static, developer-controlled content",
          "Implement Content Security Policy headers",
          "Use structured data (JSON) instead of HTML when possible"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        xss_analysis: %{
          check_html_safety: true,
          dangerous_functions: ["Phoenix.HTML.raw", "raw", "html_safe", "Phoenix.HTML.html_safe"],
          safe_functions: ["Phoenix.HTML.escape", "content_tag", "tag"],
          user_input_patterns: ["params", "conn.", "assigns", "@", "user_", "input_"]
        },
        string_analysis: %{
          check_static_strings: true,
          static_indicators: ["<", ">", "\"", "'", "class=", "id=", "style="],
          dynamic_indicators: ["#" <> "{", "$" <> "{", "concat", "interpolate"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/],
        exclude_if_sanitized: true,
        safe_if_uses: ["HtmlSanitizeEx", "phoenix_html_sanitizer", "sanitize_html"]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_html_sanitizer" => -0.7,
          "in_test_code" => -1.0,
          "has_static_content_only" => -0.8,
          "uses_escape_function" => -0.9
        }
      },
      min_confidence: 0.7
    }
  end
end