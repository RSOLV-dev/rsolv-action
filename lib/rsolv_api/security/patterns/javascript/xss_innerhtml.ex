defmodule RsolvApi.Security.Patterns.Javascript.XssInnerhtml do
  @moduledoc """
  Cross-Site Scripting (XSS) via innerHTML in JavaScript
  
  Detects dangerous patterns like:
    element.innerHTML = userInput
    document.getElementById('div').innerHTML = untrustedData
    
  Safe alternatives:
    element.textContent = userInput
    element.innerText = userInput
    element.innerHTML = DOMPurify.sanitize(userInput)
    element.setHTML(userInput)  // New Sanitizer API
    
  innerHTML is one of the most common DOM XSS sinks. It parses and executes
  any HTML/JavaScript in the assigned string, making it extremely dangerous
  when used with untrusted data.
  
  ## Vulnerability Details
  
  DOM-based XSS occurs when attacker-controlled data reaches dangerous sinks
  like innerHTML without proper sanitization. Unlike reflected or stored XSS,
  DOM XSS happens entirely in the browser, often bypassing server-side defenses.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const searchTerm = new URLSearchParams(location.search).get('q');
  document.getElementById('results').innerHTML = 'You searched for: ' + searchTerm;
  // URL: ?q=<img src=x onerror=alert(document.cookie)>
  // Executes: alert(document.cookie)
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Structured vulnerability metadata for XSS via innerHTML.
  
  This metadata documents the specific risks of using innerHTML with
  untrusted data, including various attack vectors and bypass techniques.
  """
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) via innerHTML occurs when untrusted data is assigned 
      to an element's innerHTML property without proper sanitization. The innerHTML 
      property parses the assigned string as HTML, executing any embedded JavaScript. 
      This creates a DOM-based XSS vulnerability that can lead to session hijacking, 
      data theft, and account takeover. DOM XSS is particularly dangerous because it 
      happens entirely client-side, potentially bypassing server-side XSS filters and 
      Web Application Firewalls (WAFs).
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-79",
          url: "https://cwe.mitre.org/data/definitions/79.html",
          title: "Improper Neutralization of Input During Web Page Generation"
        },
        %{
          type: :owasp,
          id: "DOM_XSS",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
          title: "OWASP DOM based XSS Prevention Cheat Sheet"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          url: "https://owasp.org/Top10/A03_2021-Injection/",
          title: "OWASP Top 10 2021 - A03 Injection"
        },
        %{
          type: :mdn,
          id: "innerHTML_security",
          url: "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations",
          title: "MDN - innerHTML Security Considerations"
        },
        %{
          type: :portswigger,
          id: "dom_xss_lab",
          url: "https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink",
          title: "PortSwigger - DOM XSS in innerHTML sink"
        }
      ],
      
      attack_vectors: [
        "Script tags: <script>alert(1)</script>",
        "Event handlers: <img src=x onerror=alert(1)>",
        "SVG elements: <svg onload=alert(1)>",
        "HTML5 events: <video src=x onerror=alert(1)>",
        "JavaScript URLs: <iframe src=javascript:alert(1)>",
        "Data URLs: <object data='data:text/html,<script>alert(1)</script>'>",
        "Style injection: <style>@keyframes x{}</style><div style='animation-name:x' onanimationstart=alert(1)>",
        "Meta refresh: <meta http-equiv='refresh' content='0;javascript:alert(1)'>"
      ],
      
      real_world_impact: [
        "Session hijacking through cookie theft",
        "Keylogging and form data interception",
        "Phishing attacks via DOM manipulation",
        "Cryptocurrency mining through injected scripts",
        "Browser exploitation and client-side attacks",
        "Defacement and reputation damage",
        "CSRF token theft enabling further attacks",
        "Local storage and IndexedDB data exfiltration"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2020-11022",
          description: "jQuery innerHTML XSS vulnerability affecting versions < 3.5.0",
          severity: "medium",
          cvss: 6.1,
          note: "Even popular libraries like jQuery had innerHTML XSS issues"
        },
        %{
          id: "CVE-2019-11358",
          description: "jQuery prototype pollution leading to XSS via innerHTML",
          severity: "medium",
          cvss: 6.1,
          note: "Prototype pollution can lead to innerHTML XSS"
        },
        %{
          id: "CVE-2024-5585",
          description: "WordPress Gutenberg innerHTML XSS in block editor",
          severity: "high",
          cvss: 7.5,
          note: "Modern frameworks still vulnerable to innerHTML XSS"
        }
      ],
      
      detection_notes: """
      This pattern detects assignments to innerHTML property with potentially
      untrusted data. Key indicators:
      1. Direct assignment to .innerHTML property
      2. Common variable names suggesting user input (userInput, data, etc.)
      3. Request parameters (req.query, req.params)
      4. String concatenation or template literals with innerHTML
      
      The pattern must avoid matching legitimate sanitized usage like
      DOMPurify.sanitize() or the new setHTML() API.
      """,
      
      safe_alternatives: [
        "Use element.textContent for plain text (automatically escapes HTML)",
        "Use element.innerText for styled text (also escapes HTML)",
        "Sanitize with DOMPurify: element.innerHTML = DOMPurify.sanitize(input)",
        "Use the new Sanitizer API: element.setHTML(input)",
        "Create elements programmatically with createElement() and appendChild()",
        "Use a templating library with automatic escaping (React, Vue, Angular)",
        "Implement Content Security Policy (CSP) to mitigate XSS impact"
      ],
      
      additional_context: %{
        common_mistakes: [
          "Believing innerHTML is safe for 'trusted' user input",
          "Using basic string replacement instead of proper sanitization",
          "Forgetting that innerHTML executes JavaScript in many contexts",
          "Not considering DOM clobbering attacks",
          "Assuming server-side XSS protection prevents DOM XSS"
        ],
        
        browser_differences: [
          "Different browsers may execute different XSS payloads",
          "IE/Edge had different innerHTML parsing than Chrome/Firefox",
          "Some browsers block <script> in innerHTML but not event handlers",
          "Mobile browsers may have different XSS filters"
        ],
        
        modern_defenses: [
          "Content Security Policy (CSP) with strict directives",
          "Trusted Types API for sink validation",
          "DOMPurify library for safe HTML sanitization",
          "Framework auto-escaping (React dangerouslySetInnerHTML)",
          "Sanitizer API (future standard)"
        ]
      }
    }
  end
  
  @doc """
  Returns the pattern definition for XSS via innerHTML.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.pattern()
      iex> pattern.id
      "js-xss-innerhtml"
      iex> pattern.severity
      :high
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-xss-innerhtml",
      name: "Cross-Site Scripting (XSS) via innerHTML",
      description: "Direct assignment of user input to innerHTML can lead to XSS attacks",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Matches element.innerHTML = value
      # Note: AST enhancement is used to filter out sanitized content
      regex: ~r/^(?!.*\/\/).*\.innerHTML\s*=/m,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use textContent or innerText for plain text. For HTML content, use DOMPurify.sanitize() or the Sanitizer API.",
      test_cases: %{
        vulnerable: [
          ~S|element.innerHTML = userInput|,
          ~S|document.getElementById('content').innerHTML = data|,
          ~S|div.innerHTML = req.query.search|,
          ~S|container.innerHTML = '<div>' + untrustedData + '</div>'|,
          ~S|el.innerHTML = `<p>${userMessage}</p>`|
        ],
        safe: [
          ~S|element.innerText = userInput|,
          ~S|element.textContent = data|,
          ~S|// div.innerHTML = userInput|,
          ~S|container.setHTML(untrustedData)|,
          ~S|const safe = escapeHtml(userMessage)|
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Handles JavaScript/TypeScript files and HTML files with embedded JavaScript.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx)$/i) -> true
      
      # HTML files with script tags
      String.match?(file_path, ~r/\.html?$/i) && content != nil ->
        String.contains?(content, "<script")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual XSS vulnerabilities and:
  - innerHTML assignments with sanitized content (DOMPurify, etc.)
  - Static HTML content without user input
  - Escaped HTML content
  - Framework-managed content (React, Vue, etc.)
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "AssignmentExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.ast_enhancement()
      iex> enhancement.ast_rules.left_side.property
      "innerHTML"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssInnerhtml.ast_enhancement()
      iex> "uses_dom_purify" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "AssignmentExpression",
        # Must be assigning to innerHTML property
        left_side: %{
          property: "innerHTML",
          object_type: "MemberExpression"
        },
        # Right side must have user input
        right_side_analysis: %{
          contains_user_input: true,
          not_sanitized: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        exclude_if_sanitized: true,          # DOMPurify, sanitize-html, etc.
        exclude_if_static_content: true,     # No dynamic content
        exclude_if_escaped: true,            # Uses escape functions
        safe_if_uses_text_content: true      # textContent is safe
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "direct_user_input_to_innerhtml" => 0.5,
          "concatenated_user_input" => 0.3,
          "uses_dom_purify" => -0.9,
          "uses_sanitize_function" => -0.8,
          "uses_escape_html" => -0.7,
          "static_html_only" => -1.0,
          "in_framework_template" => -0.6    # React/Vue handle this
        }
      },
      min_confidence: 0.8
    }
  end
end
