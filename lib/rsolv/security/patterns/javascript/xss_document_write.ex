defmodule Rsolv.Security.Patterns.Javascript.XssDocumentWrite do
  @moduledoc """
  Cross-Site Scripting (XSS) via document.write in JavaScript
  
  Detects dangerous patterns like:
    document.write(userInput)
    document.write('<div>' + data + '</div>')
    document.writeln(untrustedContent)
    
  Safe alternatives:
    element.textContent = userInput
    element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(html))
    Use createElement() and appendChild() for dynamic content
    
  document.write() is a dangerous DOM sink that directly writes HTML to the
  document stream during parsing. It can execute embedded scripts and is
  particularly dangerous because it bypasses many modern XSS protections.
  
  ## Vulnerability Details
  
  document.write() writes directly to the document's HTML parser while the page
  is loading. After page load, it replaces the entire document. This makes it
  both a security risk and a performance problem. Modern web development has
  moved away from document.write() entirely.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const name = new URLSearchParams(location.search).get('name');
  document.write('Welcome, ' + name + '!');
  // URL: ?name=<img src=x onerror=alert(document.domain)>
  // Executes: alert(document.domain)
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Structured vulnerability metadata for XSS via document.write.
  
  This metadata documents the specific risks of using document.write with
  untrusted data, including parser blocking and security implications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) via document.write occurs when untrusted data is passed 
      to the document.write() or document.writeln() methods without proper sanitization. 
      These methods write raw HTML directly to the document stream during parsing, executing 
      any embedded scripts immediately. This is a particularly dangerous DOM XSS sink because 
      it bypasses Content Security Policy (CSP) in some configurations and can break modern 
      web applications. Additionally, document.write() blocks the HTML parser and is 
      deprecated in modern web development due to severe performance implications.
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
          id: "DOM_XSS_Sinks",
          url: "https://owasp.org/www-community/attacks/DOM_Based_XSS#dangerous-html-methods",
          title: "OWASP DOM-Based XSS - Dangerous HTML Methods"
        },
        %{
          type: :mdn,
          id: "document_write",
          url: "https://developer.mozilla.org/en-US/docs/Web/API/Document/write#notes",
          title: "MDN - document.write() Security and Performance Issues"
        },
        %{
          type: :google,
          id: "intervention",
          url: "https://developers.google.com/web/updates/2016/08/removing-document-write",
          title: "Chrome Intervention: Blocking document.write() for performance"
        },
        %{
          type: :portswigger,
          id: "dom_xss_document_write",
          url: "https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink",
          title: "PortSwigger - DOM XSS in document.write sink"
        }
      ],
      
      attack_vectors: [
        "Script injection: document.write('<script>alert(1)</script>')",
        "Event handler injection: document.write('<img src=x onerror=alert(1)>')",
        "Breaking out of script context: document.write('</script><script>alert(1)</script>')",
        "Parser confusion: document.write('<!--<script>alert(1)//-->')",
        "SVG injection: document.write('<svg onload=alert(1)>')",
        "Meta refresh injection: document.write('<meta http-equiv=refresh content=0;url=javascript:alert(1)>')",
        "Base tag injection: document.write('<base href=http://evil.com/>')",
        "Style-based XSS: document.write('<style>@import\"javascript:alert(1)\"</style>')"
      ],
      
      real_world_impact: [
        "Complete page replacement after load (destroying user state)",
        "Parser blocking causing severe performance degradation",
        "Bypass of Content Security Policy in certain configurations",
        "Breaking of single-page applications and modern frameworks",
        "Session hijacking through injected scripts",
        "Phishing attacks by rewriting entire page content",
        "Breaking browser optimizations and causing reflows",
        "Potential for stored XSS if output is cached"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2023-23956",
          description: "Bootstrap XSS vulnerability via document.write in tooltip component",
          severity: "medium",
          cvss: 6.1,
          note: "Popular frameworks have had document.write XSS vulnerabilities"
        },
        %{
          id: "CVE-2020-7656",
          description: "jQuery vulnerability allowing XSS through document.write",
          severity: "medium",
          cvss: 6.1,
          note: "Even jQuery had document.write security issues"
        },
        %{
          id: "CVE-2018-14042",
          description: "WordPress plugin XSS via document.write in admin pages",
          severity: "high",
          cvss: 7.5,
          note: "Common in legacy WordPress plugins"
        }
      ],
      
      detection_notes: """
      This pattern detects calls to document.write() and document.writeln() with
      potentially untrusted data. Key indicators:
      1. Direct calls to document.write or document.writeln
      2. Window.document.write variations
      3. Common patterns of string concatenation or template literals
      4. Variable names suggesting user input
      
      The pattern should match all document.write usage since it's deprecated
      and should be replaced with modern DOM manipulation methods.
      """,
      
      safe_alternatives: [
        "Use element.textContent for plain text (automatically escapes HTML)",
        "Use element.insertAdjacentHTML() with DOMPurify.sanitize()",
        "Create elements with document.createElement() and appendChild()",
        "Use modern frameworks (React, Vue, Angular) with auto-escaping",
        "For script loading, use dynamic import() or script.src assignment",
        "For HTML templates, use <template> elements and cloneNode()",
        "Replace document.write() analytics scripts with async alternatives"
      ],
      
      additional_context: %{
        parser_blocking: [
          "document.write() blocks the HTML parser completely",
          "Chrome intervenes and blocks document.write() for slow connections",
          "Can cause 10-100x slower page loads on mobile devices",
          "Prevents browser optimization like speculative parsing",
          "Incompatible with async/defer script loading"
        ],
        
        deprecation_status: [
          "Removed from XHTML and XML documents entirely",
          "Throws exception in deferred or async scripts",
          "Chrome shows console warnings for cross-origin usage",
          "Not supported in Web Workers or Service Workers",
          "Many modern tools (Lighthouse) flag it as severe issue"
        ],
        
        common_legitimate_uses: [
          "Legacy third-party scripts (ads, analytics)",
          "Old-style JavaScript loaders and polyfills",
          "Some JSONP implementations",
          "Legacy browser detection scripts",
          "All should be migrated to modern alternatives"
        ]
      }
    }
  end
  
  @doc """
  Returns the pattern definition for XSS via document.write.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.pattern()
      iex> pattern.id
      "js-xss-document-write"
      iex> pattern.severity
      :high
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-xss-document-write",
      name: "Cross-Site Scripting (XSS) via document.write",
      description: "Direct use of document.write with user input can lead to XSS attacks",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Matches document.write() and document.writeln() calls
      # Also matches window.document.write variations
      regex: ~r/(?:window\.)?document\.write(?:ln)?\s*\(/,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Replace document.write with modern DOM manipulation methods like createElement, textContent, or insertAdjacentHTML with sanitization.",
      test_cases: %{
        vulnerable: [
          ~S|document.write(userInput)|,
          ~S|document.write('<div>' + data + '</div>')|,
          ~S|document.writeln(untrustedData)|,
          ~S|window.document.write(userContent)|,
          ~S|document.write(`<p>${message}</p>`)|
        ],
        safe: [
          ~S|element.textContent = userInput|,
          ~S|element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(html))|,
          ~S|const div = document.createElement('div'); div.textContent = data;|,
          ~S|container.innerHTML = DOMPurify.sanitize(content)|
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Handles JavaScript/TypeScript files and HTML files with embedded JavaScript.
  """
  def applies_to_file?(file_path, content ) do
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
  - document.write with escaped/encoded content
  - Static content only (no user input)
  - Build tools and polyfills that legitimately use document.write
  - Development environment scripts
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.ast_enhancement()
      iex> enhancement.ast_rules.callee.property
      "write"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssDocumentWrite.ast_enhancement()
      iex> "static_content_only" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          object: "document",
          property: "write",
          alternate_properties: ["writeln"]
        },
        # Arguments must contain user input
        argument_analysis: %{
          has_user_input: true,
          not_escaped: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/legacy/, ~r/vendor/],
        exclude_if_sanitized: true,
        exclude_if_static_only: true,
        exclude_if_dev_environment: true,    # document.write often in dev tools
        deprecated_warning: true             # document.write is deprecated anyway
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "user_input_in_write" => 0.4,
          "url_params_in_write" => 0.3,
          "uses_escape_function" => -0.8,
          "uses_encode_function" => -0.7,
          "static_content_only" => -1.0,
          "in_build_script" => -0.9,         # Build tools use document.write
          "in_polyfill" => -0.8              # Polyfills often use it
        }
      },
      min_confidence: 0.8
    }
  end
end
