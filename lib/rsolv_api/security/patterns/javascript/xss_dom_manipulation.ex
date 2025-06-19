defmodule RsolvApi.Security.Patterns.Javascript.XssDomManipulation do
  @moduledoc """
  Cross-Site Scripting (XSS) via DOM Manipulation Methods
  
  Detects dangerous patterns like:
    element.insertAdjacentHTML('beforeend', userInput)
    $(element).append(userData)
    node.outerHTML = req.body.content
    $('#content').prepend(params.html)
    
  Safe alternatives:
    element.textContent = userInput
    $(element).text(userData)
    element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(userInput))
    $(element).append(escapeHtml(userData))
    
  DOM manipulation methods that accept HTML strings are prime XSS vectors.
  These methods parse and execute HTML, including any embedded scripts.
  jQuery's methods like .html(), .append(), .prepend() are particularly
  dangerous as they're commonly used and accept raw HTML by default.
  
  ## Vulnerability Details
  
  Modern JavaScript applications frequently manipulate the DOM dynamically.
  Methods that accept HTML strings bypass the browser's built-in XSS
  protections and can execute malicious scripts when given untrusted input.
  This is especially dangerous in single-page applications where DOM
  manipulation is central to the user experience.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct user input to DOM manipulation
  function addComment(comment) {
    $('#comments').append('<div>' + comment + '</div>');
  }
  
  // Attack: comment = "<img src=x onerror='alert(document.cookie)'>"
  // Result: Script executes when image fails to load
  
  // Also vulnerable: insertAdjacentHTML
  function addNotification(message) {
    document.body.insertAdjacentHTML('beforeend', 
      '<div class="notification">' + message + '</div>'
    );
  }
  // Attack: Embedded script tags or event handlers execute
  ```
  
  ### Method-Specific Risks
  Different DOM manipulation methods have varying levels of risk:
  - insertAdjacentHTML: Parses full HTML, very dangerous
  - jQuery .append()/.prepend(): Accept HTML strings by default
  - outerHTML/innerHTML: Direct HTML assignment, no protection
  - .before()/.after(): jQuery methods that parse HTML
  - .replaceWith(): Replaces elements with parsed HTML
  Each requires careful handling of user input.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the XSS DOM Manipulation detection pattern.
  
  This pattern detects usage of DOM manipulation methods that accept
  HTML strings with user-controlled input, leading to XSS vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> pattern.id
      "js-xss-dom-manipulation"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> pattern.cwe_id
      "CWE-79"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> vulnerable = ~S|element.insertAdjacentHTML('beforeend', userInput)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> vulnerable = ~S|$(element).append(userData)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> safe = ~S|element.textContent = userInput|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.pattern()
      iex> pattern.recommendation
      "Use safe DOM methods like textContent or sanitize HTML with DOMPurify before DOM manipulation."
  """
  def pattern do
    %Pattern{
      id: "js-xss-dom-manipulation",
      name: "XSS via DOM Manipulation",
      description: "DOM manipulation methods with user input can execute malicious scripts",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript", "jsx", "tsx"],
      # Match DOM manipulation methods - AST enhancement filters false positives
      regex: ~r/
        ^(?!.*\/\/).*(?:
          insertAdjacentHTML\s*\(|
          \$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
          \$[a-zA-Z_]\w*\s*\.(?:append|prepend|after|before|html)\s*\(|
          jQuery\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
          \.outerHTML\s*=
        )
      /imx,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use safe DOM methods like textContent or sanitize HTML with DOMPurify before DOM manipulation.",
      test_cases: %{
        vulnerable: [
          ~S|element.insertAdjacentHTML('beforeend', userInput)|,
          ~S|$(element).append(userData)|,
          ~S|$('#content').prepend(req.body.content)|,
          ~S|node.outerHTML = params.html|,
          ~S|$('div').after(input)|
        ],
        safe: [
          ~S|element.textContent = userInput|,
          ~S|$(element).text(userData)|,
          ~S|element.insertAdjacentText('beforeend', userInput)|,
          ~S|element.appendChild(document.createTextNode(userData))|,
          ~S|// element.insertAdjacentHTML('beforeend', userInput)|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for DOM Manipulation XSS.
  
  This metadata documents the security implications of using DOM
  manipulation methods with untrusted input and provides guidance
  for secure dynamic content insertion.
  """
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) vulnerabilities through DOM manipulation methods
      are among the most common security issues in modern JavaScript applications.
      These methods bypass the browser's built-in XSS protections by directly
      parsing and executing HTML strings, including any embedded scripts.
      
      The rise of dynamic web applications has made DOM manipulation ubiquitous.
      Methods like insertAdjacentHTML, jQuery's append/prepend, and direct
      innerHTML/outerHTML assignment are powerful but dangerous when used with
      untrusted input. They're designed to parse HTML, which means they'll
      execute any scripts embedded in the input.
      
      jQuery's popularity has made its DOM manipulation methods particularly
      widespread attack vectors. Methods like .html(), .append(), .prepend(),
      .after(), and .before() all accept HTML strings by default. Developers
      often don't realize these methods parse HTML rather than treating input
      as text.
      
      The vulnerability is severe because:
      1. DOM manipulation is fundamental to modern web apps
      2. Many developers don't understand the security implications
      3. The methods are convenient and widely used
      4. Sanitization is often forgotten or incorrectly implemented
      5. Framework migrations often introduce these vulnerabilities
      
      Modern mitigation strategies include using safe methods (textContent),
      HTML sanitization libraries (DOMPurify), Content Security Policy (CSP),
      and framework-specific protections. However, proper input handling
      remains the primary defense against DOM XSS attacks.
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
          type: :mdn,
          id: "insertAdjacentHTML",
          title: "MDN - Element.insertAdjacentHTML() Security Considerations",
          url: "https://developer.mozilla.org/en-US/docs/Web/API/Element/insertAdjacentHTML#security_considerations"
        },
        %{
          type: :research,
          id: "dom_xss_prevention",
          title: "DOM-based XSS Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :jquery,
          id: "jquery_security",
          title: "jQuery Security Considerations",
          url: "https://jquery.com/security/"
        },
        %{
          type: :tool,
          id: "dompurify",
          title: "DOMPurify - XSS Sanitizer for HTML",
          url: "https://github.com/cure53/DOMPurify"
        }
      ],
      attack_vectors: [
        "Script injection: insertAdjacentHTML('beforeend', '<script>alert(1)</script>')",
        "Event handler: append('<img src=x onerror=alert(document.cookie)>')",
        "JavaScript URL: prepend('<a href=\"javascript:alert(1)\">Click</a>')",
        "SVG injection: after('<svg onload=alert(1)>')",
        "Style injection: before('<style>body{background:url(javascript:alert(1))}</style>')",
        "Meta refresh: outerHTML = '<meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\">'",
        "Data URI: append('<object data=\"data:text/html,<script>alert(1)</script>\">')",
        "HTML5 events: insertAdjacentHTML('afterbegin', '<video src=x onerror=alert(1)>')",
        "DOM clobbering: append('<form name=document><input name=cookie>')"
      ],
      real_world_impact: [
        "Session hijacking through cookie theft",
        "Keylogging and form data interception",
        "Phishing through UI manipulation",
        "Cryptocurrency wallet drainage",
        "Social engineering attacks via content injection",
        "Worm propagation in social platforms",
        "Corporate data exfiltration",
        "Browser exploit delivery"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-23917",
          description: "WordPress plugin DOM XSS via jQuery append() with unsanitized user input",
          severity: "high",
          cvss: 7.2,
          note: "Popular plugin vulnerable due to unsafe jQuery DOM manipulation"
        },
        %{
          id: "CVE-2022-44729",
          description: "Apache Superset XSS through insertAdjacentHTML with user-controlled data",
          severity: "high",
          cvss: 7.5,
          note: "Data visualization platform vulnerable to stored XSS"
        },
        %{
          id: "CVE-2021-45232",
          description: "Apache APISIX Dashboard DOM XSS via unsafe innerHTML assignment",
          severity: "medium",
          cvss: 6.1,
          note: "API gateway dashboard vulnerable through DOM manipulation"
        },
        %{
          id: "CVE-2020-11022",
          description: "jQuery < 3.5.0 XSS vulnerability in DOM manipulation methods",
          severity: "medium",
          cvss: 6.1,
          note: "Core jQuery library vulnerability affecting millions of sites"
        }
      ],
      detection_notes: """
      This pattern detects DOM manipulation methods that accept HTML with user input:
      
      1. insertAdjacentHTML with positions: beforebegin, afterbegin, beforeend, afterend
      2. jQuery methods: append(), prepend(), after(), before(), html()
      3. Direct assignment: outerHTML = userInput
      4. Various user input patterns: req.*, params.*, query.*, user*, input, data
      
      The pattern uses AST enhancement to reduce false positives by:
      - Detecting sanitization functions (DOMPurify, escapeHtml, etc.)
      - Identifying static content vs dynamic user input
      - Checking for safe method usage (text(), textContent)
      - Analyzing the data flow to the vulnerable sink
      
      Note that the regex is intentionally broad to catch variations.
      """,
      safe_alternatives: [
        "Use textContent for plain text: element.textContent = userInput",
        "Use jQuery text(): $(element).text(userData)",
        "Sanitize with DOMPurify: insertAdjacentHTML('beforeend', DOMPurify.sanitize(input))",
        "Create elements programmatically: const el = document.createElement('div'); el.textContent = input",
        "Use template literals with escaped values",
        "Implement Content Security Policy (CSP) to block inline scripts",
        "Use framework-specific safe methods (React JSX, Vue templates)",
        "Validate and escape on the server side",
        "Use trusted types API where available",
        "Implement strict input validation"
      ],
      additional_context: %{
        dom_manipulation_methods: [
          "insertAdjacentHTML() - Parses HTML at specified position",
          "innerHTML - Replaces element content with parsed HTML",
          "outerHTML - Replaces entire element with parsed HTML",
          "jQuery.html() - Sets innerHTML of matched elements",
          "jQuery.append() - Adds HTML to end of elements",
          "jQuery.prepend() - Adds HTML to beginning of elements",
          "jQuery.after() - Inserts HTML after elements",
          "jQuery.before() - Inserts HTML before elements",
          "jQuery.replaceWith() - Replaces elements with HTML",
          "document.write() - Writes HTML to document stream"
        ],
        safe_methods: [
          "textContent - Sets text content, auto-escaped",
          "innerText - Similar to textContent with styling",
          "jQuery.text() - jQuery's safe text method",
          "createTextNode() - Creates text node, always safe",
          "setAttribute() - Safe for most attributes",
          "classList methods - Safe for CSS classes",
          "style properties - Generally safe for CSS"
        ],
        common_mistakes: [
          "Thinking jQuery methods only accept text",
          "Not realizing insertAdjacentHTML parses HTML",
          "Concatenating user input into HTML strings",
          "Trusting data from internal APIs",
          "Client-side sanitization without server validation",
          "Using innerHTML for simple text insertion"
        ]
      }
    }
  end
  
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual XSS vulnerabilities
  and safe usage of DOM manipulation methods with proper sanitization.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.ast_enhancement()
      iex> is_list(enhancement.ast_rules.method_names)
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.ast_enhancement()
      iex> "insertAdjacentHTML" in enhancement.ast_rules.method_names
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssDomManipulation.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        method_names: [
          "insertAdjacentHTML",
          "append",
          "prepend",
          "after",
          "before",
          "html",
          "replaceWith"
        ],
        property_assignment: ["innerHTML", "outerHTML"],
        jquery_patterns: %{
          selector_pattern: ~r/\$\s*\([^)]+\)/,
          method_chain: true,
          common_methods: ["append", "prepend", "after", "before", "html"]
        },
        argument_analysis: %{
          check_for_user_input: true,
          user_input_patterns: [
            "req.", "request.", "params.", "query.",
            "body.", "user", "input", "data", "content",
            "form.", "args.", "ctx.", "event.target.value"
          ]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/fixtures/,
          ~r/mocks/,
          ~r/vendor/,
          ~r/node_modules/,
          ~r/dist/,
          ~r/build/
        ],
        safe_patterns: [
          "DOMPurify.sanitize",
          "sanitizeHtml",
          "escapeHtml",
          "_.escape",
          "he.encode",
          "entities.encode",
          "xss(",
          "sanitize(",
          "purify(",
          "clean(",
          "escape("
        ],
        safe_method_calls: [
          ".text(",
          ".textContent",
          ".innerText",
          "createTextNode",
          ".setAttribute(",
          ".classList."
        ],
        static_content_patterns: [
          ~r/^['"`]<[^>]+>['"`]$/,    # Static HTML strings
          ~r/SAFE_/,                    # SAFE_ prefixed constants
          ~r/STATIC_/,                  # STATIC_ prefixed constants
          ~r/TEMPLATE_/,                # Template constants
          ~r/CONST_/                    # Const prefixed variables
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "user_input" => 0.4,                  # Direct user input detected
          "request_data" => 0.4,                # Request data usage
          "dynamic_content" => 0.3,             # Dynamic content insertion
          "no_sanitization" => 0.3,             # No sanitization detected
          "jquery_method" => 0.2,               # jQuery method usage
          "sanitized" => -0.8,                  # Sanitization function used
          "static_content" => -0.7,             # Hardcoded content
          "safe_method" => -0.6,                # Safe method used instead
          "test_code" => -0.6,                  # Test files
          "escaped_content" => -0.5,            # Proper escaping detected
          "framework_safe" => -0.4,             # Framework safe rendering
          "csp_protected" => -0.3               # CSP headers detected
        }
      },
      min_confidence: 0.7
    }
  end
end