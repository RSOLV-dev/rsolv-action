defmodule RsolvApi.Security.Patterns.Javascript.XssJqueryHtml do
  @moduledoc """
  Cross-Site Scripting (XSS) via jQuery html() method
  
  Detects dangerous patterns like:
    $("#output").html(userInput)
    $('.content').html(req.body.content)
    jQuery("#div").html(params.message)
    
  Safe alternatives:
    $("#output").text(userInput)
    $('.content').html(DOMPurify.sanitize(userInput))
    $("#div").html(escapeHtml(params.message))
    
  jQuery's html() method is similar to innerHTML in that it interprets the string
  as HTML and can execute embedded scripts. When used with untrusted user input,
  it creates XSS vulnerabilities that allow attackers to inject malicious scripts
  that execute in other users' browsers.
  
  ## Vulnerability Details
  
  The jQuery html() method sets the HTML contents of matched elements. Unlike the
  text() method which treats content as plain text, html() parses and executes
  any HTML tags and JavaScript within the content. This makes it particularly
  dangerous when used with user-controlled input.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct user input to html()
  $('#message').html(req.query.message);
  
  // Attack: ?message=<script>alert(document.cookie)</script>
  // Result: Script executes and can steal session cookies
  
  // Also vulnerable: Template literal injection
  $('.greeting').html(`Welcome ${username}!`);
  // If username contains HTML/JS, it will execute
  ```
  
  ### jQuery-Specific Risks
  jQuery is still widely used in legacy applications and even some modern ones.
  The html() method is commonly misused because developers assume jQuery provides
  some level of automatic sanitization, which it does not. The method is essentially
  a cross-browser wrapper around innerHTML with the same security implications.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the XSS jQuery html() detection pattern.
  
  This pattern detects usage of jQuery's html() method with user-controlled input,
  which can lead to XSS vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> pattern.id
      "js-xss-jquery-html"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> pattern.cwe_id
      "CWE-79"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> vulnerable = ~S|$("#output").html(userInput)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> safe = ~S|$("#output").html(DOMPurify.sanitize(userInput))|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> safe = ~S|$("#output").text(userInput)|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> vulnerable = ~S|$('.content').html(req.body.content)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.pattern()
      iex> pattern.recommendation
      "Use jQuery text() for plain text, or sanitize HTML with DOMPurify before using html()."
  """
  def pattern do
    %Pattern{
      id: "js-xss-jquery-html",
      name: "XSS via jQuery html()",
      description: "jQuery html() method with user input can execute malicious scripts",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:\$(?:\([^)]+\)|\w+)|jQuery\s*\([^)]+\))\.html\s*\(\s*(?!DOMPurify\.sanitize|escapeHtml|sanitizeHTML|purify|SAFE_).*?(?:req\.|request\.|params\.|query\.|body\.|user|input|data|userData|untrusted)/i,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use jQuery text() for plain text, or sanitize HTML with DOMPurify before using html().",
      test_cases: %{
        vulnerable: [
          ~S|$("#output").html(userInput)|,
          ~S|$('.content').html(req.body.content)|,
          ~S|jQuery("#div").html(params.message)|,
          ~S|$element.html(query.data)|,
          ~S|$(this).html(userData)|
        ],
        safe: [
          ~S|$("#output").text(userInput)|,
          ~S|$('.content').html(DOMPurify.sanitize(req.body.content))|,
          ~S|jQuery("#div").html(escapeHtml(params.message))|,
          ~S|$element.html("<p>Static content</p>")|,
          ~S|$(this).html(SAFE_TEMPLATE)|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for jQuery html() XSS.
  
  This metadata documents the security implications of using jQuery's html()
  method with untrusted input and provides authoritative guidance for secure
  HTML manipulation in jQuery applications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) vulnerabilities through jQuery's html() method
      represent a significant security risk in web applications. The html() method
      in jQuery functions similarly to the native innerHTML property, interpreting
      string content as HTML and executing any embedded JavaScript code.
      
      When user-controlled input is passed directly to the html() method without
      proper sanitization, attackers can inject malicious scripts that execute in
      the context of other users' browsers. This can lead to session hijacking,
      credential theft, defacement, and other serious security breaches.
      
      jQuery remains one of the most widely used JavaScript libraries, especially
      in legacy applications and content management systems. Many developers
      incorrectly assume that jQuery provides automatic XSS protection, but the
      html() method offers no built-in sanitization. This misconception has led
      to numerous XSS vulnerabilities in production applications.
      
      The vulnerability is particularly dangerous because:
      1. jQuery's widespread adoption means many applications are at risk
      2. The html() method is commonly used for dynamic content updates
      3. Developers often choose html() over text() for formatting flexibility
      4. Legacy jQuery code may lack modern security practices
      5. jQuery plugins may introduce additional XSS vectors
      
      Modern web applications using jQuery must implement proper sanitization
      strategies, either through dedicated libraries like DOMPurify or by using
      jQuery's text() method when HTML rendering is not required. The rise of
      Content Security Policy (CSP) has provided an additional defense layer,
      but proper input sanitization remains the primary protection against XSS.
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
          type: :owasp,
          id: "XSS_Prevention",
          title: "OWASP XSS Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :vendor,
          id: "jquery_html",
          title: "jQuery html() Documentation",
          url: "https://api.jquery.com/html/"
        },
        %{
          type: :research,
          id: "dom_xss",
          title: "DOM Based XSS Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :nist,
          id: "SP_800-95",
          title: "Guide to Secure Web Services",
          url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-95.pdf"
        }
      ],
      attack_vectors: [
        "Script injection: $('#div').html('<script>alert(1)</script>')",
        "Event handler injection: .html('<img src=x onerror=alert(1)>')",
        "JavaScript URL injection: .html('<a href=\"javascript:alert(1)\">Click</a>')",
        "SVG-based XSS: .html('<svg onload=alert(1)>')",
        "HTML attribute breaking: .html('\" onmouseover=\"alert(1)')",
        "Template literal injection: .html(`${userInput}`)",
        "jQuery selector injection: $(userInput).html('<script>...')",
        "Nested jQuery XSS: .html($('<div>').html(userInput).html())"
      ],
      real_world_impact: [
        "Session cookie theft leading to account takeover",
        "Keylogging and credential harvesting",
        "Phishing attacks through injected forms",
        "Website defacement affecting brand reputation",
        "Cryptocurrency wallet theft via injected scripts",
        "Drive-by malware downloads",
        "Social engineering through fake UI elements",
        "CSRF token extraction enabling further attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-11022",
          description: "jQuery versions < 3.5.0 passing HTML containing <option> elements to manipulation methods could execute untrusted code",
          severity: "moderate",
          cvss: 6.1,
          note: "Demonstrates that even jQuery itself had XSS vulnerabilities in HTML handling"
        },
        %{
          id: "CVE-2019-11358",
          description: "jQuery before 3.4.0 mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution",
          severity: "moderate",
          cvss: 6.1,
          note: "While not directly html() related, shows jQuery security issues"
        },
        %{
          id: "CVE-2018-9206",
          description: "jQuery Upload File plugin XSS via uploadFile filename parameter",
          severity: "high",
          cvss: 7.5,
          note: "Common jQuery plugin with XSS via html() method usage"
        },
        %{
          id: "CVE-2021-29425",
          description: "Apache Superset jQuery XSS in dashboard markdown component",
          severity: "high",
          cvss: 7.5,
          note: "Real-world application XSS through jQuery html() usage"
        }
      ],
      detection_notes: """
      This pattern detects jQuery html() method calls that include user-controlled
      input. The detection covers:
      
      1. Direct jQuery selectors: $(...).html(userInput)
      2. jQuery function calls: jQuery(...).html(userInput)
      3. Chained jQuery methods: $(...).find(...).html(userInput)
      4. Various user input patterns: req.*, params.*, query.*, user*, input, data
      
      The pattern excludes safe usage where sanitization functions are detected:
      - DOMPurify.sanitize()
      - escapeHtml()
      - sanitizeHTML()
      - Other common sanitization patterns
      
      Note that static strings and safe templates are also excluded from detection
      to reduce false positives.
      """,
      safe_alternatives: [
        "Use .text() instead of .html() when displaying user content",
        "Sanitize with DOMPurify: .html(DOMPurify.sanitize(userInput))",
        "Use template literals with escaped values: .html(`<p>${escapeHtml(user)}</p>`)",
        "Implement Content Security Policy (CSP) headers",
        "Use jQuery validation plugins that handle escaping",
        "Create DOM elements programmatically: $('<p>').text(userInput)",
        "Use modern frameworks with built-in XSS protection",
        "Implement server-side HTML sanitization",
        "Use jQuery's .prop() or .attr() for attributes instead of HTML strings",
        "Consider migrating to frameworks with automatic XSS protection"
      ],
      additional_context: %{
        jquery_specific_notes: [
          "jQuery does NOT automatically escape HTML in .html() method",
          "Even .html() with .text() can be vulnerable if chained incorrectly",
          "jQuery's $(userInput) can also lead to XSS if userInput contains HTML",
          "Older jQuery versions have additional vulnerabilities",
          "Many jQuery plugins use .html() internally without sanitization"
        ],
        common_mistakes: [
          "Assuming jQuery provides automatic XSS protection",
          "Using .html() when .text() would suffice",
          "Trusting data from internal APIs without sanitization",
          "Forgetting that .html() executes scripts in all contexts",
          "Not sanitizing data that goes through multiple transformations",
          "Using outdated jQuery versions with known vulnerabilities"
        ],
        migration_guidance: [
          "Audit all .html() calls in the codebase",
          "Replace with .text() where HTML rendering isn't needed",
          "Implement centralized sanitization functions",
          "Update to latest jQuery version for security patches",
          "Consider CSP headers as defense in depth",
          "Plan migration to modern frameworks with built-in protections"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing jQuery usage.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for jQuery usage
      content != nil ->
        String.contains?(content, "$") || 
        String.contains?(content, "jQuery") ||
        String.contains?(content, ".html(")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual XSS vulnerabilities
  and safe jQuery html() usage with proper sanitization or static content.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.ast_enhancement()
      iex> "$" in enhancement.ast_rules.callee_patterns
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.XssJqueryHtml.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_patterns: [
          "$",            # jQuery shorthand
          "jQuery",       # jQuery full name
          "window.$",     # Global jQuery
          "window.jQuery" # Global jQuery full
        ],
        method_chain: %{
          includes: "html",
          argument_check: %{
            position: 0,
            contains_user_input: true,
            user_input_patterns: [
              "req.", "request.", "params.", "query.",
              "body.", "user", "input", "data", "payload",
              "form.", "args.", "ctx.", "event.target.value"
            ]
          }
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/fixtures/,
          ~r/mocks/,
          ~r/examples/,
          ~r/docs/,
          ~r/vendor/,
          ~r/node_modules/
        ],
        safe_patterns: [
          "DOMPurify.sanitize",
          "escapeHtml",
          "sanitizeHTML",
          "purify",
          "xss.clean",
          "validator.escape",
          "he.encode",
          "_.escape",
          "encode_html",
          "htmlspecialchars"
        ],
        safe_assignments: [
          "SAFE_",          # SAFE_TEMPLATE, SAFE_HTML, etc.
          "STATIC_",        # STATIC_CONTENT, STATIC_HTML
          "TEMPLATE_",      # TEMPLATE_HEADER, etc.
          "CONST_"          # CONST_MESSAGE, etc.
        ],
        jquery_safe_methods: [
          "text",           # Safe text method
          "val",            # Form value (not HTML)
          "prop",           # Properties
          "attr",           # Attributes
          "data"            # Data attributes
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "user_input" => 0.4,              # Direct user input
          "concatenation" => 0.3,           # String concatenation
          "template_literal" => 0.3,        # Template literals with variables
          "request_data" => 0.4,            # Request data usage
          "no_sanitization" => 0.3,         # No sanitization detected
          "sanitized" => -0.8,              # Sanitization function used
          "static_content" => -0.7,         # Hardcoded HTML
          "safe_method_nearby" => -0.4,    # .text() used nearby
          "test_code" => -0.6,              # Test files
          "escaped_variable" => -0.5,       # Escaped variables
          "content_type_check" => -0.3,    # Content-type validation
          "csp_protected" => -0.4,          # CSP headers present
          "modern_framework" => -0.3        # React/Vue/Angular present
        }
      },
      min_confidence: 0.7
    }
  end
end