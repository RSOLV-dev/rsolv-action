defmodule Rsolv.Security.Patterns.Php.XssEcho do
  @moduledoc """
  Pattern for detecting Cross-Site Scripting (XSS) vulnerabilities via echo in PHP.

  This pattern identifies when user input from PHP superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE)
  is directly echoed without proper escaping. This is one of the most common XSS vulnerabilities
  in PHP applications.

  ## Vulnerability Details

  XSS occurs when user-controlled input is output to HTML without proper encoding. In PHP,
  the `echo` statement is frequently used to output dynamic content, making it a common
  source of XSS vulnerabilities when used with unescaped user input.

  ### Attack Example
  ```php
  // Vulnerable code
  echo $_GET['name'];

  // Attack: ?name=<script>alert('XSS')</script>
  // Result: Browser executes the JavaScript
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-xss-echo",
      name: "XSS via echo",
      description: "Direct output of user input without escaping",
      type: :xss,
      severity: :high,
      languages: ["php"],
      regex:
        ~r/echo\s+(?!htmlspecialchars)(?!.*htmlspecialchars\s*\().*\$_(GET|POST|REQUEST|COOKIE)/,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use htmlspecialchars() with ENT_QUOTES flag",
      test_cases: %{
        vulnerable: [
          ~S|echo $_GET['name'];|,
          ~S|echo "Welcome " . $_POST['username'];|
        ],
        safe: [
          ~S|echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');|,
          ~S|echo "Welcome " . htmlspecialchars($_POST['username'], ENT_QUOTES);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) is a web application vulnerability that allows attackers
      to inject malicious scripts into web pages viewed by other users. In PHP, the echo
      statement is a primary output method, and when used with unescaped user input, it
      creates a direct path for XSS attacks.

      The impact of XSS vulnerabilities includes:
      - Session hijacking and cookie theft
      - Defacement of websites
      - Phishing attacks
      - Keylogging and form hijacking
      - Cryptocurrency mining
      - Drive-by malware downloads

      PHP's echo statement outputs data directly to the browser, making proper escaping
      critical for security.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-79",
          title:
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
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
          id: "php_xss_prevention",
          title: "Cross-site scripting in PHP Web Applications",
          url: "https://www.brightsec.com/blog/cross-site-scripting-php/"
        },
        %{
          type: :research,
          id: "owasp_xss_prevention",
          title: "OWASP XSS Prevention Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Basic script injection: ?name=<script>alert('XSS')</script>",
        "Event handler injection: ?name=<img src=x onerror='alert(1)'>",
        "Data URI injection: ?url=javascript:alert('XSS')",
        "SVG injection: ?input=<svg onload=alert('XSS')>",
        "HTML attribute breaking: ?id=\" onmouseover=\"alert('XSS')",
        "Encoded payloads: ?data=%3Cscript%3Ealert('XSS')%3C/script%3E"
      ],
      real_world_impact: [
        "Steal authentication cookies and hijack user sessions",
        "Capture keystrokes and form data including passwords",
        "Redirect users to phishing sites",
        "Inject cryptocurrency miners into victim browsers",
        "Deface websites and damage brand reputation",
        "Perform actions on behalf of the victim user"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-23027",
          description: "XSS in phpMyAdmin through Insert tab due to improper sanitization",
          severity: "medium",
          cvss: 6.1,
          note: "Reflected XSS allowing script injection through user input"
        },
        %{
          id: "CVE-2023-5917",
          description: "XSS vulnerability in phpBB forum software",
          severity: "low",
          cvss: 2.4,
          note: "Stored XSS through forum post content"
        },
        %{
          id: "CVE-2020-7776",
          description: "XSS in PHPOffice/PhpSpreadsheet library",
          severity: "medium",
          cvss: 5.4,
          note: "XSS via specially crafted spreadsheet files"
        },
        %{
          id: "CVE-2024-9632",
          description: "Multiple XSS vulnerabilities in PHP web applications",
          severity: "high",
          cvss: 7.2,
          note: "Reflected XSS through multiple input vectors"
        }
      ],
      detection_notes: """
      This pattern detects XSS vulnerabilities by looking for:
      - Direct echo statements with user input
      - Concatenation of user input in echo statements
      - Variable interpolation with user input
      - Missing htmlspecialchars() function calls

      The pattern uses negative lookahead to exclude properly escaped output.
      """,
      safe_alternatives: [
        "Always use htmlspecialchars() with ENT_QUOTES flag",
        "Consider using ENT_HTML5 for HTML5 documents",
        "Use UTF-8 encoding parameter for proper character handling",
        "Implement Content Security Policy (CSP) headers",
        "Use template engines with auto-escaping (Twig, Smarty)",
        "Apply context-aware escaping for different output contexts",
        "Validate and sanitize input server-side"
      ],
      additional_context: %{
        common_mistakes: [
          "Using htmlspecialchars() without ENT_QUOTES (doesn't escape single quotes)",
          "Escaping at input time instead of output time",
          "Forgetting to escape in HTML attributes",
          "Not escaping in JavaScript contexts",
          "Trusting data from databases or APIs as 'safe'"
        ],
        secure_patterns: [
          "HTML context: echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
          "HTML attribute: <div id=\"<?= htmlspecialchars($id, ENT_QUOTES) ?>\">",
          "JavaScript context: var data = <?= json_encode($data) ?>;",
          "URL context: <a href=\"<?= htmlspecialchars($url, ENT_QUOTES) ?>\">",
          "CSS context: Use validated values only, never user input"
        ],
        php_specific_notes: [
          "htmlspecialchars() default doesn't escape single quotes",
          "ENT_QUOTES is essential for attribute context",
          "UTF-8 encoding parameter prevents encoding bypasses",
          "Short echo tags (<?=) still need escaping",
          "Template engines like Twig auto-escape by default"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.XssEcho.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = Rsolv.Security.Patterns.Php.XssEcho.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|echo $_GET['name'];|,
          description: "Direct echo of GET parameter"
        },
        %{
          code: ~S|echo "Welcome " . $_POST['user'];|,
          description: "Concatenation with POST parameter"
        },
        %{
          code: ~S|echo "<div>$_REQUEST[content]</div>";|,
          description: "Interpolation in HTML context"
        },
        %{
          code: ~S|echo trim($_COOKIE['data']);|,
          description: "Echo with function wrapping"
        },
        %{
          code: ~S|echo $_GET['id'] . " - " . $_GET['name'];|,
          description: "Multiple user inputs"
        },
        %{
          code: ~S|echo "<h1>{$_POST['title']}</h1>";|,
          description: "Complex interpolation syntax"
        }
      ],
      negative: [
        %{
          code: ~S|echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');|,
          description: "Properly escaped with all flags"
        },
        %{
          code: ~S|echo "Hello World";|,
          description: "Static string without user input"
        },
        %{
          code: ~S|echo htmlspecialchars($_POST['comment'], ENT_QUOTES);|,
          description: "Escaped with ENT_QUOTES"
        },
        %{
          code: ~S|echo $safe_variable;|,
          description: "Echo of non-user variable"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Basic reflected XSS" => ~S"""
        // User profile page - VULNERABLE
        <h1>Welcome <?php echo $_GET['username']; ?>!</h1>

        // Attack: ?username=<script>alert(document.cookie)</script>
        // Result: JavaScript executes and can steal cookies
        """,
        "XSS in HTML attributes" => ~S"""
        // Search form - VULNERABLE
        <input type="text" value="<?php echo $_GET['q']; ?>" />

        // Attack: ?q=" onmouseover="alert('XSS')
        // Result: Breaks out of attribute and injects event handler
        """,
        "Multiple injection points" => ~S"""
        // Comment display - VULNERABLE
        <div class="comment">
            <h3><?php echo $_POST['name']; ?></h3>
            <p><?php echo $_POST['comment']; ?></p>
            <span>Posted on <?php echo $_POST['date']; ?></span>
        </div>

        // Multiple XSS vectors in one form
        """
      },
      fixed: %{
        "Using htmlspecialchars()" => ~S"""
        // User profile page - SECURE
        <h1>Welcome <?php echo htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8'); ?>!</h1>

        // Escapes all special HTML characters including quotes
        """,
        "Context-aware escaping" => ~S"""
        // Different contexts require different escaping

        // HTML context
        <p><?php echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8'); ?></p>

        // HTML attribute context
        <div id="<?php echo htmlspecialchars($id, ENT_QUOTES, 'UTF-8'); ?>">

        // JavaScript context
        <script>
        var userData = <?php echo json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP); ?>;
        </script>

        // URL context
        <a href="<?php echo htmlspecialchars($url, ENT_QUOTES, 'UTF-8'); ?>">Link</a>
        """,
        "Using template engine" => ~S"""
        // Using Twig template engine - SECURE
        // Auto-escapes by default

        <h1>Welcome {{ username }}!</h1>
        <p>{{ comment }}</p>

        // Or with PHP template function
        function h($str) {
            return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
        }

        <h1>Welcome <?= h($_GET['username']) ?>!</h1>
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Cross-Site Scripting (XSS) is one of the most prevalent web application vulnerabilities,
    particularly in PHP applications. XSS occurs when an attacker can inject malicious
    scripts into web pages that are viewed by other users, enabling cross-site scripting
    attacks. The echo statement in PHP is a primary vector for XSS when used with 
    unescaped user input.

    ## Why It's Dangerous

    XSS vulnerabilities allow attackers to:
    - Execute arbitrary JavaScript in victims' browsers
    - Steal session cookies and authentication tokens
    - Perform actions on behalf of the user
    - Redirect users to malicious websites
    - Deface websites
    - Install keyloggers

    ## PHP Echo and XSS

    The `echo` statement outputs data directly to the browser without any encoding:

    ```php
    echo $_GET['input'];  // Direct XSS vulnerability
    ```

    ## Types of XSS

    1. **Reflected XSS** - Malicious script comes from current HTTP request
    2. **Stored XSS** - Malicious script is stored on server (database, files)
    3. **DOM-based XSS** - Vulnerability exists in client-side code

    ## Real-World Impact

    - **Session Hijacking**: Steal cookies to impersonate users
    - **Phishing**: Create fake login forms to steal credentials
    - **Malware Distribution**: Redirect to exploit kits
    - **Data Theft**: Access sensitive information
    - **Defacement**: Damage brand reputation

    ## Prevention with htmlspecialchars()

    The `htmlspecialchars()` function is PHP's primary defense:

    ```php
    // Basic usage (incomplete protection)
    echo htmlspecialchars($input);

    // Recommended usage (complete protection)
    echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    ```

    ### Why ENT_QUOTES is Critical

    Without ENT_QUOTES, single quotes are not escaped:
    - `<` becomes `&lt;`
    - `>` becomes `&gt;`
    - `"` becomes `&quot;`
    - `'` remains `'` (DANGEROUS in attributes!)

    ## Context-Aware Escaping

    Different output contexts require different escaping:

    1. **HTML Context**: `htmlspecialchars()`
    2. **JavaScript Context**: `json_encode()`
    3. **URL Context**: `urlencode()` or `rawurlencode()`
    4. **CSS Context**: Validate against whitelist only

    ## Defense in Depth

    1. **Input Validation** - Validate all input server-side
    2. **Output Encoding** - Always encode when outputting
    3. **Content Security Policy** - Add CSP headers
    4. **HTTPOnly Cookies** - Prevent JavaScript access
    5. **Template Engines** - Use auto-escaping templates
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.XssEcho.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Php.XssEcho.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Php.XssEcho.ast_enhancement()
      iex> length(enhancement.ast_rules)
      3
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "output_context",
          description: "Verify output context for XSS",
          functions: [
            "echo",
            "print",
            "printf",
            "<?=",
            "die",
            "exit"
          ]
        },
        %{
          type: "input_sanitization",
          description: "Check for proper escaping functions",
          safe_functions: [
            "htmlspecialchars",
            "htmlentities",
            "strip_tags",
            "filter_var",
            # WordPress
            "esc_html",
            # Laravel
            "e"
          ],
          note: "htmlspecialchars with ENT_QUOTES is preferred"
        },
        %{
          type: "safe_patterns",
          description: "Patterns that indicate safe usage",
          patterns: [
            # JSON context
            "json_encode",
            # Integer casting
            "intval",
            # Float casting
            "floatval",
            # Type casting
            "(int)",
            # Number formatting
            "number_format",
            # Date formatting
            "date"
          ]
        }
      ],
      min_confidence: 0.7
    }
  end
end
