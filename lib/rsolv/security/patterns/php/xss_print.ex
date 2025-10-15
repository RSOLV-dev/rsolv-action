defmodule Rsolv.Security.Patterns.Php.XssPrint do
  @moduledoc """
  Pattern for detecting Cross-Site Scripting (XSS) vulnerabilities via print in PHP.

  This pattern identifies when user input from PHP superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE)
  is directly printed without proper escaping. Like echo, print is a common output method
  that can lead to XSS vulnerabilities.

  ## Vulnerability Details

  The `print` statement in PHP outputs data directly to the browser. Unlike `echo`, `print`
  always returns 1, making it slightly different, but equally vulnerable to XSS when used
  with unescaped user input.

  ### Attack Example
  ```php
  // Vulnerable code
  print $_GET['message'];

  // Attack: ?message=<script>alert('XSS')</script>
  // Result: Browser executes the JavaScript
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-xss-print",
      name: "XSS via print",
      description:
        "Cross-site scripting (XSS) through direct printing of user input without escaping",
      type: :xss,
      severity: :high,
      languages: ["php"],
      regex:
        ~r/print\s*\(?(?!htmlspecialchars)(?!.*htmlspecialchars\s*\().*\$_(GET|POST|REQUEST|COOKIE)/,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use htmlspecialchars() before printing user input",
      test_cases: %{
        vulnerable: [
          ~S|print $_POST['comment'];|,
          ~S|print "Hello " . $_GET['user'];|,
          ~S|print($_GET['message']);|
        ],
        safe: [
          ~S|print htmlspecialchars($_POST['comment'], ENT_QUOTES);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) via the print statement is functionally identical to
      XSS via echo. The print statement outputs data directly to the browser without
      any encoding, creating a direct path for malicious script injection.

      This vulnerability represents a classic cross-site scripting attack vector
      where user input is reflected in the page without proper sanitization.

      Key differences between print and echo:
      - print always returns 1, echo has no return value
      - print can only take one argument
      - print can be used in expressions

      Despite these differences, both are equally vulnerable to XSS attacks when
      used with unescaped user input.
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
          id: "php_print_xss",
          title: "XSS Prevention in PHP Applications",
          url: "https://www.php.net/manual/en/security.magicquotes.php"
        }
      ],
      attack_vectors: [
        "Basic script injection: ?msg=<script>alert('XSS')</script>",
        "Event handler injection: ?msg=<img src=x onerror='alert(1)'>",
        "SVG injection: ?msg=<svg onload=alert('XSS')>",
        "Data URI injection: ?url=data:text/html,<script>alert('XSS')</script>",
        "HTML attribute breaking: ?class=\" onclick=\"alert('XSS')",
        "JavaScript URL: ?link=javascript:alert('XSS')"
      ],
      real_world_impact: [
        "Session hijacking through cookie theft",
        "Phishing attacks via injected forms",
        "Keylogging and credential theft",
        "Defacement of web pages",
        "Malware distribution",
        "Cryptocurrency mining in victim browsers"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-23210",
          description: "XSS vulnerability in PHP application via print statement",
          severity: "medium",
          cvss: 6.1,
          note: "Reflected XSS through unescaped print output"
        },
        %{
          id: "CVE-2024-56365",
          description: "Reflected XSS in PHPSpreadsheet via print",
          severity: "medium",
          cvss: 6.1,
          note: "XSS through improper output encoding"
        },
        %{
          id: "CVE-2022-23990",
          description: "XSS in PHP web application print statements",
          severity: "high",
          cvss: 7.2,
          note: "Multiple XSS vectors through print without encoding"
        }
      ],
      detection_notes: """
      This pattern detects XSS vulnerabilities by looking for:
      - Direct print statements with user input
      - Concatenation of user input in print statements
      - Variable interpolation with user input
      - Missing htmlspecialchars() function calls

      The pattern uses negative lookahead similar to the echo pattern.
      """,
      safe_alternatives: [
        "Always use htmlspecialchars() with ENT_QUOTES flag",
        "Create a safe print wrapper function",
        "Use template engines with auto-escaping",
        "Implement output encoding at the framework level",
        "Apply context-aware escaping",
        "Use Content Security Policy (CSP) headers"
      ],
      additional_context: %{
        common_mistakes: [
          "Forgetting ENT_QUOTES in htmlspecialchars()",
          "Escaping at input instead of output",
          "Not escaping in JavaScript contexts",
          "Trusting data from internal sources",
          "Using print in complex expressions without escaping"
        ],
        secure_patterns: [
          "HTML: print htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
          "Wrapper: function safe_print($str) { print htmlspecialchars($str, ENT_QUOTES, 'UTF-8'); }",
          "JavaScript: print json_encode($data)",
          "URL: print urlencode($url_param)"
        ],
        php_specific_notes: [
          "print returns 1, can be used in expressions",
          "print takes only one argument unlike echo",
          "print is marginally slower than echo",
          "Both print and echo need proper escaping",
          "print() with parentheses works but isn't a function"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.XssPrint.test_cases()
      iex> length(test_cases.positive) > 0
      true

      iex> test_cases = Rsolv.Security.Patterns.Php.XssPrint.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|print $_GET['message'];|,
          description: "Direct print of GET parameter"
        },
        %{
          code: ~S|print "Hello " . $_POST['name'];|,
          description: "Concatenation with POST parameter"
        },
        %{
          code: ~S|print "<div>$_REQUEST[content]</div>";|,
          description: "Interpolation in HTML context"
        },
        %{
          code: ~S|print($_COOKIE['data']);|,
          description: "Print with parentheses"
        },
        %{
          code: ~S|print $_GET['x'] . " - " . $_GET['y'];|,
          description: "Multiple user inputs"
        }
      ],
      negative: [
        %{
          code: ~S|print htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');|,
          description: "Properly escaped with all flags"
        },
        %{
          code: ~S|print "Hello World";|,
          description: "Static string without user input"
        },
        %{
          code: ~S|print htmlspecialchars($_POST['data'], ENT_QUOTES);|,
          description: "Escaped with ENT_QUOTES"
        },
        %{
          code: ~S|print $safe_variable;|,
          description: "Print of non-user variable"
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
        // Status message - VULNERABLE
        <div class="status">
            <?php print $_GET['status']; ?>
        </div>

        // Attack: ?status=<script>alert(document.cookie)</script>
        // Result: JavaScript executes and can steal cookies
        """,
        "XSS in error messages" => ~S"""
        // Error display - VULNERABLE
        if ($error) {
            print "Error: " . $_POST['error_msg'];
        }

        // Attack: Inject scripts through error messages
        """,
        "Print in expressions" => ~S"""
        // Using print's return value - VULNERABLE
        $result = print $_GET['data'];  // $result will be 1

        // Still vulnerable to XSS despite being in expression
        """
      },
      fixed: %{
        "Using htmlspecialchars()" => ~S"""
        // Status message - SECURE
        <div class="status">
            <?php print htmlspecialchars($_GET['status'], ENT_QUOTES, 'UTF-8'); ?>
        </div>

        // All HTML characters are properly escaped
        """,
        "Safe print wrapper" => ~S"""
        // Create a safe print function
        function safe_print($data) {
            print htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        }

        // Usage
        safe_print($_GET['message']);
        safe_print($_POST['comment']);

        // Ensures consistent escaping throughout application
        """,
        "Context-aware output" => ~S"""
        // Different contexts need different escaping

        // HTML context
        print htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');

        // JavaScript context
        print "<script>var data = " . json_encode($userInput) . ";</script>";

        // HTML attribute
        print '<div title="' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '">';

        // URL context
        print '<a href="?page=' . urlencode($page) . '">Link</a>';
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Cross-Site Scripting (XSS) through the print statement is a common vulnerability
    in PHP applications. Like echo, print outputs data directly to the browser,
    making it a vector for cross-site scripting attacks when used with unescaped user input.

    ## Print vs Echo

    While functionally similar for XSS purposes, print has some differences:

    ```php
    // print always returns 1
    $x = print "Hello";  // $x is 1

    // print takes only one argument
    print "Hello " . $_GET['name'];  // Must concatenate

    // echo takes multiple arguments
    echo "Hello ", $_GET['name'];  // Can use commas
    ```

    ## XSS Impact

    Both print and echo are equally vulnerable to XSS:
    - Session hijacking
    - Credential theft
    - Malware distribution
    - Phishing attacks
    - Website defacement

    ## Real-World Scenarios

    Common vulnerable patterns:

    1. **Status Messages**
    ```php
    print "Status: " . $_GET['status'];
    ```

    2. **Error Displays**
    ```php
    if ($error) print $_POST['error'];
    ```

    3. **User Profiles**
    ```php
    print "<h1>Welcome $_GET[username]</h1>";
    ```

    ## Prevention

    The same escaping rules apply to print as to echo:

    ```php
    // Always escape with htmlspecialchars
    print htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    ```

    ## Best Practices

    1. **Escape at Output** - Never trust any data when outputting
    2. **Use ENT_QUOTES** - Escapes both single and double quotes
    3. **Specify Encoding** - Use UTF-8 to prevent encoding attacks
    4. **Template Engines** - Use auto-escaping template systems
    5. **CSP Headers** - Implement Content Security Policy

    ## Framework Solutions

    Modern PHP frameworks provide built-in protection:
    - Laravel: `{{ $variable }}` auto-escapes
    - Symfony: Twig auto-escapes by default
    - WordPress: `esc_html()` function

    Remember: print may seem different from echo, but both require
    the same careful attention to output encoding for security.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.XssPrint.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.XssPrint.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Php.XssPrint.ast_enhancement()
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
            "print",
            "printf",
            "vprintf",
            # When second param is false
            "print_r"
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
            # WordPress
            "esc_attr",
            # Common helper function
            "h"
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
            # When second param is true
            "var_export",
            # Date formatting
            "date",
            # Number formatting
            "number_format"
          ]
        }
      ],
      min_confidence: 0.7
    }
  end
end
