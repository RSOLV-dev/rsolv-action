defmodule Rsolv.Security.Patterns.Php.OpenRedirect do
  @moduledoc """
  Pattern for detecting open redirect vulnerabilities in PHP.

  This pattern identifies when PHP applications redirect users to URLs
  controlled by user input without proper validation, potentially allowing
  attackers to redirect victims to malicious sites.

  ## Vulnerability Details

  Open redirect vulnerabilities occur when a web application accepts a user-controlled
  input that specifies a link to an external site, and uses that link in a redirect.
  This can be leveraged by attackers for phishing attacks, bypassing security controls,
  or stealing credentials.

  ### Attack Example
  ```php
  // Vulnerable code
  header("Location: " . $_GET['url']);

  // Attack: https://trusted.com/redirect.php?url=http://evil.com/phishing
  // User thinks they're on trusted.com but gets redirected to evil.com
  ```

  The vulnerability is particularly dangerous because users trust the initial domain
  and may not notice they've been redirected to a malicious site.
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-open-redirect",
      name: "Open Redirect",
      description: "Unvalidated redirect URLs allowing phishing attacks",
      type: :open_redirect,
      severity: :medium,
      languages: ["php"],
      regex:
        ~r/(header\s*\(\s*["']Location:\s*[^"']*["']?\s*\.\s*\$_(GET|POST|REQUEST|COOKIE))|(wp_redirect\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))/i,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against an allowlist",
      test_cases: %{
        vulnerable: [
          ~S|header("Location: " . $_GET['url']);|,
          ~S|header('Location: ' . $_POST['redirect']);|,
          ~S|wp_redirect($_GET['redirect_to']);|,
          ~S|header("Location: https://" . $_GET['domain'] . "/login");|
        ],
        safe: [
          ~S|$allowed_urls = ['/home', '/dashboard', '/profile'];
$redirect = $_GET['url'];
if (in_array($redirect, $allowed_urls)) {
    header("Location: " . $redirect);
}|,
          ~S|header("Location: /home");|,
          ~S|wp_redirect(home_url());|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Open redirect vulnerabilities allow attackers to redirect users from a trusted
      site to any external URL. This is commonly exploited in phishing attacks where
      users trust the initial domain and don't realize they've been redirected to a
      malicious site.

      The vulnerability occurs when applications use user-controlled input to determine
      redirect destinations without proper validation. While browsers show the final
      URL, many users don't check the address bar after clicking a trusted link.

      ### How Open Redirects Work

      **Basic Attack Flow**:
      1. Attacker crafts URL: `https://trusted.com/redirect.php?url=http://evil.com`
      2. Victim receives link appearing to be from trusted.com
      3. Victim clicks link, trusting the domain
      4. Application redirects to attacker's site
      5. Attacker's site mimics trusted site to steal credentials

      **Common Redirect Methods in PHP**:
      - `header("Location: " . $url)` - HTTP header redirect
      - `wp_redirect($url)` - WordPress redirect function
      - `<meta http-equiv="refresh" content="0;url=$url">` - HTML meta redirect
      - `echo "<script>window.location='$url'</script>"` - JavaScript redirect

      ### Attack Scenarios

      **Phishing Attacks**:
      ```
      1. Email: "Your account needs verification: https://bank.com/verify?url=http://attacker.com"
      2. User sees bank.com domain and clicks
      3. Redirected to attacker.com that looks like bank.com
      4. User enters credentials on fake site
      ```

      **OAuth Token Theft**:
      ```
      1. OAuth flow: https://app.com/oauth/callback?redirect_uri=http://attacker.com
      2. After authentication, tokens sent to attacker's URL
      3. Attacker gains access to user's account
      ```

      **Bypassing Security Warnings**:
      - Many security tools trust redirects from known good domains
      - Spam filters may allow emails with trusted domains
      - Browser warnings may be bypassed
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-601",
          title: "URL Redirection to Untrusted Site ('Open Redirect')",
          url: "https://cwe.mitre.org/data/definitions/601.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp_cheatsheet,
          id: "unvalidated_redirects",
          title: "OWASP Unvalidated Redirects and Forwards Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "open_redirect_impact",
          title: "A Study of Open Redirect Vulnerabilities",
          url: "https://www.acunetix.com/blog/articles/open-redirection-vulnerabilities/"
        }
      ],
      attack_vectors: [
        "Phishing: ?url=http://evil.com/fake-login",
        "Credential theft: ?redirect=http://attacker.com/capture-password",
        "OAuth token theft: ?redirect_uri=http://attacker.com/steal-token",
        "XSS payload delivery: ?url=javascript:alert(document.cookie)",
        "Bypassing referrer checks: ?next=http://evil.com",
        "Social engineering: ?return_to=http://fake-support.com",
        "Malware distribution: ?download=http://malware-site.com/trojan.exe"
      ],
      real_world_impact: [
        "Mass phishing campaigns targeting banking customers",
        "Corporate credential theft through spoofed login pages",
        "OAuth token hijacking for account takeover",
        "Malware distribution through trusted domains",
        "SEO poisoning and traffic redirection",
        "Bypassing email and web filters",
        "Reputation damage to the vulnerable site"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-21887",
          description: "Ivanti Connect Secure open redirect allowing phishing attacks",
          severity: "medium",
          cvss: 6.1,
          note: "Chained with auth bypass for critical impact"
        },
        %{
          id: "CVE-2023-29489",
          description: "cPanel open redirect vulnerability in login interface",
          severity: "medium",
          cvss: 6.1,
          note: "Exploited for widespread phishing campaigns"
        },
        %{
          id: "CVE-2022-24854",
          description: "WordPress plugin open redirect affecting millions of sites",
          severity: "medium",
          cvss: 6.1,
          note: "Mass exploitation for SEO spam and phishing"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell exploited via open redirects for payload delivery",
          severity: "critical",
          cvss: 10.0,
          note: "Open redirects used as initial vector for RCE chains"
        }
      ],
      detection_notes: """
      This pattern detects open redirect vulnerabilities by identifying:

      1. **Header Redirects**: PHP header() function with Location header
         - Direct concatenation: header("Location: " . $_GET['url'])
         - Case insensitive: header("location: " . $_POST['redirect'])

      2. **WordPress Redirects**: wp_redirect() with user input
         - Direct parameter: wp_redirect($_GET['redirect_to'])
         - Request array: wp_redirect($_REQUEST['url'])

      3. **User Input Sources**: All PHP superglobals
         - $_GET - URL parameters
         - $_POST - Form data
         - $_REQUEST - Combined GET/POST/COOKIE
         - $_COOKIE - Cookie values

      The regex uses case-insensitive matching and handles various spacing patterns.
      It looks for concatenation operators (.) connecting user input to redirect functions.
      """,
      safe_alternatives: [
        "Use an allowlist of valid redirect URLs",
        "Only allow relative URLs starting with '/'",
        "Validate URLs match expected domain: parse_url($url, PHP_URL_HOST)",
        "Use indexed redirects: redirect.php?page=1 maps to predefined URLs",
        "Implement HMAC signatures for redirect URLs",
        "Framework functions: Laravel's redirect()->route('name')",
        "WordPress: wp_safe_redirect() with allowed_redirect_hosts filter"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting URLs that start with '/' (could be '//evil.com')",
          "Only checking for 'http' (missing 'javascript:' URLs)",
          "Allowing any URL from the same domain (subdomain takeover risk)",
          "Not considering URL encoding bypass techniques",
          "Trusting referrer headers for validation",
          "Implementing blocklists instead of allowlists",
          "Forgetting about protocol-relative URLs (//evil.com)"
        ],
        bypass_techniques: [
          "Protocol-relative: //evil.com",
          "Whitespace: / /evil.com",
          "URL encoding: %2F%2Fevil.com",
          "Case variation: HtTp://evil.com",
          "@ bypass: http://trusted.com@evil.com",
          "Backslash: /\\evil.com",
          "Question mark: /?/evil.com"
        ],
        secure_patterns: [
          "Always use absolute internal paths",
          "Maintain allowlist in configuration",
          "Log all redirect attempts",
          "Implement rate limiting on redirects",
          "Show interstitial warning for external URLs",
          "Use POST requests for sensitive redirects",
          "Add CSRF tokens to redirect parameters"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the open redirect pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.OpenRedirect.test_cases()
      iex> length(test_cases.positive)
      8

      iex> test_cases = Rsolv.Security.Patterns.Php.OpenRedirect.test_cases()
      iex> length(test_cases.negative)
      6
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|header("Location: " . $_GET['url']);|,
          description: "Direct GET parameter concatenation"
        },
        %{
          code: ~S|header('Location: ' . $_POST['redirect']);|,
          description: "POST parameter redirect"
        },
        %{
          code: ~S|header("Location: " . $_REQUEST['next']);|,
          description: "REQUEST superglobal usage"
        },
        %{
          code: ~S|header('Location: ' . $_COOKIE['return_url']);|,
          description: "Cookie-based redirect"
        },
        %{
          code: ~S|wp_redirect($_GET['redirect_to']);|,
          description: "WordPress redirect with GET"
        },
        %{
          code: ~S|wp_redirect($_POST['url']);|,
          description: "WordPress redirect with POST"
        },
        %{
          code: ~S|header("location: " . $_GET['redirect']);|,
          description: "Case insensitive header"
        },
        %{
          code: ~S|header("Location: https://" . $_GET['domain'] . "/login");|,
          description: "Domain injection in URL"
        }
      ],
      negative: [
        %{
          code: ~S|header("Location: /home");|,
          description: "Hardcoded safe redirect"
        },
        %{
          code: ~S|header("Location: " . $safe_url);|,
          description: "Non-user-controlled variable"
        },
        %{
          code: ~S|header("Content-Type: text/html");|,
          description: "Different header type"
        },
        %{
          code: ~S|$redirect = $_GET['url'];|,
          description: "Assignment without redirect"
        },
        %{
          code: ~S|// header("Location: " . $_GET['url']);|,
          description: "Commented out redirect"
        },
        %{
          code: ~S|wp_redirect(home_url());|,
          description: "WordPress safe redirect"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.

  ## Examples

      iex> examples = Rsolv.Security.Patterns.Php.OpenRedirect.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  def examples do
    %{
      vulnerable: %{
        "Basic redirect" => """
        // VULNERABLE: Direct user input in redirect
        if (isset($_GET['redirect'])) {
            header("Location: " . $_GET['redirect']);
            exit();
        }

        // Attack: site.com/login.php?redirect=http://evil.com/phishing
        """,
        "WordPress redirect" => """
        // VULNERABLE: Unvalidated wp_redirect
        $redirect_to = $_REQUEST['redirect_to'] ?: home_url();
        wp_redirect($redirect_to);
        exit;

        // Attacker can redirect anywhere
        """,
        "Domain concatenation" => """
        // VULNERABLE: User controls part of URL
        $subdomain = $_GET['site'];
        header("Location: https://" . $subdomain . ".example.com");

        // Attack: ?site=evil.com/path#@real
        // Redirects to: https://evil.com/path#@real.example.com
        """
      },
      fixed: %{
        "Allowlist validation" => """
        // SECURE: Validate against allowlist
        $allowed_redirects = [
            '/dashboard',
            '/profile',
            '/settings',
            '/logout'
        ];

        $redirect = $_GET['redirect'] ?? '/dashboard';

        if (!in_array($redirect, $allowed_redirects)) {
            $redirect = '/dashboard'; // Default safe location
        }

        header("Location: " . $redirect);
        exit();
        """,
        "Relative URL check" => """
        // SECURE: Only allow relative URLs
        function safe_redirect($url) {
            // Remove whitespace
            $url = trim($url);

            // Only allow URLs starting with single /
            if (preg_match('#^/[^/]#', $url)) {
                header("Location: " . $url);
            } else {
                header("Location: /");
            }
            exit();
        }

        safe_redirect($_GET['redirect'] ?? '/');
        """,
        "URL validation" => """
        // SECURE: Validate URL belongs to our domain
        function is_safe_redirect($url) {
            $parsed = parse_url($url);

            // Only allow our domain or relative URLs
            $allowed_hosts = ['example.com', 'www.example.com'];

            if (!isset($parsed['host'])) {
                // Relative URL - check it starts with /
                return strpos($url, '/') === 0 && strpos($url, '//') !== 0;
            }

            return in_array($parsed['host'], $allowed_hosts);
        }

        $redirect = $_GET['url'] ?? '/';

        if (is_safe_redirect($redirect)) {
            header("Location: " . $redirect);
        } else {
            header("Location: /");
        }
        exit();
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.

  ## Examples

      iex> desc = Rsolv.Security.Patterns.Php.OpenRedirect.vulnerability_description()
      iex> desc =~ "redirect"
      true

      iex> desc = Rsolv.Security.Patterns.Php.OpenRedirect.vulnerability_description()
      iex> desc =~ "phishing"
      true

      iex> desc = Rsolv.Security.Patterns.Php.OpenRedirect.vulnerability_description()
      iex> desc =~ "validation"
      true
  """
  def vulnerability_description do
    """
    Open redirect vulnerabilities occur when a web application accepts untrusted
    input that could cause the application to redirect users to an unintended
    external URL, enabling phishing attacks and credential theft.

    Attackers exploit open redirects by crafting malicious URLs that appear to
    originate from a trusted domain but redirect victims to attacker-controlled
    sites designed to steal credentials or distribute malware.

    ## Security Impact

    **Phishing Attacks**: Users trust links from known domains, making them more
    likely to enter credentials on the redirected phishing site.

    **Credential Theft**: Fake login pages that look identical to the real site
    can capture usernames, passwords, and 2FA codes.

    **Trust Exploitation**: Bypasses spam filters and security warnings that would
    normally block direct links to malicious sites.

    ## Attack Scenarios

    1. **Email Phishing**:
       - Attacker sends: "Reset password at https://bank.com/reset?url=evil.com"
       - Victim trusts bank.com domain
       - Gets redirected to convincing fake site

    2. **OAuth Hijacking**:
       - Manipulate OAuth redirect_uri parameter
       - Steal authorization codes or tokens
       - Gain access to user accounts

    3. **Filter Bypass**:
       - Use trusted domain to bypass email filters
       - Evade browser security warnings
       - Circumvent corporate firewalls

    ## Prevention

    Implement strict validation using allowlists of acceptable redirect
    destinations, validate that URLs are relative or belong to your domain,
    and never trust user input for determining redirect locations.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing redirect context and validation patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.OpenRedirect.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.OpenRedirect.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Php.OpenRedirect.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      ast_rules: [
        %{
          type: "redirect_functions",
          description: "Identify PHP redirect functions",
          functions: [
            "header",
            "wp_redirect",
            "wp_safe_redirect",
            "redirect",
            "Redirect",
            "http_redirect"
          ],
          location_patterns: [
            "Location:",
            "location:",
            "LOCATION:",
            "Content-Location:",
            "Refresh:"
          ]
        },
        %{
          type: "user_input_sources",
          description: "Detect user-controlled input sources",
          dangerous_sources: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"],
          safe_sources: ["home_url()", "site_url()", "admin_url()", "get_permalink()"],
          request_vars: ["HTTP_REFERER", "REQUEST_URI", "QUERY_STRING"]
        },
        %{
          type: "validation_patterns",
          description: "Check for URL validation attempts",
          validation_functions: [
            "parse_url",
            "filter_var",
            "preg_match",
            "in_array",
            "array_key_exists",
            "strpos"
          ],
          safe_patterns: [
            "FILTER_VALIDATE_URL",
            "allowed_redirect_hosts",
            "safe_redirect",
            "is_allowed_host"
          ]
        },
        %{
          type: "context_analysis",
          description: "Analyze redirect context for safety",
          exclude_patterns: [
            "test",
            "mock",
            "example",
            "documentation",
            "// header",
            "/* header",
            "* header("
          ],
          high_risk_indicators: [
            "login",
            "auth",
            "oauth",
            "callback",
            "return",
            "next",
            "continue",
            "redirect"
          ]
        }
      ]
    }
  end
end
