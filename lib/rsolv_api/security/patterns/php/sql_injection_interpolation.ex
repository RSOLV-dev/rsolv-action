defmodule RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation do
  @moduledoc """
  Pattern for detecting SQL injection via variable interpolation in PHP.
  
  This pattern identifies when PHP variables ($_GET, $_POST, $_REQUEST, $_COOKIE) are 
  directly interpolated into SQL query strings using double quotes. PHP's variable 
  interpolation feature makes it trivial to accidentally create SQL injection vulnerabilities.
  
  ## Vulnerability Details
  
  When using double quotes in PHP, variables are automatically interpolated:
  ```php
  $query = "SELECT * FROM users WHERE name = '$_GET[name]'";
  // If $_GET['name'] = "admin' OR '1'='1", the query becomes:
  // SELECT * FROM users WHERE name = 'admin' OR '1'='1'
  ```
  
  This is equally dangerous as concatenation but even more subtle because developers
  might not realize that interpolation creates the same vulnerability.
  
  ### Attack Example
  ```php
  // Vulnerable code
  $id = $_GET['id'];
  $query = "SELECT * FROM users WHERE id = $id";
  
  // Attack: ?id=1 OR 1=1 UNION SELECT password FROM admins--
  // Results in: SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT password FROM admins--
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-sql-injection-interpolation",
      name: "SQL Injection via Variable Interpolation",
      description: "User input interpolated directly into SQL strings creates SQL injection vulnerabilities",
      type: :sql_injection,
      severity: :critical,
      languages: ["php"],
      regex: ~r/["'](?:SELECT|UPDATE|DELETE|INSERT).*\$_(GET|POST|REQUEST|COOKIE)\[/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use PDO or mysqli with prepared statements and parameter binding",
      test_cases: %{
        vulnerable: [
          ~S|$query = "SELECT * FROM users WHERE name = '$_GET[name]'";|,
          ~S|mysqli_query($conn, "UPDATE users SET email = '$_POST[email]' WHERE id = $id");|
        ],
        safe: [
          ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
$stmt->execute(['name' => $_GET['name']]);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection via variable interpolation exploits PHP's double-quoted string feature
      where variables are automatically expanded within the string. This creates the same
      vulnerability as concatenation but is often overlooked because it appears more natural
      and concise to PHP developers.
      
      The vulnerability occurs in several forms:
      - Simple interpolation: "WHERE id = $_GET[id]"
      - Quoted interpolation: "WHERE name = '$_POST[name]'"
      - Complex interpolation: "WHERE user = '{$_GET['user']}'"
      
      All forms are equally dangerous and can lead to:
      - Complete database compromise
      - Authentication bypass
      - Data exfiltration
      - Data manipulation or destruction
      - In some cases, remote code execution
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-89",
          title: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
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
          id: "php_interpolation_security",
          title: "PHP String Interpolation Security",
          url: "https://www.php.net/manual/en/language.types.string.php#language.types.string.parsing"
        },
        %{
          type: :research,
          id: "stackoverflow_interpolation",
          title: "PHP Variable Interpolation and SQL Injection",
          url: "https://stackoverflow.com/questions/71332933/what-is-the-use-of-curly-braces-in-php-mysql"
        }
      ],
      attack_vectors: [
        "Basic interpolation: ?name=admin' OR '1'='1",
        "Numeric field bypass: ?id=1 OR 1=1",
        "Union-based data extraction: ?id=1 UNION SELECT password FROM admins",
        "Boolean blind: ?name=admin' AND ASCII(SUBSTR(password,1,1))>64--",
        "Time-based blind: ?id=1 AND SLEEP(5)",
        "Complex syntax: ?user=admin'} OR '1'='1' --"
      ],
      real_world_impact: [
        "Authentication bypass through WHERE clause manipulation",
        "Complete database content extraction",
        "Privilege escalation to admin accounts",
        "Data modification without authorization",
        "Database server compromise through stacked queries",
        "Compliance violations and data breach notifications"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-21703",
          description: "Grafana 7.5.15/8.3.5 - SQL injection via variable interpolation in data source queries",
          severity: "critical",
          cvss: 9.8,
          note: "Variable interpolation in database queries allowed SQL injection"
        },
        %{
          id: "CVE-2021-44228",
          description: "Multiple PHP applications - Secondary SQL injections via Log4j string interpolation",
          severity: "critical",
          cvss: 10.0,
          note: "Log4j vulnerability led to SQL injection through PHP variable interpolation"
        },
        %{
          id: "CVE-2020-35572",
          description: "osCommerce 2.3.4.1 - SQL injection via interpolated product_id",
          severity: "high",
          cvss: 8.8,
          note: "Direct interpolation of GET parameter into product queries"
        },
        %{
          id: "CVE-2019-10067",
          description: "Dolibarr ERP/CRM 10.0.6 - Multiple SQL injections via interpolation",
          severity: "critical",
          cvss: 9.8,
          note: "User input interpolated into various database queries throughout the application"
        }
      ],
      detection_notes: """
      This pattern detects variable interpolation within SQL query strings by looking for:
      - SQL keywords within double-quoted strings
      - Direct use of PHP superglobal arrays ($_GET, $_POST, etc.)
      - Array notation without quotes around the key (common PHP shorthand)
      
      The pattern covers various interpolation syntaxes:
      - Simple: "$_GET[id]"
      - Quoted: "'$_POST[name]'"
      - Complex: "{$_GET['user']}"
      - Nested: "'{$_REQUEST['data']}'"
      """,
      safe_alternatives: [
        "Use PDO with named parameters: prepare('SELECT * FROM users WHERE id = :id')",
        "Use MySQLi with positional placeholders: prepare('SELECT * FROM users WHERE id = ?')",
        "Use query builders that handle parameterization automatically",
        "Never interpolate user input directly into SQL strings",
        "Use single quotes for SQL strings to prevent accidental interpolation"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking that quotes around interpolated variables provide protection",
          "Believing that integer casting like (int)$_GET['id'] is always safe",
          "Using addslashes() or escape functions instead of parameterization",
          "Mixing prepared statements with interpolation in the same query"
        ],
        secure_patterns: [
          "PDO: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id')",
          "PDO: $stmt->bindParam(':id', $_GET['id'], PDO::PARAM_INT)",
          "MySQLi: $stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?')",
          "MySQLi: $stmt->bind_param('i', $_GET['id'])"
        ],
        php_specific_notes: [
          "Double quotes allow variable interpolation, single quotes do not",
          "Complex syntax with {} allows array access and object properties",
          "Heredoc and nowdoc syntaxes also support interpolation (heredoc only)",
          "PHP 8.2+ deprecates ${} syntax but {} syntax remains"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$query = "SELECT * FROM users WHERE name = '$_GET[name]'";|,
          description: "Simple interpolation with quotes"
        },
        %{
          code: ~S|$sql = "SELECT * FROM products WHERE id = $_POST[id]";|,
          description: "Numeric field interpolation without quotes"
        },
        %{
          code: ~S|$query = "DELETE FROM comments WHERE user = '{$_GET['user']}'";|,
          description: "Complex syntax interpolation"
        },
        %{
          code: ~S|mysqli_query($conn, "UPDATE users SET status = '$_REQUEST[status]' WHERE id = $id");|,
          description: "Direct query execution with interpolation"
        },
        %{
          code: ~S|$result = $db->query("INSERT INTO logs VALUES ('$_COOKIE[session]', NOW())");|,
          description: "COOKIE interpolation in INSERT"
        }
      ],
      negative: [
        %{
          code: ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");|,
          description: "Prepared statement with placeholder"
        },
        %{
          code: ~S|$query = 'SELECT * FROM users WHERE role = "admin"';|,
          description: "Single quotes prevent interpolation"
        },
        %{
          code: ~S|$sql = "SELECT * FROM products WHERE category = 'electronics'";|,
          description: "Static query without user input"
        },
        %{
          code: ~S|$stmt->execute(['name' => $_GET['name']]);|,
          description: "Parameter binding in execute"
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
        "Basic authentication bypass" => ~S"""
        // Login check - VULNERABLE
        $username = $_POST['username'];
        $password = $_POST['password'];
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        $result = mysqli_query($conn, $query);
        
        // Attack: username = admin' -- 
        // Results in: SELECT * FROM users WHERE username = 'admin' -- ' AND password = ''
        """,
        "Numeric field injection" => ~S"""
        // Product lookup - VULNERABLE  
        $product_id = $_GET['id'];
        $sql = "SELECT * FROM products WHERE id = $product_id AND status = 'active'";
        $result = $db->query($sql);
        
        // Attack: ?id=1 OR 1=1
        // Results in: SELECT * FROM products WHERE id = 1 OR 1=1 AND status = 'active'
        // Returns all products regardless of status
        """,
        "Complex syntax vulnerability" => ~S"""
        // User search - VULNERABLE
        $search = $_GET['search'];
        $filter = $_GET['filter'];
        $query = "SELECT * FROM users WHERE name LIKE '%{$search}%' AND department = '{$filter}'";
        
        // Attack: ?search=admin%' OR '1'='1&filter=IT' OR '1'='1
        // Bypasses all search restrictions
        """
      },
      fixed: %{
        "PDO with named parameters" => ~S"""
        // Login check - SECURE
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $stmt->execute([
            ':username' => $username,
            ':password' => $password
        ]);
        $result = $stmt->fetch();
        
        // User input is properly parameterized, SQL injection is not possible
        """,
        "MySQLi with positional placeholders" => ~S"""
        // Product lookup - SECURE
        $product_id = $_GET['id'];
        
        $stmt = $mysqli->prepare("SELECT * FROM products WHERE id = ? AND status = 'active'");
        $stmt->bind_param("i", $product_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        // The 'i' parameter ensures the value is treated as an integer
        """,
        "Type-safe parameter binding" => ~S"""
        // User search - SECURE
        $search = $_GET['search'];
        $filter = $_GET['filter'];
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name LIKE :search AND department = :filter");
        $stmt->execute([
            ':search' => '%' . $search . '%',
            ':filter' => $filter
        ]);
        
        // LIKE wildcards are added safely outside the SQL query
        """
      }
    }
  end
  
  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    SQL injection via variable interpolation is a critical vulnerability that exploits
    PHP's convenient but dangerous string interpolation feature. When developers use
    double quotes for SQL queries, PHP automatically expands variables within the string.
    
    ## Why It's Dangerous
    
    Variable interpolation appears safer than concatenation to many developers because:
    - It looks cleaner and more readable
    - It's a native PHP feature used everywhere
    - The quotes around variables create a false sense of security
    - IDEs often syntax-highlight it as a single string
    
    However, it creates identical vulnerabilities to concatenation.
    
    ## PHP Interpolation Mechanics
    
    PHP supports several interpolation syntaxes in double quotes:
    
    1. **Simple syntax**: `"WHERE id = $_GET[id]"`
    2. **Complex syntax**: `"WHERE id = {$_GET['id']}"`
    3. **Variable variables**: `"WHERE id = ${$_GET['field']}"`
    4. **Object properties**: `"WHERE id = $obj->id"`
    
    All are vulnerable when user input is involved.
    
    ## Real-World CVE Examples
    
    - **CVE-2022-21703**: Grafana SQL injection via interpolated variables
    - **CVE-2020-35572**: osCommerce SQL injection in product queries
    - **CVE-2019-10067**: Dolibarr ERP multiple SQL injections
    - **CVE-2021-44228**: Secondary SQL injections via Log4j interpolation
    
    ## Attack Techniques
    
    Attackers exploit interpolation using:
    - **Quote breaking**: `admin' OR '1'='1`
    - **Comment injection**: `admin'--`
    - **Union attacks**: `1 UNION SELECT password FROM admins`
    - **Boolean blind**: `admin' AND 1=1--`
    - **Time delays**: `admin' AND SLEEP(5)--`
    
    ## Prevention
    
    The only reliable prevention is parameterized queries:
    - Use prepared statements with PDO or MySQLi
    - Never interpolate user input into SQL strings
    - Use single quotes for SQL strings to prevent accidental interpolation
    - Enable SQL query logging to detect injection attempts
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation.ast_enhancement()
      iex> enhancement.min_confidence
      0.9
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation.ast_enhancement()
      iex> length(enhancement.rules)
      3
  """
  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "interpolation_detection",
          description: "Verify PHP string interpolation context",
          string_types: [
            "double_quotes",
            "heredoc",
            "curly_braces",
            "complex_syntax"
          ],
          note: "PHP only interpolates in double quotes and heredoc, not single quotes"
        },
        %{
          type: "database_context",
          description: "Verify SQL query context",
          patterns: [
            "query",
            "sql",
            "stmt",
            "statement",
            "mysqli_query",
            "mysql_query",
            "$pdo->query",
            "$db->query",
            "$conn->query"
          ]
        },
        %{
          type: "input_escaping",
          description: "Check for escaping functions (insufficient but reduces severity)",
          escape_functions: [
            "mysqli_real_escape_string",
            "mysql_real_escape_string",
            "addslashes",
            "intval",
            "floatval"
          ],
          note: "Escaping is NOT sufficient protection - prepared statements required"
        }
      ],
      min_confidence: 0.9
    }
  end
end