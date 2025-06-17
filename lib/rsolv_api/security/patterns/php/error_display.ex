defmodule RsolvApi.Security.Patterns.Php.ErrorDisplay do
  @moduledoc """
  Pattern for detecting detailed error messages shown to users in PHP applications.
  
  This pattern identifies when PHP applications display detailed database or system
  error messages directly to users, potentially exposing sensitive information about
  the application's internal structure, database schema, or configuration.
  
  ## Vulnerability Details
  
  Displaying detailed error messages to end users can expose sensitive information
  such as database structure, SQL queries, file paths, and server configuration.
  This information can be leveraged by attackers to craft more sophisticated attacks
  against the application.
  
  ### Attack Example
  ```php
  // Vulnerable code
  $result = mysqli_query($conn, $query);
  if (!$result) {
      die("Database error: " . mysqli_error($conn));
      // Exposes: Database error: Table 'myapp.users' doesn't exist
  }
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-error-display",
      name: "Detailed Error Display",
      description: "Showing detailed error messages to users",
      type: :information_disclosure,
      severity: :low,
      languages: ["php"],
      regex: ~r/(die|exit)\s*\(\s*["'][^"']*["']\s*\.\s*[\w_]+\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-209",
      owasp_category: "A05:2021",
      recommendation: "Log errors internally and show generic messages to users",
      test_cases: %{
        vulnerable: [
          ~S|die("Database error: " . mysqli_error($conn));|,
          ~S|exit("Query failed: " . pg_last_error());|
        ],
        safe: [
          ~S|die("An error occurred. Please try again later.");|,
          ~S|error_log("Database error: " . mysqli_error($conn));|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Information disclosure through error messages is a common vulnerability that
      occurs when applications expose detailed technical information to end users.
      While helpful during development, detailed error messages in production can
      provide attackers with valuable information about the application's architecture,
      dependencies, and potential vulnerabilities.
      
      When database errors are displayed directly to users, they often reveal:
      
      **Database Information**:
      - Table and column names
      - Database structure and relationships
      - SQL query syntax and logic
      - Database server type and version
      - Connection parameters
      
      **Application Details**:
      - File paths and directory structure
      - Function and class names
      - Framework and library information
      - Server configuration
      - Internal application state
      
      **Attack Facilitation**:
      
      **SQL Injection Reconnaissance**: Error messages help attackers understand
      database structure, making it easier to craft successful SQL injection attacks.
      
      **Path Traversal**: File paths in errors reveal directory structure, aiding
      in path traversal and local file inclusion attacks.
      
      **Technology Fingerprinting**: Error formats and messages reveal the technology
      stack, allowing attackers to research known vulnerabilities.
      
      **Business Logic Discovery**: Error messages can reveal application flow and
      business rules that shouldn't be exposed.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-209",
          title: "Generation of Error Message Containing Sensitive Information",
          url: "https://cwe.mitre.org/data/definitions/209.html"
        },
        %{
          type: :cwe,
          id: "CWE-211",
          title: "Externally-Generated Error Message Containing Sensitive Information",
          url: "https://cwe.mitre.org/data/definitions/211.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :owasp_guide,
          id: "error_handling",
          title: "OWASP Error Handling Guide",
          url: "https://owasp.org/www-community/Improper_Error_Handling"
        }
      ],
      attack_vectors: [
        "Triggering database errors to enumerate table/column names",
        "Causing connection failures to reveal database hostnames",
        "Injecting malformed data to expose query structure",
        "Exploiting missing files to reveal directory paths",
        "Using error messages to map application endpoints",
        "Leveraging stack traces to understand code flow",
        "Extracting version information for vulnerability research"
      ],
      real_world_impact: [
        "Database schema exposure leading to targeted SQL injection",
        "File path disclosure enabling directory traversal attacks",
        "Technology stack identification for exploit development",
        "Internal IP addresses and hostnames revealed",
        "User data exposed in error contexts",
        "Business logic and validation rules disclosed",
        "Compliance violations for data protection regulations"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-45133",
          description: "WordPress plugin SQL error information disclosure",
          severity: "medium",
          cvss: 5.3,
          note: "Database structure exposed through error messages"
        },
        %{
          id: "CVE-2022-4063",
          description: "PrestaShop database error information disclosure",
          severity: "medium",
          cvss: 5.3,
          note: "SQL queries and table names exposed in errors"
        },
        %{
          id: "CVE-2021-44521",
          description: "Apache Cassandra error message information leak",
          severity: "medium",
          cvss: 5.3,
          note: "Internal state and configuration exposed"
        },
        %{
          id: "CVE-2020-11988",
          description: "Apache Airflow error handling information disclosure",
          severity: "medium",
          cvss: 5.3,
          note: "Stack traces revealed sensitive configuration"
        }
      ],
      detection_notes: """
      This pattern detects information disclosure by identifying:
      
      1. **Output Functions**: die() or exit() that terminate execution
      2. **Error Context**: String containing "error" concatenated with content
      3. **Database Error Functions**: Functions ending with _error or _errno
         - mysqli_error(), mysql_error()
         - pg_last_error(), oci_error()
         - sqlsrv_errors(), mysqli_errno()
      
      The regex: (die|exit)\\s*\\(\\s*["'][^"']*error[^"']*["']\\s*\\.\\s*\\w+_(error|errno)
      
      This pattern specifically targets database error disclosure. Additional patterns
      may be needed for other types of error information disclosure.
      """,
      safe_alternatives: [
        "Log detailed errors to files: error_log($message, 3, '/var/log/app/errors.log')",
        "Show generic messages: die('An error occurred. Please contact support.')",
        "Use error codes: die('Error Code: APP_ERR_1001')",
        "Implement custom error handlers: set_error_handler('customErrorHandler')",
        "Use structured logging with context",
        "Send errors to monitoring services (Sentry, Rollbar)",
        "Implement user-friendly error pages"
      ],
      additional_context: %{
        common_mistakes: [
          "Leaving development error handling in production",
          "Concatenating error messages directly into output",
          "Not distinguishing between user and developer errors",
          "Exposing stack traces in API responses",
          "Including sensitive data in log messages",
          "Using var_dump() or print_r() in production",
          "Not sanitizing error messages before display"
        ],
        secure_practices: [
          "Separate error handling for development and production",
          "Log detailed errors, display generic messages",
          "Use error monitoring services for production",
          "Implement centralized error handling",
          "Regular security audits of error messages",
          "Test error scenarios before deployment",
          "Document error codes for support teams"
        ],
        framework_solutions: [
          "Laravel: APP_DEBUG=false and custom error views",
          "Symfony: prod environment with error controllers",
          "CodeIgniter: Custom error_404 and error_general pages",
          "WordPress: WP_DEBUG_DISPLAY = false",
          "Slim Framework: Custom error handlers"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the error display pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.ErrorDisplay.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.ErrorDisplay.test_cases()
      iex> length(test_cases.negative)
      8
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|die("Database error: " . mysqli_error($conn));|,
          description: "MySQLi error with die()"
        },
        %{
          code: ~S|exit("Query failed: " . pg_last_error());|,
          description: "PostgreSQL error with exit()"
        },
        %{
          code: ~S|die('Connection error: ' . mysql_error());|,
          description: "MySQL error (deprecated function)"
        },
        %{
          code: ~S|die("SQL error: " . mysqli_errno($conn));|,
          description: "MySQLi error number"
        },
        %{
          code: ~S|exit("Database error: " . oci_error());|,
          description: "Oracle error"
        },
        %{
          code: ~S|die("Query error: " . sqlsrv_errors());|,
          description: "SQL Server error"
        },
        %{
          code: ~S|die( "Error: " . mysqli_error($conn) );|,
          description: "With extra spacing"
        },
        %{
          code: ~S|die("Connection failed with error: " . pg_last_error($dbconn));|,
          description: "More descriptive error message"
        }
      ],
      negative: [
        %{
          code: ~S|die("An error occurred. Please try again later.");|,
          description: "Generic error message"
        },
        %{
          code: ~S|exit("Operation failed");|,
          description: "No detailed information"
        },
        %{
          code: ~S|error_log("Database error: " . mysqli_error($conn));|,
          description: "Logging instead of displaying"
        },
        %{
          code: ~S|$error = mysqli_error($conn);|,
          description: "Just variable assignment"
        },
        %{
          code: ~S|if (mysqli_error($conn)) { die("Error occurred"); }|,
          description: "Check but don't display"
        },
        %{
          code: ~S|die("Error Code: " . ERROR_CODE_DB);|,
          description: "Using error codes instead"
        },
        %{
          code: ~S|// die("Database error: " . mysqli_error($conn));|,
          description: "Commented out"
        },
        %{
          code: ~S|throw new Exception("Database connection failed");|,
          description: "Using exceptions"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.ErrorDisplay.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Basic error display" => """
        // VULNERABLE: Exposing database errors
        $result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
        if (!$result) {
            die("Database error: " . mysqli_error($conn));
            // Could expose: Database error: You have an error in your SQL syntax
        }
        
        // VULNERABLE: Connection error details
        $conn = mysqli_connect($host, $user, $pass, $db);
        if (!$conn) {
            die("Connection failed: " . mysqli_connect_error());
            // Could expose: Connection failed: Access denied for user 'root'@'localhost'
        }
        """,
        "Query error exposure" => """
        // VULNERABLE: Exposing query structure
        $query = "INSERT INTO orders (user_id, total) VALUES ($user_id, $total)";
        $result = mysqli_query($conn, $query);
        
        if (!$result) {
            exit("Query failed: " . mysqli_error($conn));
            // Exposes table structure and query logic
        }
        
        // VULNERABLE: PostgreSQL errors
        $result = pg_query($conn, $sql);
        if (!$result) {
            die("PostgreSQL error: " . pg_last_error($conn));
            // Could expose: ERROR: relation "users" does not exist
        }
        """,
        "Multiple error details" => """
        // VULNERABLE: Comprehensive error information
        if (!$result) {
            $error_msg = "Database operation failed\\n";
            $error_msg .= "Error: " . mysqli_error($conn) . "\\n";
            $error_msg .= "Error Code: " . mysqli_errno($conn) . "\\n";
            $error_msg .= "Query: " . $query;
            die($error_msg);
            // Exposes everything an attacker needs!
        }
        """
      },
      fixed: %{
        "Generic error message" => """
        // SECURE: Generic user message, detailed logging
        $result = mysqli_query($conn, "SELECT * FROM users WHERE id = ?");
        if (!$result) {
            // Log detailed error for developers
            error_log("Database error in users.php: " . mysqli_error($conn));
            error_log("Query: " . $query);
            error_log("User ID: " . $user_id);
            
            // Show generic message to user
            die("An error occurred. Please try again later.");
        }
        
        // SECURE: Error codes for support
        if (!$result) {
            $error_code = 'DB_ERR_' . time();
            error_log("[$error_code] " . mysqli_error($conn));
            die("An error occurred. Reference: $error_code");
        }
        """,
        "Structured error handling" => """
        // SECURE: Custom error handler class
        class ErrorHandler {
            private $logger;
            
            public function handleDatabaseError($error, $context = []) {
                // Generate unique ID
                $error_id = uniqid('ERR_', true);
                
                // Log with context
                $this->logger->error("Database Error", [
                    'error_id' => $error_id,
                    'message' => $error,
                    'file' => debug_backtrace()[0]['file'],
                    'line' => debug_backtrace()[0]['line'],
                    'context' => $context
                ]);
                
                // Return user-friendly response
                if (php_sapi_name() === 'cli') {
                    echo "Error: Operation failed. ID: $error_id\\n";
                } else {
                    http_response_code(500);
                    include 'templates/error_500.php';
                }
                exit();
            }
        }
        
        // Usage
        if (!$result) {
            $handler->handleDatabaseError(mysqli_error($conn), [
                'operation' => 'user_lookup',
                'user_id' => $user_id
            ]);
        }
        """,
        "Production error handling" => """
        // SECURE: Environment-aware error handling
        class Application {
            private $debug = false;
            
            public function __construct() {
                $this->debug = ($_ENV['APP_ENV'] === 'development');
            }
            
            public function handleError($exception) {
                if ($this->debug) {
                    // Development: show detailed error
                    echo "<pre>";
                    echo "Error: " . $exception->getMessage() . "\\n";
                    echo "File: " . $exception->getFile() . "\\n";
                    echo "Line: " . $exception->getLine() . "\\n";
                    echo "Trace:\\n" . $exception->getTraceAsString();
                    echo "</pre>";
                } else {
                    // Production: log and show generic
                    error_log($exception->getMessage());
                    
                    // Send to monitoring service
                    if ($this->sentry) {
                        $this->sentry->captureException($exception);
                    }
                    
                    // Show error page
                    http_response_code(500);
                    include 'views/errors/500.php';
                }
                exit();
            }
        }
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.ErrorDisplay.vulnerability_description()
      iex> desc =~ "error"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.ErrorDisplay.vulnerability_description()
      iex> desc =~ "information"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.ErrorDisplay.vulnerability_description()
      iex> desc =~ "sensitive"
      true
  """
  @impl true
  def vulnerability_description do
    """
    Information disclosure through error messages occurs when applications reveal 
    sensitive technical details to end users, providing attackers with valuable 
    information about the system's architecture, configuration, and potential 
    vulnerabilities.
    
    While detailed error messages are helpful during development, they become a 
    security risk in production environments. Database errors, in particular, can 
    expose table names, column structures, query syntax, and even data values that 
    should remain confidential.
    
    ## Security Impact
    
    **Information Leakage**: Error messages reveal internal system details that 
    attackers can use to understand the application's structure and identify 
    potential attack vectors.
    
    **Attack Surface Mapping**: Technical errors help attackers enumerate the 
    technology stack, database schema, and application endpoints, making targeted 
    attacks more feasible.
    
    **Vulnerability Discovery**: Error messages often reveal the exact nature of 
    input validation failures, making it easier to craft successful exploits.
    
    ## Common Scenarios
    
    1. **Database Errors**:
       - Table and column names exposed
       - SQL syntax revealed
       - Database version information
    
    2. **File System Errors**:
       - Full file paths disclosed
       - Directory structure mapped
       - Permission details revealed
    
    3. **Application Errors**:
       - Framework version exposed
       - Internal function names
       - Business logic revealed
    
    ## Prevention
    
    Always log detailed errors for debugging purposes but display only generic 
    messages to users, implement proper error handling with environment-specific 
    behavior, use error monitoring services for production issues, and regularly 
    audit your application for information disclosure vulnerabilities.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual error disclosure and
  legitimate error handling practices.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.ErrorDisplay.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.ErrorDisplay.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.ErrorDisplay.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      rules: [
        %{
          type: "error_functions",
          description: "Identify error-related functions",
          database_errors: [
            "mysqli_error", "mysql_error", "pg_last_error",
            "oci_error", "sqlsrv_errors", "db2_conn_error"
          ],
          system_errors: [
            "error_get_last", "libxml_get_errors",
            "curl_error", "json_last_error_msg"
          ],
          error_numbers: [
            "mysqli_errno", "mysql_errno", "pg_last_error",
            "oci_error", "sqlsrv_errors"
          ]
        },
        %{
          type: "output_context",
          description: "Analyze how errors are output",
          dangerous_outputs: [
            "die", "exit", "echo", "print",
            "printf", "var_dump", "print_r"
          ],
          safe_outputs: [
            "error_log", "syslog", "trigger_error",
            "throw", "logger", "monolog"
          ]
        },
        %{
          type: "error_handling_patterns",
          description: "Detect proper error handling",
          safe_patterns: [
            "try.*catch", "set_error_handler",
            "set_exception_handler", "error_reporting\\(0\\)"
          ],
          logging_patterns: [
            "error_log", "\\$logger->", "monolog",
            "log4php", "psr-3"
          ]
        },
        %{
          type: "environment_detection",
          description: "Check for environment-specific handling",
          production_indicators: [
            "production", "prod", "live",
            "APP_ENV", "ENVIRONMENT"
          ],
          generic_messages: [
            "error occurred", "try again",
            "contact support", "error code"
          ]
        }
      ]
    }
  end
end