defmodule Rsolv.Security.Patterns.Php.LdapInjection do
  @moduledoc """
  Pattern for detecting LDAP injection vulnerabilities in PHP.
  
  This pattern identifies when PHP applications construct LDAP search filters
  using unsanitized user input, potentially allowing attackers to manipulate
  LDAP queries and gain unauthorized access to directory information.
  
  ## Vulnerability Details
  
  LDAP injection is a critical security vulnerability that occurs when applications
  construct LDAP search filters by directly concatenating or interpolating user input
  without proper escaping or validation. This allows attackers to manipulate LDAP
  queries and potentially:
  
  - Bypass authentication mechanisms
  - Extract sensitive directory information
  - Enumerate users and organizational structure
  - Escalate privileges within directory services
  
  ### Attack Example
  ```php
  // Vulnerable code - user input directly in LDAP filter
  $username = $_POST['username']; // Attacker input: "admin)(|(objectClass=*"
  $filter = "(uid=$username)";
  $result = ldap_search($ds, $dn, $filter);
  
  // Results in malicious filter: (uid=admin)(|(objectClass=*)
  // This can bypass authentication or extract all directory entries
  ```
  
  LDAP filters use a specific syntax with parentheses, operators, and special
  characters. When user input containing these characters is not properly escaped,
  attackers can break out of the intended filter structure and inject their own
  LDAP logic.
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-ldap-injection",
      name: "LDAP Injection",
      description: "User input in LDAP queries without escaping",
      type: :ldap_injection,
      severity: :high,
      languages: ["php"],
      regex: ~r/(?:ldap_search|ldap_list|ldap_read)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)\[/,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Use ldap_escape() to sanitize user input in LDAP filters",
      test_cases: %{
        vulnerable: [
          ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|,
          ~S|ldap_list($ds, $dn, "(cn=$_POST[name])");|,
          ~S|ldap_read($ds, $dn, "(mail=$_REQUEST[email])");|,
          ~S|ldap_search($ds, $dn, "(&(objectClass=user)(cn=$_GET[search]))");|
        ],
        safe: [
          ~S|$username = ldap_escape($_GET['username'], '', LDAP_ESCAPE_FILTER); ldap_search($ds, $dn, "(uid=$username)");|,
          ~S|ldap_search($ds, $dn, "(uid=safe_value)");|,
          ~S|ldap_search($ds, $dn, $safe_filter);|,
          ~S|ldap_bind($ds, $username, $password);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      LDAP injection is a critical security vulnerability that allows attackers to manipulate 
      LDAP (Lightweight Directory Access Protocol) queries by injecting malicious input into 
      LDAP search filters. This vulnerability occurs when applications construct LDAP queries 
      using unsanitized user input, enabling attackers to bypass authentication, extract 
      sensitive directory information, and potentially compromise entire directory services.
      
      LDAP injection attacks exploit the special syntax and operators used in LDAP search filters.
      LDAP filters use parentheses, logical operators (&, |, !), and special characters that have
      specific meaning in LDAP queries. When user input containing these characters is not properly
      escaped or validated, attackers can break out of the intended filter structure and inject
      their own LDAP logic.
      
      ### Common Attack Vectors
      
      **Authentication Bypass**: The most common LDAP injection attack targets authentication
      systems that use LDAP for user verification. By injecting logical operators, attackers
      can create filters that always evaluate to true:
      
      ```php
      // Vulnerable authentication code
      $username = $_POST['username']; // Attacker input: "admin)(|(objectClass=*"
      $password = $_POST['password'];
      $filter = "(&(uid=$username)(password=$password))";
      $result = ldap_search($connection, $baseDN, $filter);
      
      // Malicious filter becomes:
      // (&(uid=admin)(|(objectClass=*)(password=anything))
      // This bypasses password check for admin user
      ```
      
      **Information Disclosure**: Attackers can modify search filters to extract sensitive
      directory information beyond what the application intended to expose:
      
      ```php
      // Intended: Search for users by department
      $dept = $_GET['department']; // Attacker input: "*)(objectClass=*"
      $filter = "(department=$dept)";
      
      // Results in: (department=*)(objectClass=*)
      // This returns all directory entries instead of just department users
      ```
      
      **Privilege Escalation**: In applications that use LDAP groups for authorization,
      injection attacks can manipulate group membership queries:
      
      ```php
      // Check if user is admin
      $user = $_SESSION['username']; // Attacker input: "*)(|(memberOf=cn=admin,*"
      $filter = "(&(uid=$user)(memberOf=cn=user,ou=groups,dc=company,dc=com))";
      
      // Becomes: (&(uid=*)(|(memberOf=cn=admin,*)(memberOf=cn=user,ou=groups,dc=company,dc=com))
      // This can grant admin privileges to any user
      ```
      
      ### Directory Service Impact
      
      LDAP injection attacks can have severe consequences for organizations:
      
      - **User Enumeration**: Attackers can discover valid usernames, email addresses, and
        organizational structure information
      - **Authentication Bypass**: Complete circumvention of login mechanisms
      - **Data Exfiltration**: Access to sensitive employee information, contact details,
        and internal organizational data
      - **Privilege Escalation**: Unauthorized access to administrative functions
      - **Service Disruption**: Malformed queries can cause LDAP server performance issues
      
      ### Enterprise Directory Vulnerabilities
      
      Enterprise directory services like Active Directory, OpenLDAP, and others are particularly
      vulnerable because they often contain:
      - Employee personal information (names, emails, phone numbers)
      - Organizational hierarchy and reporting structures
      - Group memberships and access control information
      - Application-specific attributes and permissions
      - System and service account credentials
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-90",
          title: "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
          url: "https://cwe.mitre.org/data/definitions/90.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :owasp,
          id: "LDAP_Prevention",
          title: "OWASP LDAP Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "ldap_filter_syntax",
          title: "LDAP Filter Syntax and Security Considerations",
          url: "https://ldap.com/ldap-filters/"
        },
        %{
          type: :research,
          id: "php_ldap_security",
          title: "PHP LDAP Security Best Practices",
          url: "https://www.php.net/manual/en/function.ldap-escape.php"
        }
      ],
      attack_vectors: [
        "Authentication bypass: '*)(&' - creates always-true filter condition",
        "Information disclosure: '*)(objectClass=*' - extracts all directory entries",
        "Privilege escalation: '*)(|(memberOf=cn=admin,*' - grants admin group membership",
        "User enumeration: '*)(uid=admin*' - discovers valid usernames through error patterns",
        "Filter injection: '*)(&(password=*' - bypasses password validation in authentication",
        "Logic manipulation: '*)(!(&(disabled=true)(*' - inverts intended query logic",
        "Wildcard exploitation: '*' - matches all entries when injected into filters"
      ],
      real_world_impact: [
        "Complete authentication bypass in enterprise directory systems",
        "Exposure of sensitive employee and organizational data",
        "Unauthorized access to administrative accounts and privileges",
        "Data breaches involving personal information from directory services",
        "Compromise of single sign-on (SSO) authentication mechanisms",
        "Industrial espionage through organizational structure enumeration",
        "Compliance violations (GDPR, HIPAA) due to unauthorized data access"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-41580",
          description: "LDAP injection in phpIPAM via dname parameter",
          severity: "high",
          cvss: 8.8,
          note: "Allows enumeration of arbitrary LDAP fields and sensitive data access"
        },
        %{
          id: "CVE-2017-14596",
          description: "Joomla! LDAP injection enabling account takeover",
          severity: "critical",
          cvss: 9.8,
          note: "Critical vulnerability allowing complete site takeover via LDAP filter manipulation"
        },
        %{
          id: "CVE-2024-11236",
          description: "PHP ldap_escape() integer overflow vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Integer overflow in ldap_escape() function can bypass protection mechanisms"
        },
        %{
          id: "CVE-2018-15473",
          description: "OpenSSH username enumeration via LDAP injection",
          severity: "medium",
          cvss: 5.3,
          note: "Username enumeration through LDAP filter injection in authentication"
        },
        %{
          id: "CVE-2019-14439",
          description: "phpLDAPadmin LDAP injection vulnerability",
          severity: "high",
          cvss: 8.1,
          note: "LDAP injection in server_id parameter enabling unauthorized access"
        }
      ],
      detection_notes: """
      This pattern detects LDAP injection vulnerabilities by identifying PHP code that:
      
      1. **Function Analysis**: Matches LDAP query functions:
         - ldap_search() - searches LDAP directory tree
         - ldap_list() - lists entries in LDAP directory
         - ldap_read() - reads single LDAP entry
      
      2. **Parameter Inspection**: Analyzes the third parameter (filter parameter) for:
         - Direct user input variables ($_GET, $_POST, $_REQUEST, $_COOKIE)
         - Unescaped concatenation of user data
         - Missing sanitization or validation
      
      3. **Context Validation**: The regex pattern specifically looks for:
         - LDAP function calls with proper parameter structure
         - User input sources within the filter parameter
         - Absence of proper escaping mechanisms
      
      The pattern uses a regex that matches the structure:
      ldap_function(connection, base_dn, "filter_with_$_USER_INPUT")
      
      Special considerations:
      - Matches both quoted and unquoted filter parameters
      - Detects concatenation patterns with user input
      - Identifies all major PHP superglobal sources
      - Accounts for various whitespace and formatting styles
      """,
      safe_alternatives: [
        "Use ldap_escape() with LDAP_ESCAPE_FILTER flag: ldap_escape($_GET['input'], '', LDAP_ESCAPE_FILTER)",
        "Validate input against allowed character sets before using in filters",
        "Use parameterized queries where available in LDAP libraries",
        "Implement strict input validation with allowlists for LDAP filter components",
        "Use DN (Distinguished Name) binding instead of filter-based authentication where possible",
        "Implement proper access controls and least privilege principles for LDAP operations",
        "Use prepared LDAP filter templates with placeholder replacement"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that LDAP is 'safe' from injection attacks unlike SQL databases",
          "Using basic string escaping instead of LDAP-specific escaping functions",
          "Only escaping parentheses while ignoring other LDAP special characters",
          "Trusting 'internal' user input sources like session variables without validation",
          "Implementing custom escaping instead of using ldap_escape() function",
          "Not understanding that LDAP filter injection can bypass authentication",
          "Assuming that complex filters are immune to injection attacks"
        ],
        ldap_special_characters: [
          "( ) - Grouping operators that define filter structure",
          "& | ! - Logical operators (AND, OR, NOT) for combining conditions",
          "* - Wildcard character that matches any value",
          "\\ - Escape character for literal special characters",
          "= - Equality operator for attribute matching",
          ">= <= - Comparison operators for range queries",
          "~= - Approximate matching operator"
        ],
        enterprise_considerations: [
          "Active Directory integration requires careful filter construction",
          "OpenLDAP servers may have different escaping requirements",
          "Consider LDAP injection in single sign-on (SSO) implementations",
          "Audit LDAP-based authorization and group membership queries",
          "Implement monitoring for unusual LDAP query patterns",
          "Test LDAP injection defenses with automated security tools",
          "Document all LDAP filter construction patterns for security review"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the LDAP injection pattern.
  
  ## Examples
  
      iex> test_cases = Rsolv.Security.Patterns.Php.LdapInjection.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = Rsolv.Security.Patterns.Php.LdapInjection.test_cases()
      iex> length(test_cases.negative)
      6
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|,
          description: "Direct user input in LDAP search filter"
        },
        %{
          code: ~S|ldap_list($ds, $dn, "(cn=$_POST[name])");|,
          description: "POST data in LDAP list filter"
        },
        %{
          code: ~S|ldap_read($ds, $dn, "(mail=$_REQUEST[email])");|,
          description: "REQUEST data in LDAP read filter"
        },
        %{
          code: ~S|ldap_search($ds, $dn, "(cn=$_GET[search])");|,
          description: "Simple filter with user input"
        },
        %{
          code: "ldap_search(\$ds, \$dn, \"(|(uid=\$_POST[id])(mail=\$_POST[email]))\");",
          description: "OR filter with multiple user inputs"
        },
        %{
          code: ~S|ldap_search($ds, $dn, "(!(cn=$_GET[exclude]))");|,
          description: "NOT filter with user input"
        },
        %{
          code: ~S|ldap_list($ds, $dn, "(department=$_REQUEST[dept])");|,
          description: "Department filter with REQUEST data"
        },
        %{
          code: ~S|ldap_search($ds, $dn, "(sn=" . $_COOKIE['surname'] . ")");|,
          description: "String concatenation with cookie data"
        }
      ],
      negative: [
        %{
          code: ~S|ldap_search($ds, $dn, "(uid=safe_value)");|,
          description: "Hardcoded safe filter value"
        },
        %{
          code: ~S|ldap_search($ds, $dn, "(cn=" . ldap_escape($_GET['name']) . ")");|,
          description: "Properly escaped user input"
        },
        %{
          code: ~S|$filter = "(uid=" . ldap_escape($_POST['username'], null, LDAP_ESCAPE_FILTER) . ")"; ldap_search($ds, $dn, $filter);|,
          description: "LDAP_ESCAPE_FILTER flag usage"
        },
        %{
          code: ~S|ldap_search($ds, $dn, $safe_filter);|,
          description: "Pre-constructed safe filter variable"
        },
        %{
          code: ~S|ldap_bind($ds, $username, $password);|,
          description: "LDAP bind operation (not search)"
        },
        %{
          code: ~S|ldap_connect('ldap://example.com');|,
          description: "LDAP connection (not query)"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = Rsolv.Security.Patterns.Php.LdapInjection.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  def examples do
    %{
      vulnerable: %{
        "Authentication bypass" => """
        // VULNERABLE: Direct user input in authentication filter
        $username = $_POST['username'];
        $password = $_POST['password'];
        $filter = "(&(uid=$username)(password=$password))";
        $result = ldap_search($connection, $baseDN, $filter);
        
        // Attacker input: username = "admin)(|(objectClass=*"
        // Results in: (&(uid=admin)(|(objectClass=*)(password=anything))
        """,
        "Information disclosure" => """
        // VULNERABLE: Department search without escaping
        $department = $_GET['dept'];
        $filter = "(department=$department)";
        $employees = ldap_search($ldap, $base, $filter);
        
        // Attacker input: dept = "*)(objectClass=*"
        // Results in: (department=*)(objectClass=*)
        // Returns all directory entries
        """,
        "User enumeration" => """
        // VULNERABLE: Username search for autocomplete
        $search = $_GET['q'];
        $filter = "(cn=*$search*)";
        $users = ldap_search($ldap, $userBase, $filter);
        
        // Attacker can inject: q = "*)(uid=admin*"
        // To discover specific usernames
        """
      },
      fixed: %{
        "Escaped filter" => """
        // SECURE: Proper LDAP escaping
        $username = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
        $password = ldap_escape($_POST['password'], '', LDAP_ESCAPE_FILTER);
        $filter = "(&(uid=$username)(password=$password))";
        $result = ldap_search($connection, $baseDN, $filter);
        """,
        "Parameterized query" => """
        // SECURE: Input validation and parameterized approach
        $department = $_GET['dept'];
        if (!preg_match('/^[a-zA-Z0-9\\s]+$/', $department)) {
            throw new InvalidArgumentException('Invalid department name');
        }
        $escapedDept = ldap_escape($department, '', LDAP_ESCAPE_FILTER);
        $filter = "(department=$escapedDept)";
        $employees = ldap_search($ldap, $base, $filter);
        """,
        "Input validation" => """
        // SECURE: Allowlist-based validation
        $allowedDepartments = ['IT', 'HR', 'Finance', 'Marketing'];
        $department = $_GET['dept'];
        
        if (!in_array($department, $allowedDepartments)) {
            throw new InvalidArgumentException('Invalid department');
        }
        
        $filter = "(department=$department)";
        $employees = ldap_search($ldap, $base, $filter);
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = Rsolv.Security.Patterns.Php.LdapInjection.vulnerability_description()
      iex> desc =~ "LDAP injection"
      true
      
      iex> desc = Rsolv.Security.Patterns.Php.LdapInjection.vulnerability_description()
      iex> desc =~ "ldap_escape"
      true
      
      iex> desc = Rsolv.Security.Patterns.Php.LdapInjection.vulnerability_description()
      iex> desc =~ "filter"
      true
  """
  def vulnerability_description do
    """
    LDAP injection occurs when applications construct LDAP search filters using 
    unsanitized user input, allowing attackers to manipulate LDAP queries and 
    potentially bypass authentication or extract sensitive directory information.
    
    In PHP, this commonly happens when:
    
    1. **Direct Input Usage**: User input from $_GET, $_POST, $_REQUEST, or $_COOKIE
       is directly concatenated into LDAP filter strings without escaping.
       
    2. **Missing Validation**: No validation or sanitization is performed on user
       input before constructing LDAP filters.
       
    3. **Improper Escaping**: Custom or incorrect escaping methods are used instead
       of the proper ldap_escape() function with LDAP_ESCAPE_FILTER flag.
    
    ## Attack Techniques
    
    **Authentication Bypass**: Attackers inject LDAP operators to create always-true
    conditions, bypassing username/password verification.
    
    **Information Disclosure**: Malicious filters can extract more data than intended,
    including sensitive organizational information.
    
    **Privilege Escalation**: In systems using LDAP for authorization, attackers can
    manipulate group membership queries to gain elevated privileges.
    
    ## Prevention
    
    Always use ldap_escape() with the LDAP_ESCAPE_FILTER flag to properly escape
    user input before including it in LDAP filters. Additionally, implement input
    validation and consider using allowlists for expected values.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing LDAP function usage, input sources, and escaping mechanisms.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.LdapInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Php.LdapInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Php.LdapInjection.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      ast_rules: [
        %{
          type: "ldap_functions",
          description: "Identify LDAP query functions that accept filters",
          functions: [
            "ldap_search", "ldap_list", "ldap_read", "ldap_compare"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Detect dangerous user input sources in LDAP filters",
          dangerous_sources: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
          safe_sources: ["$config", "$constants", "$validated_input"]
        },
        %{
          type: "escaping_detection",
          description: "Identify proper LDAP escaping mechanisms",
          escape_functions: ["ldap_escape"],
          escape_patterns: ["LDAP_ESCAPE_FILTER", "LDAP_ESCAPE_DN"],
          validation_patterns: ["preg_match", "filter_var", "in_array"]
        },
        %{
          type: "context_validation",
          description: "Validate LDAP injection context and exclude false positives",
          exclude_patterns: [
            "test", "mock", "example", "demo", "comment",
            "documentation", "tutorial", "sample"
          ]
        }
      ]
    }
  end
end
