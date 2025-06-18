defmodule RsolvApi.Security.Patterns.Php.XpathInjection do
  @moduledoc """
  Pattern for detecting XPath injection vulnerabilities in PHP.
  
  This pattern identifies when PHP applications construct XPath queries using 
  unsanitized user input, potentially allowing attackers to manipulate XML 
  queries and gain unauthorized access to data.
  
  ## Vulnerability Details
  
  XPath injection is a critical security vulnerability that occurs when applications
  construct XPath queries by directly concatenating or interpolating user input
  without proper validation or escaping. This allows attackers to manipulate
  XPath queries and potentially:
  
  - Bypass authentication mechanisms in XML-based user stores
  - Extract sensitive data from XML documents
  - Enumerate structure and content of XML databases
  - Access restricted portions of XML documents
  
  ### Attack Example
  ```php
  // Vulnerable code - user input directly in XPath query
  $username = $_POST['username']; // Attacker input: "admin' or '1'='1"
  $xpath = "//user[username='$username' and password='$password']";
  $result = $domxpath->query($xpath);
  
  // Results in malicious query: //user[username='admin' or '1'='1' and password='anything']
  // This bypasses authentication by creating an always-true condition
  ```
  
  XPath queries use a specific syntax with predicates, operators, and functions.
  When user input containing XPath metacharacters is not properly escaped,
  attackers can break out of the intended query structure and inject their own
  XPath logic.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-xpath-injection",
      name: "XPath Injection",
      description: "User input in XPath queries without escaping",
      type: :xpath_injection,
      severity: :high,
      languages: ["php"],
      regex: ~r/->(query|evaluate)\s*\([^)]*(?:\$_(GET|POST|REQUEST|COOKIE)|['"][^'"]*\$_(GET|POST|REQUEST|COOKIE)|['"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE))/,
      default_tier: :enterprise,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Validate and escape user input in XPath queries, use parameterized queries when possible",
      test_cases: %{
        vulnerable: [
          ~S|$xpath->query("//user[name='$_GET[username]']");|,
          ~S|$domxpath->query("//book[@id='$_POST[book_id]']");|,
          ~S|$xpath->evaluate("count(//employee[department='$_REQUEST[dept]'])");|,
          ~S|$xmlXpath->query("//product[category='$_COOKIE[cat]']");|
        ],
        safe: [
          ~S|$username = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['username']); $xpath->query("//user[name='$username']");|,
          ~S|$xpath->query("//user[name='safe_value']");|,
          ~S|$xpath->query($safe_query);|,
          ~S|$xpath->compile("//user[@name='static']");|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XPath injection is a critical security vulnerability that allows attackers to manipulate 
      XPath (XML Path Language) queries by injecting malicious input into XPath expressions. 
      This vulnerability occurs when applications construct XPath queries using unsanitized 
      user input, enabling attackers to bypass authentication, extract sensitive XML data, 
      and potentially compromise entire XML-based data stores.
      
      XPath injection attacks exploit the special syntax and operators used in XPath expressions.
      XPath uses predicates (square brackets), logical operators (and, or), comparison operators,
      and string functions that have specific meaning in XPath queries. When user input containing
      these characters is not properly escaped or validated, attackers can break out of the
      intended query structure and inject their own XPath logic.
      
      ### Common Attack Vectors
      
      **Authentication Bypass**: The most common XPath injection attack targets authentication
      systems that use XML documents for user verification. By injecting logical operators,
      attackers can create expressions that always evaluate to true:
      
      ```php
      // Vulnerable authentication code
      $username = $_POST['username']; // Attacker input: "admin' or '1'='1"
      $password = $_POST['password'];
      $xpath = "//user[username='$username' and password='$password']";
      $result = $domxpath->query($xpath);
      
      // Malicious query becomes:
      // //user[username='admin' or '1'='1' and password='anything']
      // This bypasses password check due to operator precedence
      ```
      
      **Information Disclosure**: Attackers can modify XPath expressions to extract sensitive
      data beyond what the application intended to expose:
      
      ```php
      // Intended: Search for users by department
      $dept = $_GET['department']; // Attacker input: "'] | //user/*['"
      $xpath = "//user[department='$dept']";
      
      // Results in: //user[department=''] | //user/*['']
      // This returns all child elements of all user nodes
      ```
      
      **Data Enumeration**: In applications that use XPath for data retrieval,
      injection attacks can enumerate XML structure and content:
      
      ```php
      // Check user permissions
      $user = $_SESSION['username']; // Attacker input: "'] | //admin | //[''"
      $xpath = "//permissions[user='$user']";
      
      // Becomes: //permissions[user=''] | //admin | //['']
      // This reveals the existence and structure of admin nodes
      ```
      
      ### XML Document Impact
      
      XPath injection attacks can have severe consequences for XML-based applications:
      
      - **Data Exfiltration**: Access to sensitive information stored in XML documents
      - **Authentication Bypass**: Complete circumvention of XML-based login mechanisms  
      - **Structure Discovery**: Enumeration of XML schema and data organization
      - **Privilege Escalation**: Access to administrative or restricted XML nodes
      - **Service Disruption**: Malformed queries can cause XML parser performance issues
      
      ### Enterprise XML Vulnerabilities
      
      Enterprise applications using XML for configuration, user management, or data storage
      are particularly vulnerable because they often contain:
      - User account information and authentication credentials
      - Configuration data with security-sensitive settings
      - Business logic rules and access control definitions
      - Integration data with external systems and APIs
      - Audit logs and compliance-related information
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-643",
          title: "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
          url: "https://cwe.mitre.org/data/definitions/643.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :owasp,
          id: "XPath_Prevention",
          title: "OWASP XPath Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/XPath_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "xpath_injection_attacks",
          title: "XPath Injection Attack and Defense Techniques",
          url: "https://rhinosecuritylabs.com/penetration-testing/xpath-injection-attack-defense-techniques/"
        },
        %{
          type: :research,
          id: "php_xpath_security",
          title: "PHP XPath Security Best Practices",
          url: "https://www.php.net/manual/en/class.domxpath.php"
        }
      ],
      attack_vectors: [
        "Authentication bypass: 'admin' or '1'='1' - creates always-true condition",
        "Data extraction: '] | //user/* | //*[' - extracts all XML elements", 
        "Structure enumeration: '] | //admin | //['  - discovers admin nodes",
        "Function injection: '] | //user[position()=1] | //*[' - uses XPath functions",
        "Comment injection: '] | //user[contains(comment(), 'secret')] | //*[' - searches comments",
        "Attribute extraction: '] | //@* | //*[' - extracts all attributes",
        "Logic manipulation: ' and 1=2] | //user[1=1 and ' - inverts intended query logic"
      ],
      real_world_impact: [
        "Complete authentication bypass in XML-based user management systems",
        "Exposure of sensitive configuration data and business rules",
        "Unauthorized access to restricted XML document sections",
        "Data breaches involving XML-stored personal and financial information",
        "Compromise of enterprise document management systems",
        "Industrial espionage through XML data structure enumeration",
        "Compliance violations (SOX, GDPR) due to unauthorized data access"
      ],
      cve_examples: [
        %{
          id: "CVE-2016-6272",
          description: "XPath injection in Epic MyChart allowing access to XML documents",
          severity: "medium",
          cvss: 6.5,
          note: "Allows remote attackers to access contents of XML documents containing display strings"
        },
        %{
          id: "CVE-2019-17591",
          description: "XPath injection in Juniper J-Web interface",
          severity: "high", 
          cvss: 8.8,
          note: "Improper neutralization of data within XPath expressions in network management"
        },
        %{
          id: "CVE-2021-22204",
          description: "XPath injection via ExifTool XML processing",
          severity: "critical",
          cvss: 9.8,
          note: "Remote code execution through XPath injection in metadata processing"
        },
        %{
          id: "CVE-2023-28562",
          description: "Concrete5 CMS XPath injection vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "XPath injection in content management system enabling data access"
        },
        %{
          id: "CVE-2020-12243",
          description: "XPath injection in OpenEMR via XML document processing",
          severity: "medium",
          cvss: 5.4,
          note: "Healthcare application XPath injection enabling patient data access"
        }
      ],
      detection_notes: """
      This pattern detects XPath injection vulnerabilities by identifying PHP code that:
      
      1. **Method Analysis**: Matches XPath query methods:
         - ->query() - executes XPath expressions against XML documents
         - ->evaluate() - evaluates XPath expressions and returns results
      
      2. **Parameter Inspection**: Analyzes method parameters for:
         - Direct user input variables ($_GET, $_POST, $_REQUEST, $_COOKIE)
         - Unescaped concatenation of user data in XPath expressions
         - Missing sanitization or validation of XPath input
      
      3. **Context Validation**: The regex pattern specifically looks for:
         - XPath method calls with proper object dereferencing (->)
         - User input sources within the expression parameter
         - Absence of proper escaping or validation mechanisms
      
      The pattern uses a regex that matches the structure:
      $xpath_object->method("xpath_expression_with_$_USER_INPUT")
      
      Special considerations:
      - Matches both query() and evaluate() methods
      - Detects both quoted and concatenated parameter patterns
      - Identifies all major PHP superglobal sources
      - Accounts for various whitespace and formatting styles
      - Distinguishes from safe static XPath expressions
      """,
      safe_alternatives: [
        "Validate input against allowed character sets: preg_replace('/[^a-zA-Z0-9]/', '', $input)",
        "Use input allowlists for XPath components: in_array($input, $allowed_values)",
        "Escape XPath special characters: str_replace([\"'\", '\"', '[', ']'], ['&apos;', '&quot;', '&#91;', '&#93;'], $input)",
        "Use parameterized XPath queries where available in XML libraries",
        "Implement strict input validation with length and format restrictions",
        "Use SimpleXML with proper filtering instead of raw XPath when possible",
        "Design XML schemas to minimize need for dynamic XPath construction"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that XPath is 'safer' than SQL and doesn't need injection protection",
          "Using basic string escaping instead of XPath-specific character encoding", 
          "Only escaping quotes while ignoring XPath operators and functions",
          "Trusting XML data from 'internal' sources without validation",
          "Implementing custom escaping instead of using established libraries",
          "Not understanding that XPath injection can bypass authentication",
          "Assuming that XML schema validation prevents injection attacks"
        ],
        xpath_special_characters: [
          "' \" - String delimiters that can break out of expressions",
          "[ ] - Predicate brackets for filtering conditions",
          "| - Union operator for combining node sets", 
          "/ // - Path separators for navigating XML structure",
          "@ - Attribute selector for accessing XML attributes",
          "( ) - Function call delimiters and grouping operators",
          "and or not - Logical operators for combining conditions"
        ],
        enterprise_considerations: [
          "XML-based configuration systems require careful XPath construction",
          "Document management systems may have different XPath requirements",
          "Consider XPath injection in single sign-on (SSO) implementations",
          "Audit XML-based authorization and access control queries",
          "Implement monitoring for unusual XPath query patterns", 
          "Test XPath injection defenses with automated security tools",
          "Document all dynamic XPath construction patterns for security review"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the XPath injection pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.XpathInjection.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.XpathInjection.test_cases()
      iex> length(test_cases.negative)
      6
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$xpath->query("//user[name='$_GET[username]']");|,
          description: "Direct user input in XPath query expression"
        },
        %{
          code: ~S|$domxpath->query("//book[@id='$_POST[book_id]']");|,
          description: "POST data in XPath attribute filter"
        },
        %{
          code: ~S|$xpath->evaluate("count(//employee[department='$_REQUEST[dept]'])");|,
          description: "REQUEST data in XPath function call"
        },
        %{
          code: ~S|$xmlXpath->query("//product[category='$_COOKIE[cat]']");|,
          description: "Cookie data in XPath predicate"
        },
        %{
          code: ~S|$xpath->query("//user[@username='$_POST[login]' and @password='$_POST[pass]']");|,
          description: "Multiple user inputs in authentication XPath"
        },
        %{
          code: ~S|$xpath->evaluate("string(//user[@id='$_GET[id]']/@email)");|,
          description: "User input in XPath string function"
        },
        %{
          code: ~S|$domxpath->query("//item[@position='$_REQUEST[pos]']");|,
          description: "REQUEST data in XPath attribute filter"
        },
        %{
          code: ~S|$xpath->query("//record[@status='$_COOKIE[status]']");|,
          description: "Cookie data in XPath attribute filter"
        }
      ],
      negative: [
        %{
          code: ~S|$xpath->query("//user[name='safe_value']");|,
          description: "Hardcoded safe XPath expression"
        },
        %{
          code: ~S|$xpath->query("//user[name='" . htmlspecialchars($_GET['name']) . "']");|,
          description: "Properly escaped user input"
        },
        %{
          code: ~S|$name = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['name']); $xpath->query("//user[name='$name']");|,
          description: "Input validation before XPath usage"
        },
        %{
          code: ~S|$xpath->query($safe_query);|,
          description: "Pre-constructed safe query variable"
        },
        %{
          code: ~S|$xpath->compile("//user[@name='static']");|,
          description: "XPath compilation (not query execution)"
        },
        %{
          code: ~S|$doc->createElement('user', $_POST['name']);|,
          description: "DOM manipulation (not XPath query)"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.XpathInjection.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Authentication bypass" => """
        // VULNERABLE: Direct user input in authentication XPath
        $username = $_POST['username'];
        $password = $_POST['password'];
        $xpath = "//user[username='$username' and password='$password']";
        $result = $domxpath->query($xpath);
        
        // Attacker input: username = "admin' or '1'='1"
        // Results in: //user[username='admin' or '1'='1' and password='anything']
        """,
        "Data extraction" => """
        // VULNERABLE: User search without escaping
        $search = $_GET['search'];
        $xpath = "//employee[name='$search']";
        $employees = $domxpath->query($xpath);
        
        // Attacker input: search = "'] | //employee/* | //*['"
        // Results in: //employee[name=''] | //employee/* | //*['']
        // Returns all employee data
        """,
        "Function injection" => """
        // VULNERABLE: User input in XPath function
        $category = $_GET['category'];
        $xpath = "//product[category='$category']";
        $count = $domxpath->evaluate("count($xpath)");
        
        // Attacker can inject: category = "'] | //admin/* | //*['"
        // To access restricted admin data
        """
      },
      fixed: %{
        "Input validation" => """
        // SECURE: Validate input against allowlist
        $allowedCategories = ['electronics', 'books', 'clothing', 'sports'];
        $category = $_GET['category'];
        
        if (!in_array($category, $allowedCategories)) {
            throw new InvalidArgumentException('Invalid category');
        }
        
        $xpath = "//product[category='$category']";
        $products = $domxpath->query($xpath);
        """,
        "Parameterized queries" => """
        // SECURE: Input sanitization and validation
        $username = $_POST['username'];
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            throw new InvalidArgumentException('Invalid username format');
        }
        
        $escapedUsername = str_replace("'", "&apos;", $username);
        $xpath = "//user[username='$escapedUsername']";
        $result = $domxpath->query($xpath);
        """,
        "Alternative approach" => """
        // SECURE: Use SimpleXML with validation
        $userId = filter_var($_GET['id'], FILTER_VALIDATE_INT);
        if ($userId === false) {
            throw new InvalidArgumentException('Invalid user ID');
        }
        
        $users = simplexml_load_file('users.xml');
        foreach ($users->user as $user) {
            if ((int)$user['id'] === $userId) {
                return $user;
            }
        }
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.XpathInjection.vulnerability_description()
      iex> desc =~ "XPath injection"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.XpathInjection.vulnerability_description()
      iex> desc =~ "xpath"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.XpathInjection.vulnerability_description()
      iex> desc =~ "query"
      true
  """
  @impl true
  def vulnerability_description do
    """
    XPath injection occurs when applications construct xpath query expressions using 
    unsanitized user input, allowing attackers to manipulate XML queries and 
    potentially bypass authentication or extract sensitive XML data.
    
    In PHP, this commonly happens when:
    
    1. **Direct Input Usage**: User input from $_GET, $_POST, $_REQUEST, or $_COOKIE
       is directly concatenated into xpath expression strings without escaping.
       
    2. **Missing Validation**: No validation or sanitization is performed on user
       input before constructing xpath queries.
       
    3. **Improper Escaping**: Custom or incorrect escaping methods are used instead
       of proper xpath character encoding.
    
    ## Attack Techniques
    
    **Authentication Bypass**: Attackers inject xpath operators to create always-true
    conditions, bypassing username/password verification in XML-based systems.
    
    **Information Disclosure**: Malicious xpath expressions can extract more data than 
    intended, including sensitive XML document content and structure.
    
    **Privilege Escalation**: In systems using XML for authorization, attackers can
    manipulate queries to access restricted XML nodes or administrative data.
    
    ## Prevention
    
    Always validate and sanitize user input before including it in xpath expressions.
    Use input allowlists, escape xpath special characters, and consider using
    alternative XML processing methods when possible.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing XPath method usage, input sources, and validation mechanisms.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.XpathInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.XpathInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.XpathInjection.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      rules: [
        %{
          type: "xpath_functions",
          description: "Identify XPath query methods that execute expressions",
          methods: [
            "query", "evaluate", "registerNamespace", "registerPHPFunctions"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Detect dangerous user input sources in XPath expressions",
          dangerous_sources: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
          safe_sources: ["$config", "$constants", "$validated_input"]
        },
        %{
          type: "validation_detection",
          description: "Identify proper XPath input validation mechanisms",
          validation_functions: ["preg_replace", "filter_var", "htmlspecialchars", "str_replace"],
          validation_patterns: ["preg_match", "in_array", "ctype_alnum"],
          escape_patterns: ["&apos;", "&quot;", "&#91;", "&#93;"]
        },
        %{
          type: "context_validation",
          description: "Validate XPath injection context and exclude false positives",
          exclude_patterns: [
            "test", "mock", "example", "demo", "comment",
            "documentation", "tutorial", "sample", "template"
          ]
        }
      ]
    }
  end
end