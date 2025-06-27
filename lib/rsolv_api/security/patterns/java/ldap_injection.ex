defmodule RsolvApi.Security.Patterns.Java.LdapInjection do
  @moduledoc """
  LDAP Injection pattern for Java code.
  
  Detects LDAP injection vulnerabilities in Java applications where user input is directly
  concatenated into LDAP queries without proper sanitization or escaping. LDAP injection
  attacks can lead to authentication bypass, information disclosure, and unauthorized
  access to directory services.
  
  ## Vulnerability Details
  
  LDAP injection occurs when an application constructs LDAP queries by directly concatenating
  user input without proper validation or escaping. This allows attackers to manipulate
  LDAP queries to bypass authentication, access unauthorized data, or modify directory
  information.
  
  Common vulnerable patterns:
  - String concatenation in LDAP search filters
  - Unsafe DN (Distinguished Name) construction
  - Direct user input in bind operations
  - Filter construction without escaping special characters
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - direct concatenation
  String filter = "(uid=" + username + ")";
  ctx.search("ou=users,dc=example,dc=com", filter, controls);
  
  // Attack payload examples:
  // username = "*)(objectClass=*))(|(uid=*" -> Bypass authentication
  // username = "admin)(&(password=*" -> Password enumeration
  // username = "*)(mail=*))%00" -> Information disclosure
  ```
  
  ## References
  
  - CWE-90: Improper Neutralization of Special Elements used in an LDAP Query
  - OWASP A03:2021 - Injection
  - CVE-2022-46337: Apache Derby LDAP injection vulnerability
  - OWASP LDAP Injection Prevention Cheat Sheet
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Pattern detects LDAP injection vulnerabilities in Java code.
  
  Identifies unsafe string concatenation in LDAP operations that could allow
  attackers to manipulate LDAP queries and bypass security controls.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.LdapInjection.pattern()
      iex> pattern.id
      "java-ldap-injection"
      
      iex> pattern = RsolvApi.Security.Patterns.Java.LdapInjection.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Java.LdapInjection.pattern()
      iex> vulnerable = "ctx.search(\\\"cn=\\\" + username + \\\",ou=users\\\", filter, controls);"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, vulnerable) end)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Java.LdapInjection.pattern()
      iex> safe = "// ctx.search(\\\"cn=\\\" + username + \\\",ou=users\\\", filter, controls);"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe) end)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "java-ldap-injection",
      name: "LDAP Injection",
      description: "String concatenation in LDAP operations allows injection attacks",
      type: :ldap_injection,
      severity: :high,
      languages: ["java"],
      regex: [
        # Direct string concatenation in LDAP methods without encoding - matches patterns like:
        # ctx.search("cn=" + username + ",ou=users", ...) but not if 'escaped' or 'encoded' is in variable name
        ~r/^(?!.*\/\/).*\.(?:search|bind|lookup|createSubcontext|destroySubcontext|modifyAttributes|rename|list|listBindings)\s*\([^)]*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+(?<!escaped|encoded|sanitized)\s*\+/m,
        # LDAP filter construction with direct user input concatenation - more generic pattern
        ~r/^(?!.*\/\/).*(?:filter|Filter|query|Query|searchString)\s*=\s*["\(]*(?:&|\|)?\([^)]*[a-zA-Z]+\s*=\s*["]*\s*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+/m,
        # DN construction with direct concatenation - support various LDAP attributes
        ~r/^(?!.*\/\/).*(?:dn|DN|userDN|baseDN|principalDN|authDN)\s*=\s*["]*(?:cn|uid|mail|sAMAccountName|ou)=["]*\s*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+/m,
        # Simple filter pattern matching
        ~r/^(?!.*\/\/).*["\(]\w+\s*=\s*["]*\s*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+\s*\+\s*["\)]/m,
        # Pattern for memberOf and similar attributes
        ~r/^(?!.*\/\/).*["\(](?:memberOf|member)\s*=\s*[^"]*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+/m,
        # Search method with filter as second parameter containing concatenation
        ~r/^(?!.*\/\/).*\.search\s*\([^,]+,\s*["]*[^"]*\+\s*(?!escaped|encoded|sanitized)[\w\[\]\.]+/m
      ],
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized LDAP queries, escape user input with LdapEncoder.filterEncode(), and validate input against allowlists",
      test_cases: %{
        vulnerable: [
          ~S|ctx.search("cn=" + username + ",ou=users", filter, controls);|,
          ~S|String filter = "(uid=" + uid + ")";|,
          ~S|ctx.bind("cn=" + username + ",ou=users,dc=example,dc=com", password, attrs);|
        ],
        safe: [
          ~S|String escapedUsername = LdapEncoder.filterEncode(username);
ctx.search("cn=" + escapedUsername + ",ou=users", filter, controls);|,
          ~S|// ctx.search("cn=" + username + ",ou=users", filter, controls);|,
          ~S|String comment = "Use parameterized LDAP queries like (cn={0})";|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      LDAP injection vulnerabilities occur when an application constructs LDAP queries by directly
      concatenating user input without proper validation, sanitization, or escaping. This allows
      attackers to manipulate LDAP queries to bypass authentication, access unauthorized data,
      or modify directory information.
      
      LDAP injection attacks can lead to:
      - Authentication bypass through filter manipulation
      - Information disclosure via blind injection techniques
      - Unauthorized access to directory data
      - Privilege escalation through group membership manipulation
      - Denial of service through malformed queries
      
      The vulnerability is particularly dangerous because:
      - LDAP is commonly used for authentication and authorization
      - Directory services often contain sensitive organizational data
      - Many applications trust LDAP authentication results
      - LDAP syntax allows complex boolean logic manipulation
      - Error messages can reveal directory structure information
      
      Historical context:
      - LDAP injection has been recognized since the early 2000s
      - Included in OWASP Top 10 2021 under A03 (Injection)
      - Critical vulnerabilities in Apache Derby, IBM products, and enterprise systems
      - Often overlooked compared to SQL injection but equally dangerous
      - Common in enterprise applications using Active Directory integration
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-90",
          title: "Improper Neutralization of Special Elements used in an LDAP Query",
          url: "https://cwe.mitre.org/data/definitions/90.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection", 
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "owasp_ldap_prevention",
          title: "OWASP LDAP Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "owasp_ldap_attacks",
          title: "OWASP LDAP Injection Attack Techniques",
          url: "https://owasp.org/www-community/attacks/LDAP_Injection"
        },
        %{
          type: :research,
          id: "brightsec_ldap",
          title: "Complete Guide to LDAP Injection: Types, Examples, and Prevention",
          url: "https://www.brightsec.com/blog/ldap-injection/"
        }
      ],
      attack_vectors: [
        "Authentication bypass: *()|&(objectClass=*))&(cn=* to bypass login checks",
        "Information disclosure: *)(&(password=*)(cn=* to enumerate user attributes",
        "Blind injection: *)(&(objectClass=*)(uid=admin*)(cn=* for data exfiltration",
        "Boolean logic manipulation: *(|(uid=admin)(uid=guest))(cn=* to access multiple accounts",
        "Filter injection: *))(|(objectClass=*))(&(cn=* to extract directory structure",
        "Null byte injection: admin)(&(password=*))%00 to truncate filter conditions"
      ],
      real_world_impact: [
        "Apache Derby CVE-2022-46337: LDAP injection allowing authentication bypass with CVSS 9.1",
        "IBM Transformation Extender: LDAP injection enabling data corruption and privilege escalation",
        "Oracle idm-pki-java: Authentication bypass via sessionID=* parameter manipulation",
        "Enterprise Active Directory breaches: Unauthorized access to corporate user accounts",
        "Government systems compromise: Classified data exposure through LDAP filter manipulation",
        "Financial services attacks: Customer data access via LDAP injection in trading platforms",
        "Healthcare directory breaches: Patient information disclosure through directory injection"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-46337",
          description: "Apache Derby LDAP injection vulnerability in authenticator allowing authentication bypass",
          severity: "critical",
          cvss: 9.1,
          note: "LDAP filter manipulation enables viewing and corrupting sensitive data and executing database functions"
        },
        %{
          id: "CVE-2021-23335", 
          description: "LDAP injection in is-user-valid package leading to authentication bypass or information exposure",
          severity: "high",
          cvss: 8.5,
          note: "All versions vulnerable to LDAP injection through improper input sanitization"
        },
        %{
          id: "CVE-2024-10127",
          description: "Authentication bypass in M-Files server LDAP authentication configuration",
          severity: "high", 
          cvss: 7.8,
          note: "OpenLDAP configuration vulnerability allowing unauthorized access to file management system"
        }
      ],
      detection_notes: """
      This pattern detects insecure LDAP operations by identifying:
      
      1. LDAP search methods with string concatenation in filters or distinguished names
      2. Filter construction using direct string concatenation with user input
      3. LDAP bind operations concatenating user input into authentication parameters
      4. Distinguished Name (DN) construction without proper escaping
      5. Other LDAP directory operations using unsafe string concatenation
      
      The pattern uses negative lookahead to avoid false positives when code is commented out.
      It targets common LDAP injection vectors including:
      - Search filter manipulation
      - DN injection in bind operations
      - Boolean logic manipulation in complex filters
      - Method chaining with unsafe concatenation
      
      Key detection criteria:
      - Looks for .search(), .bind(), .lookup() and other LDAP methods
      - Identifies string concatenation patterns with + operator
      - Covers filter construction and DN building patterns
      - Excludes commented code and string literals
      """,
      safe_alternatives: [
        "Use LdapEncoder.filterEncode() to escape special characters in search filters",
        "Use LdapEncoder.nameEncode() to escape special characters in distinguished names",
        "Implement parameterized LDAP queries with placeholder substitution",
        "Use allowlist validation for user input before LDAP operations",
        "Use LDAP framework with built-in injection protection (Spring LDAP)",
        "Implement proper input validation and sanitization for all LDAP parameters",
        "Use StringBuilder with escaped values instead of direct concatenation",
        "Apply the principle of least privilege for LDAP service accounts"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming LDAP injection is less dangerous than SQL injection",
          "Only escaping some special characters but not implementing comprehensive filtering",
          "Relying on client-side validation for LDAP query parameters",
          "Using blacklist filtering instead of allowlist validation",
          "Forgetting to escape distinguished names in addition to search filters",
          "Not validating the structure of LDAP results after queries",
          "Implementing custom escaping functions instead of using proven libraries"
        ],
        secure_patterns: [
          "Always use LdapEncoder or similar library functions for input escaping",
          "Implement parameterized LDAP queries where framework supports it",
          "Use allowlist validation for all user input used in LDAP operations",
          "Apply input length limits to prevent buffer overflow attacks",
          "Implement proper error handling without revealing directory structure",
          "Use service accounts with minimal necessary privileges",
          "Log and monitor all LDAP authentication attempts for anomalies",
          "Regular security testing with LDAP injection payloads"
        ],
        ldap_injection_types: [
          "Authentication bypass: Manipulating filters to always return true",
          "Information disclosure: Using boolean blind injection to extract data",
          "Filter injection: Modifying search filters to access unauthorized records",
          "DN injection: Manipulating distinguished names to access different contexts"
        ],
        special_characters: [
          "Parentheses (), asterisk *, backslash \\, null byte %00",
          "AND (&), OR (|), NOT (!), equals =, greater/less than <>"
        ],
        framework_considerations: [
          "Spring LDAP: Use LdapQueryBuilder for safe query construction",
          "Java LDAP SDK: Always use proper escaping functions before concatenation",
          "Apache Directory: Implement custom filters with parameter binding",
          "JNDI Context: Use search controls and proper exception handling",
          "Active Directory: Be aware of specific AD LDAP syntax and escaping requirements"
        ],
        compliance_impact: [
          "SOX: Improper access controls can violate financial reporting security requirements",
          "HIPAA: Patient data exposure through directory injection violates privacy rules",
          "PCI DSS: Compromise of authentication systems affects cardholder data protection",
          "GDPR: Personal data breach through LDAP injection requires notification",
          "ISO 27001: Directory service vulnerabilities violate access control standards"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual LDAP injection vulnerabilities and safe
  LDAP usage patterns that have proper input sanitization and escaping.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.LdapInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.LdapInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.LdapInjection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        ldap_analysis: %{
          check_ldap_operations: true,
          ldap_methods: ["search", "bind", "lookup", "createSubcontext", "destroySubcontext", "modifyAttributes", "rename", "list", "listBindings"],
          check_string_concatenation: true,
          dangerous_concatenation_patterns: ["\\+", "String.format", "StringBuilder.append"],
          check_context_types: true
        },
        context_analysis: %{
          check_directory_context: true,
          context_types: ["DirContext", "LdapContext", "InitialDirContext", "InitialLdapContext"],
          dangerous_operations: ["authentication", "authorization", "user_lookup", "group_membership"],
          check_naming_context: true
        },
        filter_analysis: %{
          check_filter_construction: true,
          filter_patterns: ["filter", "Filter", "searchFilter", "ldapFilter"],
          dangerous_concatenation: true,
          ldap_special_chars: ["(", ")", "*", "\\", "&", "|", "!", "=", "<", ">", "~", "%00"],
          check_boolean_logic: true
        },
        auth_analysis: %{
          check_authentication_bypass: true,
          bind_operations: ["bind", "authenticate", "login"],
          dn_construction: ["dn", "DN", "userDN", "baseDN", "principalDN"],
          check_credential_handling: true,
          auth_contexts: ["authentication", "authorization", "access_control"]
        }
      },
      context_rules: %{
        check_input_sanitization: true,
        escape_functions: [
          "LdapEncoder.filterEncode",
          "LdapEncoder.nameEncode", 
          "LdapUtils.escapeLdapSearchFilter",
          "StringEscapeUtils.escapeLdap",
          "escapeLDAPSearchFilter",
          "escapeFilterValue"
        ],
        ldap_injection_indicators: [
          "string_concatenation_with_user_input",
          "unescaped_special_characters",
          "direct_filter_construction",
          "unsafe_dn_building"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/],
        check_framework_usage: true,
        safe_frameworks: ["Spring LDAP", "Apache Directory", "UnboundID LDAP SDK"],
        high_risk_contexts: ["authentication", "authorization", "user management", "directory search", "access control"]
      },
      confidence_rules: %{
        base: 0.9,
        adjustments: %{
          "has_input_escaping" => -0.7,
          "uses_parameterized_queries" => -0.8,
          "uses_safe_framework" => -0.5,
          "in_authentication_context" => 0.2,
          "has_user_input" => 0.1,
          "in_web_context" => 0.1,
          "complex_filter_construction" => 0.1,
          "in_test_code" => -0.5,
          "is_commented_out" => -0.9,
          "has_input_validation" => -0.3,
          "uses_allowlist_validation" => -0.4
        }
      },
      min_confidence: 0.8
    }
  end
end
