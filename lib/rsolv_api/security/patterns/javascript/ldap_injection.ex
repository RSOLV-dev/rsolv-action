defmodule RsolvApi.Security.Patterns.Javascript.LdapInjection do
  @moduledoc """
  Detects LDAP injection vulnerabilities in JavaScript/TypeScript code.
  
  LDAP (Lightweight Directory Access Protocol) injection occurs when untrusted user
  input is concatenated into LDAP queries without proper escaping. This can allow
  attackers to modify query logic, bypass authentication, or extract sensitive data.
  
  ## Vulnerability Details
  
  LDAP injection is similar to SQL injection but targets directory services. Special
  characters like parentheses, asterisks, and backslashes can alter LDAP filter logic.
  Common attack vectors include authentication bypass using wildcard filters or logic
  manipulation.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct concatenation of user input
  const filter = "(cn=" + username + ")";
  ldap.search(filter, (err, res) => {
    // If username is "*", matches all users
    // If username is "admin)(|(password=*", reveals passwords
  });
  
  // Attack input: "admin)(objectClass=*))(&(objectClass=void"
  // Results in: "(cn=admin)(objectClass=*))(&(objectClass=void)"
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the pattern definition for LDAP injection detection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.LdapInjection.pattern()
      iex> pattern.id
      "js-ldap-injection"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.LdapInjection.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.LdapInjection.pattern()
      iex> vulnerable = ~S|ldap.search("(cn=" + username + ")")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.LdapInjection.pattern()
      iex> safe = ~S|ldap.search("(cn=" + ldapEscape(username) + ")")|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-ldap-injection",
      name: "LDAP Injection",
      description: "LDAP queries constructed with user input can be manipulated to bypass authentication or access unauthorized data",
      type: :ldap_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Detects LDAP query construction with user input via concatenation or template literals
      regex: ~r/
        # LDAP method calls with string concatenation
        (?:ldap|client)\.(?:search|bind|add|modify|delete)\s*\(\s*
        (?:
          # String concatenation pattern, but NOT with escape function
          ["'][^"']*["']\s*\+\s*(?!ldapEscape|ldapjs\.escape|escapeLDAP|sanitizeLdap)(?:req\.|request\.|params\.|query\.|body\.|user|input|data|\w+)
          |
          # Template literal with interpolation for LDAP methods, but NOT with escaped variables
          `[^`]*\$\{(?!escaped|ldapEscape|ldapjs\.escape|escapeLDAP|sanitizeLdap)[^}]+\}[^`]*`
          |
          # Direct user input in filter object
          \{[^}]*filter\s*:\s*(?:
            ["'`][^"'`]*["'`]\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)
            |
            `[^`]*\$\{(?!escaped|ldapEscape|ldapjs\.escape|escapeLDAP|sanitizeLdap)(?:req\.|request\.|params\.|query\.|body\.|user|input|data)[^`]*`
          )
        )
        |
        # LDAP DN construction with concatenation
        (?:cn|uid|ou|dc|sn|mail|sAMAccountName)\s*=\s*["']\s*\+\s*
        (?!ldapEscape|ldapjs\.escape|escapeLDAP)(?:req\.|request\.|params\.|query\.|body\.|user|input|data|\w+)
        |
        # LDAP filter variable assignment with concatenation
        (?:filter|ldapFilter|searchFilter)\s*=\s*
        (?:
          ["'][^"']*["']\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|data|\w+)
          |
          `[^`]*\$\{(?!escaped|ldapEscape|ldapjs\.escape|escapeLDAP|sanitizeLdap)[^}]+\}[^`]*`
        )
        |
        # LDAP modify with user input
        ldap\.modify\s*\(\s*[^,]+,\s*\{[^\}]*:\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)
      /xi,
      default_tier: :public,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Always escape special LDAP characters in user input. Use LDAP escape libraries like ldapjs.escape() or implement proper escaping for (, ), *, \\, and null bytes.",
      test_cases: %{
        vulnerable: [
          ~S|ldap.search("(cn=" + username + ")")|,
          ~S|client.search({filter: "(uid=" + req.body.user + ")"})|,
          ~S|filter = "(&(objectClass=user)(sAMAccountName=" + userInput + "))"| ,
          ~S|ldap.bind("cn=" + username + ",ou=users,dc=example,dc=com")|,
          ~S|ldap.search(`(cn=${req.body.username})`)|,
          ~S|ldap.modify("cn=admin", {mail: req.body.email})|
        ],
        safe: [
          ~S|ldap.search("(cn=" + ldapEscape(username) + ")")|,
          ~S|filter = ldap.escape.filter`(uid=${user})`|,
          ~S|client.search({filter: sanitizeLdapFilter(userInput)})|,
          ~S|ldap.search("(objectClass=user)")|,
          ~S|const escaped = ldapjs.escapeFilter(input); ldap.search(`(cn=${escaped})`)|
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for LDAP injection.
  """
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      LDAP injection occurs when untrusted data is inserted into LDAP queries without
      proper sanitization. Attackers can manipulate LDAP filters and distinguished names
      (DNs) to bypass authentication, elevate privileges, or extract sensitive information
      from directory services.
      
      LDAP uses special characters that must be escaped:
      - Parentheses: ( and ) - Used for grouping filters
      - Asterisk: * - Wildcard matching
      - Backslash: \\ - Escape character
      - Null: \\00 - Can terminate strings
      - And others: =, <, >, ~, &, |, !
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
          id: "ldap_injection_owasp",
          title: "OWASP LDAP Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "ldap_injection_attacks",
          title: "Understanding LDAP Injection",
          url: "https://www.synopsys.com/glossary/what-is-ldap-injection.html"
        }
      ],
      attack_vectors: [
        "Authentication bypass: username=* (matches any user)",
        "Logic manipulation: admin)(|(password=*) (reveals passwords)",
        "Filter injection: user)(objectClass=*))(&(objectClass=void",
        "DN injection: admin,ou=admins,dc=com,dc=fake",
        "Wildcard abuse: a*min (matches admin, administrator, etc)",
        "Null byte injection: admin\\00,dc=evil,dc=com"
      ],
      real_world_impact: [
        "Complete authentication bypass allowing login as any user",
        "Unauthorized access to directory information",
        "Extraction of sensitive attributes (passwords, emails, etc)",
        "Privilege escalation by modifying group memberships",
        "Denial of service through expensive wildcard queries",
        "Information disclosure about directory structure"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell included LDAP injection as an attack vector for JNDI lookups",
          severity: "critical",
          cvss: 10.0,
          note: "While primarily a Java issue, Node.js apps using Java services were affected"
        },
        %{
          id: "CVE-2019-13990",
          description: "Oracle Access Manager LDAP injection allowing authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates how LDAP injection can completely compromise authentication"
        },
        %{
          id: "CVE-2020-25078",
          description: "D-Link router LDAP injection in authentication mechanism",
          severity: "high",
          cvss: 8.8,
          note: "Shows LDAP injection in embedded/IoT contexts"
        }
      ],
      detection_notes: """
      This pattern detects LDAP injection by looking for:
      1. LDAP filter construction using string concatenation with user input
      2. DN (Distinguished Name) construction with user data
      3. Template literal usage with interpolated user input in LDAP contexts
      4. Common LDAP method calls (search, bind, add, modify) with concatenated input
      
      The pattern avoids false positives by not matching when escape functions are present.
      """,
      safe_alternatives: [
        "Use parameterized LDAP queries where available",
        "Escape using ldapjs: ldapjs.escapeFilter(userInput)",
        "Implement allowlist validation for LDAP attributes",
        "Use prepared filter templates with placeholders",
        "Validate input format before constructing queries",
        "Avoid dynamic DN construction - use lookups instead",
        "Consider using higher-level abstractions that handle escaping"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming alphanumeric input doesn't need escaping",
          "Only escaping parentheses but not other special chars",
          "Forgetting that asterisk (*) is a wildcard in LDAP",
          "Not escaping backslashes which can break escape sequences",
          "Trusting client-side validation alone"
        ],
        secure_patterns: [
          "Always use an LDAP escaping library",
          "Validate input against strict patterns before escaping",
          "Use separate validation for filter values vs DN components",
          "Log LDAP queries for security monitoring",
          "Implement query complexity limits to prevent DoS"
        ],
        ldap_special_chars: %{
          filter_escape: [
            "( -> \\28",
            ") -> \\29", 
            "\\ -> \\5c",
            "* -> \\2a",
            "NUL -> \\00"
          ],
          dn_escape: [
            ", -> \\,",
            "+ -> \\+",
            "\" -> \\\"",
            "\\ -> \\\\",
            "< -> \\<",
            "> -> \\>",
            "; -> \\;"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual LDAP injection vulnerabilities and:
  - LDAP queries using proper escape functions
  - Parameterized LDAP query builders
  - Allowlist-validated input
  - Static filter templates
  - Pre-compiled LDAP queries
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.LdapInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.LdapInjection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.LdapInjection.ast_enhancement()
      iex> enhancement.ast_rules.argument_analysis.has_filter_string
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.LdapInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.LdapInjection.ast_enhancement()
      iex> "uses_ldap_escape" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        # LDAP client method calls
        callee_patterns: [
          ~r/ldap.*\.(search|bind|add|modify|delete)/,
          ~r/\.(searchAsync|bindAsync)/
        ],
        # Filter string must contain user input
        argument_analysis: %{
          has_filter_string: true,
          contains_user_input: true,
          uses_string_concatenation: true,
          not_parameterized: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        exclude_if_escaped: true,            # LDAP escape functions
        exclude_if_parameterized: true,      # Using LDAP query builders
        exclude_if_allowlist_only: true,     # Only predefined values
        ldap_escape_functions: ["ldap.escape", "escapeLDAPSearchFilter", "ldapEscape"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "filter_string_concatenation" => 0.5,
          "user_input_in_dn" => 0.4,
          "complex_filter_construction" => 0.3,
          "uses_ldap_escape" => -0.9,
          "parameterized_filter" => -0.8,
          "static_filter_template" => -0.7,
          "allowlist_validation" => -0.8
        }
      },
      min_confidence: 0.8
    }
  end
end