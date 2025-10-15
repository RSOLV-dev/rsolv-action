defmodule Rsolv.Security.Patterns.Ruby.LdapInjection do
  @moduledoc """
  Pattern for detecting LDAP injection vulnerabilities in Ruby applications.

  This pattern identifies when user input is directly interpolated into LDAP
  queries or distinguished names, allowing attackers to manipulate LDAP
  operations and potentially bypass authentication or access unauthorized data.

  ## Vulnerability Details

  LDAP injection occurs when applications construct LDAP queries using
  unsanitized user input. This vulnerability is particularly dangerous in
  authentication systems where LDAP is commonly used for user verification.
  Unlike databases, LDAP systems often lack robust access controls, making
  successful injection attacks highly impactful.

  ### Attack Example
  ```ruby
  # Vulnerable LDAP authentication
  class AuthenticationController < ApplicationController
    def authenticate
      username = params[:username]  # User input: "admin)(|(objectClass=*"
      password = params[:password]  # User input: "anything"

      # VULNERABLE: Direct interpolation into LDAP filter
      filter = "(\\&(uid=\#{username})(userPassword=\#{password}))"
      # Results in: (&(uid=admin)(|(objectClass=*)(userPassword=anything))
      # This changes query logic to match any object class, bypassing auth

      ldap = Net::LDAP.new(host: 'ldap.company.com')
      result = ldap.search(filter: filter)

      if result.any?
        session[:user_id] = result.first.uid
        redirect_to dashboard_path
      end
    end
  end

  # Attack result: Authentication bypass without valid credentials
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "ruby-ldap-injection",
      name: "LDAP Injection",
      description: "Detects LDAP queries with unsanitized user input",
      type: :ldap_injection,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/Net::LDAP::Filter\.construct\s*\(\s*['\"].*?#\{/,
        ~r/\.search\s*\(.*?:filter\s*=>\s*['\"].*?#\{/,
        ~r/\.search\s*\(.*?filter:\s*['\"].*?#\{/,
        ~r/(?:ldap_search|search_ldap|find_ldap_entry|perform_ldap_search)\s*\(\s*['\"].*?#\{/,
        ~r/\.auth\s*\(\s*['\"].*?#\{/,
        ~r/\.authenticate\s*\(\s*['\"].*?#\{/
      ],
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation:
        "Use Net::LDAP::Filter.escape() to sanitize user input or Net::LDAP::Filter.eq() for safe filter construction",
      test_cases: %{
        vulnerable: [
          ~S|Net::LDAP::Filter.construct("(uid=#{username})")|,
          ~S|ldap.search(filter: "(cn=#{params[:name]})")|,
          ~S|ldap.auth("uid=#{user},ou=people,dc=example,dc=com", password)|,
          ~S|search_filter = "(memberOf=#{group_dn})"|
        ],
        safe: [
          ~S|filter = Net::LDAP::Filter.eq("uid", username)|,
          ~S|escaped_name = Net::LDAP::Filter.escape(user_input)|,
          ~S|ldap.search(filter: Net::LDAP::Filter.eq("cn", name))|,
          ~S|ldap.auth("cn=admin,dc=example,dc=com", password)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      LDAP injection is a security vulnerability that occurs when an application
      constructs LDAP queries using unsanitized user input. This allows attackers
      to modify the intended LDAP query logic and potentially bypass authentication,
      access unauthorized data, or modify directory information.

      **How LDAP Injection Works:**
      LDAP (Lightweight Directory Access Protocol) uses a specific filter syntax
      for querying directory services. When user input is directly interpolated
      into LDAP filters or distinguished names, attackers can inject malicious
      LDAP syntax that changes the query behavior.

      **Ruby LDAP Libraries Affected:**
      - **Net::LDAP**: Most popular Ruby LDAP library
      - **ruby-ldap**: Older Ruby LDAP bindings
      - **ActiveLdap**: ActiveRecord-style LDAP library
      - **Ladle**: LDAP server implementation in Ruby

      **Why LDAP Injection is Critical:**
      LDAP systems are commonly used for authentication and authorization,
      making successful attacks particularly severe:
      - **Authentication Bypass**: Modify login filters to always return true
      - **Privilege Escalation**: Access admin accounts or elevated permissions
      - **Data Extraction**: Retrieve sensitive directory information
      - **Directory Modification**: In some cases, modify or delete LDAP entries

      **Common Attack Patterns:**
      - **Boolean logic manipulation**: Use `)(|(objectClass=*` to create OR conditions
      - **Comment injection**: Use `#` or null bytes to terminate filters early
      - **Wildcard abuse**: Use `*` to match any value in authentication
      - **Parenthesis manipulation**: Close/open filters to change query structure

      **Ruby-Specific Vulnerabilities:**
      The FluidAttacks research demonstrates how Ruby applications using Net::LDAP
      are particularly vulnerable when constructing filters with string interpolation.
      The Net::LDAP::Filter.escape() method provides proper protection but is
      often overlooked by developers.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-90",
          title:
            "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
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
          id: "owasp_ldap_injection_prevention",
          title: "OWASP LDAP Injection Prevention Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "fluidattacks_ruby_ldap",
          title: "FluidAttacks - LDAP Injection in Ruby",
          url: "https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-ruby-107"
        },
        %{
          type: :research,
          id: "net_ldap_docs",
          title: "Net::LDAP Filter Documentation",
          url: "https://www.rubydoc.info/gems/ruby-net-ldap/Net/LDAP/Filter"
        }
      ],
      attack_vectors: [
        "Authentication bypass: username = 'admin)(|(objectClass=*' to create always-true condition",
        "Privilege escalation: inject filters to match administrative accounts",
        "Data extraction: use wildcard matching to enumerate directory entries",
        "Boolean logic manipulation: inject OR conditions to bypass restrictions",
        "Comment injection: use # or null bytes to terminate filter processing",
        "Parenthesis manipulation: close/open filters to change query structure",
        "Attribute enumeration: inject conditions to discover available attributes",
        "Distinguished name manipulation: modify DN construction for unauthorized access",
        "Filter concatenation: chain multiple conditions to expand query scope",
        "Wildcard injection: use * patterns to match broader sets of entries"
      ],
      real_world_impact: [
        "FluidAttacks research: Net::LDAP filter construction vulnerabilities in Ruby applications",
        "JumpCloud GitHub example: Vulnerable memberOf filter construction with string interpolation",
        "OWASP documentation: LDAP injection attacks in enterprise authentication systems",
        "Corporate directory systems: Unauthorized access to employee information",
        "Active Directory attacks: Privilege escalation through LDAP filter manipulation",
        "Authentication bypasses: Login systems using LDAP for user verification",
        "Enterprise applications: Unauthorized access to business-critical directory data",
        "Identity management systems: Compromise of centralized user authentication"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-8813",
          description: "LDAP injection in cacti network monitoring tool",
          severity: "high",
          cvss: 8.8,
          note: "LDAP authentication bypass through filter injection"
        },
        %{
          id: "CVE-2019-11510",
          description: "LDAP injection in Pulse Connect Secure",
          severity: "critical",
          cvss: 9.8,
          note: "Authentication bypass and arbitrary file reading via LDAP injection"
        },
        %{
          id: "CVE-2018-15473",
          description: "OpenSSH LDAP authentication bypass",
          severity: "high",
          cvss: 7.4,
          note: "Username enumeration via LDAP injection timing attacks"
        }
      ],
      detection_notes: """
      This pattern detects LDAP injection by looking for Ruby LDAP libraries
      combined with string interpolation in filter construction:

      **Primary Detection Points:**
      - Net::LDAP::Filter.construct() with interpolated strings
      - .search() method calls with filter: parameter and interpolation
      - .auth() and .authenticate() method calls with DN interpolation
      - Custom LDAP search functions with interpolation

      **Ruby Libraries Covered:**
      - Net::LDAP (most common): Filter construction and search operations
      - Custom LDAP wrapper functions: ldap_search, find_ldap_entry, etc.
      - Authentication methods: .auth(), .authenticate()
      - Search operations: .search() with filter parameters

      **False Positive Considerations:**
      - Static LDAP filters without user input (lower risk)
      - Properly escaped input using Net::LDAP::Filter.escape()
      - Safe filter construction using Net::LDAP::Filter.eq()
      - LDAP operations in test files (excluded by AST enhancement)

      **Detection Limitations:**
      - Complex filter building across multiple lines
      - LDAP queries built through method chaining
      - Dynamic method calls or metaprogramming
      - Non-standard LDAP library usage
      """,
      safe_alternatives: [
        "Safe filter construction: Net::LDAP::Filter.eq('uid', username)",
        "Input escaping: Net::LDAP::Filter.escape(user_input) before interpolation",
        "Parameterized filters: Use filter objects instead of string construction",
        "Input validation: Validate user input against known safe patterns",
        "Whitelist approach: Only allow predefined values for filter components",
        "DN validation: Validate distinguished names before use in authentication",
        "Library methods: Use Net::LDAP::Filter convenience methods (eq, present, etc.)",
        "Structured queries: Build filters programmatically rather than string concatenation"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing LDAP is inherently safer than SQL databases",
          "Not understanding LDAP filter syntax and injection points",
          "Using string concatenation instead of interpolation (equally dangerous)",
          "Assuming client-side validation prevents LDAP injection",
          "Not escaping special LDAP characters: *, (, ), \\, /, NUL",
          "Trusting internal systems without proper input validation",
          "Using LDAP for authorization without proper access controls",
          "Not implementing proper error handling that might leak information"
        ],
        secure_patterns: [
          "Net::LDAP::Filter.eq('uid', username) # Safe equality filter",
          "escaped_input = Net::LDAP::Filter.escape(user_input) # Proper escaping",
          "filter = Net::LDAP::Filter.eq('cn', name) & Net::LDAP::Filter.eq('ou', unit) # Chained filters",
          "Net::LDAP::Filter.present('objectClass') # Safe presence check",
          "Net::LDAP::Filter.substring('cn', nil, ['*', escaped_input, '*']) # Safe substring",
          "ldap.auth('cn=admin,dc=example,dc=com', password) # Static DN"
        ],
        ruby_specific: %{
          vulnerable_patterns: [
            "Net::LDAP::Filter.construct(\"(uid=\#{username})\") - Direct interpolation",
            "ldap.search(filter: \"(cn=\#{name})\") - Search with interpolation",
            "ldap.auth(\"uid=\#{user},ou=people,dc=example,dc=com\", pass) - DN interpolation",
            "search_filter = \"(memberOf=\#{group_dn})\" - Filter variable assignment",
            "filter_string = \"(\\&(objectClass=person)(mail=\#{email}))\" - Complex filter"
          ],
          safe_alternatives: [
            "Net::LDAP::Filter.eq('uid', username) - Safe equality construction",
            "Net::LDAP::Filter.escape(user_input) - Proper input escaping",
            "ldap.search(filter: Net::LDAP::Filter.eq('cn', name)) - Safe search",
            "Net::LDAP::Filter.present('objectClass') - Safe presence check",
            "filter = Net::LDAP::Filter.substring('cn', nil, ['*', escaped, '*']) - Safe substring"
          ],
          libraries: [
            "Net::LDAP: Most popular, has built-in escaping methods",
            "ruby-ldap: Lower-level bindings, requires manual escaping",
            "ActiveLdap: ActiveRecord-style, better safety by default",
            "Ladle: LDAP server implementation, less client-side risk"
          ]
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual LDAP injection vulnerabilities
  and safe LDAP usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.LdapInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Ruby.LdapInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: [
          "construct",
          "search",
          "auth",
          "authenticate",
          "ldap_search",
          "search_ldap",
          "find_ldap_entry",
          "perform_ldap_search"
        ],
        receiver_analysis: %{
          check_ldap_context: true,
          libraries: ["Net::LDAP", "LDAP", "ActiveLdap"],
          ldap_indicators: ["ldap", "directory", "auth", "filter"]
        },
        argument_analysis: %{
          check_ldap_syntax: true,
          detect_interpolation: true,
          ldap_pattern: ~r{\([\w=*()&|!]+\)},
          interpolation_pattern: ~r/#\{[^}]+\}/,
          dn_pattern: ~r{[\w]+=[\w\s,]+}
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/docs/
        ],
        check_ldap_context: true,
        safe_functions: [
          "Net::LDAP::Filter.escape",
          "Net::LDAP::Filter.eq",
          "Net::LDAP::Filter.present",
          "Net::LDAP::Filter.substring",
          "Net::LDAP::Filter.ge",
          "Net::LDAP::Filter.le"
        ],
        dangerous_sources: [
          "params",
          "request",
          "cookies",
          "session",
          "ENV",
          "gets",
          "ARGV",
          "user_input",
          "form_data",
          "query_params"
        ],
        ldap_specific: %{
          safe_methods_preferred: true,
          static_filters_safe: true,
          check_escape_usage: true,
          require_interpolation_for_danger: true
        }
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "contains_user_input" => 0.4,
          "uses_interpolation" => 0.3,
          "ldap_syntax_detected" => 0.2,
          "ldap_library_context" => 0.15,
          "uses_filter_methods" => -0.9,
          "uses_escape_function" => -0.9,
          "static_ldap_only" => -0.7,
          "in_test_code" => -1.0,
          "proper_escaping" => -0.8,
          "whitelisted_values" => -0.6
        }
      },
      min_confidence: 0.75
    }
  end
end
