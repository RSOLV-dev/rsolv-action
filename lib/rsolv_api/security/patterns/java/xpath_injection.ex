defmodule RsolvApi.Security.Patterns.Java.XpathInjection do
  @moduledoc """
  XPath Injection pattern for Java code.
  
  Detects XPath injection vulnerabilities where user input is concatenated directly
  into XPath queries. This can lead to authentication bypass, data extraction, and
  in some cases (like JXPath) remote code execution.
  
  ## Vulnerability Details
  
  XPath injection occurs when untrusted user input is incorporated into XPath queries
  through string concatenation. Attackers can inject XPath syntax to:
  - Bypass authentication (e.g., injecting `' or '1'='1`)
  - Extract sensitive data from XML documents
  - Perform blind data extraction through boolean/time-based techniques
  - In cases like JXPath (CVE-2022-41852), achieve remote code execution
  
  ### Attack Example
  
  ```java
  // Vulnerable authentication check
  String xpath = "//user[username='" + username + "' and password='" + password + "']";
  XPath xPath = XPathFactory.newInstance().newXPath();
  Node user = (Node) xPath.evaluate(xpath, doc, XPathConstants.NODE);
  
  // Attack: username = admin' or '1'='1
  // Results in: //user[username='admin' or '1'='1' and password='...']
  // Returns first user, bypassing authentication
  ```
  
  ## References
  
  - CWE-643: Improper Neutralization of Data within XPath Expressions
  - OWASP A03:2021 - Injection
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-xpath-injection",
      name: "XPath Injection",
      description: "String concatenation in XPath expressions",
      type: :xpath_injection,
      severity: :high,
      languages: ["java"],
      regex: [
        # xpath.evaluate with concatenation
        ~r/xpath\.evaluate\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/im,
        # xpath.compile with concatenation
        ~r/xpath\.compile\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/im,
        # selectNodes/selectSingleNode with concatenation
        ~r/\.select(?:Nodes|SingleNode)\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/,
        # evaluate with XPathConstants
        ~r/\.evaluate\s*\(\s*[^)]*["'][^"']*["']\s*\+[^),]*,[^)]*XPathConstants\.[A-Z]+\s*\)/,
        # JXPath methods (CVE-2022-41852)
        ~r/JXPathContext\.(?:getValue|iterate|selectNodes)\s*\([^)]*\)/,
        ~r/\.getValue\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/,
        # JXPath with variable input (dangerous when xpath comes from user)
        ~r/JXPathContext\.newContext\([^)]*\)\.(?:getValue|iterate|selectNodes)\s*\(\s*\w+\s*\)/,
        # JXPath iterate/selectNodes with concatenation
        ~r/\.(?:iterate|selectNodes)\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/,
        # XPath with text() or count() functions (blind injection indicators)
        ~r/xpath\.evaluate\s*\(\s*[^)]*(?:text\(\)|count\(|position\(|string-length\()[^)]*\+[^)]*\)/,
        # Variable assignment with XPath concatenation
        ~r/String\s+\w+\s*=\s*["'][^"']*(?:\/\/|\[@|text\(\)|count\()[^"']*["']\s*\+/
      ],
      default_tier: :protected,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized XPath with variable resolvers or sanitize input",
      test_cases: %{
        vulnerable: [
          ~S|XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate("//user[name='" + username + "']", doc);|,
          ~S|xpath.compile("//product[@id='" + productId + "']");|,
          ~S|document.selectNodes("//user[id='" + userId + "']");|,
          ~S|JXPathContext.getValue(userXPath);|
        ],
        safe: [
          ~S|// Use XPath variables
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(resolver);
xpath.evaluate("//user[name=$username]", doc);|,
          ~S|// Static XPath expression
xpath.evaluate("//users/user[@role='admin']", document);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XPath injection occurs when untrusted data is concatenated into XPath queries without
      proper sanitization. XPath is a language for navigating XML documents, similar to how
      SQL queries databases. When user input is directly embedded in XPath expressions,
      attackers can manipulate the query logic to bypass security controls, extract sensitive
      data, or in some implementations like JXPath, execute arbitrary code.
      
      The vulnerability is particularly dangerous in authentication systems where XPath is
      used to validate credentials against XML-based user stores. Attackers can inject
      boolean logic to bypass authentication entirely.
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
          type: :research,
          id: "xpath_injection_owasp",
          title: "XPATH Injection - OWASP",
          url: "https://owasp.org/www-community/attacks/XPATH_Injection"
        },
        %{
          type: :research,
          id: "blind_xpath_owasp",
          title: "Blind XPath Injection - OWASP",
          url: "https://owasp.org/www-community/attacks/Blind_XPath_Injection"
        },
        %{
          type: :tool,
          id: "codeql_xpath",
          title: "XPath injection — CodeQL",
          url: "https://codeql.github.com/codeql-query-help/java/java-xml-xpath-injection/"
        }
      ],
      attack_vectors: [
        "Authentication bypass: username = admin' or '1'='1",
        "Data extraction: ' or //user/password/text() or '",
        "Blind extraction: ' or substring(//user[1]/password,1,1)='a",
        "Error-based extraction: ' or name(//user/*[1])='password' or '",
        "Union attacks: ' | //confidential/data | '",
        "Function injection in JXPath: java.lang.Thread.sleep(10000)",
        "Boolean-based blind: ' or count(//user)>0 or '",
        "Time-based blind (JXPath): ' or java.lang.Thread.sleep(5000) or '"
      ],
      real_world_impact: [
        "Complete authentication bypass in XML-based login systems",
        "Extraction of entire XML documents including sensitive data",
        "Privilege escalation by modifying query logic",
        "Remote code execution in JXPath implementations",
        "Data integrity compromise through unauthorized access",
        "Compliance violations from data exposure (GDPR, PCI-DSS)"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-39565",
          description: "XPath injection in Juniper Networks Junos OS J-Web allowing RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Unauthenticated network attacker can execute remote commands via XPath injection"
        },
        %{
          id: "CVE-2022-41852",
          description: "Remote code execution in Apache Commons JXPath",
          severity: "critical",
          cvss: 9.8,
          note: "All JXPathContext methods processing XPath strings allow arbitrary code execution"
        },
        %{
          id: "CVE-2024-36401",
          description: "GeoServer XPath injection via commons-jxpath leading to RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Critical RCE in GeoServer versions prior to 2.23.6, 2.24.4"
        },
        %{
          id: "CVE-2022-46464",
          description: "ConcreteCMS v9.1.3 XPath injection allowing data access",
          severity: "high",
          cvss: 7.5,
          note: "Allows attackers to access sensitive XML data through XPath injection"
        }
      ],
      detection_notes: """
      This pattern detects various forms of XPath injection in Java:
      - Direct string concatenation in evaluate() and compile() methods
      - DOM selectNodes/selectSingleNode with user input
      - JXPath usage which is particularly dangerous (allows RCE)
      - Blind injection patterns using text(), count(), position() functions
      - Variable assignments building dynamic XPath expressions
      
      The pattern looks for the + operator near XPath-specific syntax to identify
      concatenation of user input into queries.
      """,
      safe_alternatives: [
        "Use XPath variable resolvers: xpath.setXPathVariableResolver(resolver)",
        "Parameterize queries: evaluate('//user[name=$username]', doc)",
        "Use allowlisting for dynamic node/attribute names if needed",
        "Sanitize input by escaping XPath special characters (' \" [ ] @ * /)",
        "Consider using XQuery with proper parameterization",
        "For JXPath, upgrade to patched versions or avoid entirely",
        "Use schema validation to restrict XML structure",
        "Implement least-privilege access to XML data"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that escaping quotes is sufficient (it's not)",
          "Using string replacement instead of proper parameterization",
          "Trusting input from authenticated users",
          "Not considering blind injection techniques",
          "Using vulnerable libraries like unpatched JXPath"
        ],
        secure_patterns: [
          "Always use XPath variables with resolvers",
          "Never concatenate user input into XPath strings",
          "Validate against an XML schema before querying",
          "Use static XPath expressions where possible",
          "Implement proper access controls at the application layer"
        ],
        blind_techniques: [
          "Boolean-based: Extracting data bit by bit using true/false conditions",
          "Error-based: Forcing errors to reveal information",
          "Time-based: Using delays to infer data (JXPath specific)",
          "Out-of-band: DNS/HTTP requests to exfiltrate data"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual XPath injection vulnerabilities
  and safe XPath usage patterns like static queries or properly parameterized expressions.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.XpathInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.XpathInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.XpathInjection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        xpath_analysis: %{
          check_method_name: true,
          xpath_methods: [
            "evaluate", "compile", "selectNodes", "selectSingleNode",
            "getValue", "iterate", "getPointer"
          ],
          check_string_concatenation: true,
          check_parameterization: true
        },
        concatenation_analysis: %{
          check_operators: true,
          dangerous_operators: ["+", "concat", "StringBuilder.append", "String.format"],
          check_xpath_context: true,
          xpath_indicators: ["//", "/@", "[", "]", "text()", "count()", "position()"]
        },
        variable_analysis: %{
          check_user_input_sources: true,
          input_sources: [
            "getParameter", "getHeader", "getCookie", "getQueryString",
            "getInputStream", "getReader", "getUserInput"
          ],
          check_variable_flow: true
        }
      },
      context_rules: %{
        check_variable_resolver: true,
        safe_resolver_patterns: [
          "setXPathVariableResolver",
          "XPathVariableResolver",
          "$variable"
        ],
        parameterized_xpath_indicators: [
          ~r/\$\w+/,  # XPath variables like $username
          ~r/:\w+/    # Named parameters
        ],
        exclude_static_xpath: true,
        static_indicators: [
          "No concatenation operators",
          "Constant string only",
          "No method calls in expression"
        ],
        jxpath_detection: [
          "JXPathContext",
          "commons-jxpath",
          "org.apache.commons.jxpath"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_string_concatenation" => 0.3,
          "has_user_input_source" => 0.3,
          "contains_xpath_syntax" => 0.2,
          "uses_jxpath" => 0.4,  # Higher risk due to RCE
          "has_variable_resolver" => -0.6,
          "uses_parameterized_xpath" => -0.7,
          "is_static_expression" => -0.8,
          "in_test_code" => -0.5
        }
      },
      min_confidence: 0.7
    }
  end
end