defmodule Rsolv.Security.Patterns.Javascript.XpathInjection do
  @moduledoc """
  Detects XPath injection vulnerabilities in JavaScript/TypeScript code.

  XPath injection occurs when untrusted user input is concatenated into XPath queries
  without proper sanitization. Attackers can modify query logic to bypass security
  controls or extract sensitive data from XML documents.

  ## Vulnerability Details

  XPath is a query language for XML documents. Like SQL injection, XPath injection
  allows attackers to manipulate queries by injecting special characters and expressions.
  Common attack vectors include authentication bypass using logical operators and
  data extraction using XPath functions.

  ### Attack Example
  ```javascript
  // Vulnerable: Direct concatenation of user input
  const users = xpath.select("//user[username='" + username + "' and password='" + password + "']");

  // Attack input: admin' or '1'='1
  // Results in: //user[username='admin' or '1'='1' and password='...']
  // This returns all users, bypassing authentication
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the pattern definition for XPath injection detection.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Javascript.XpathInjection.pattern()
      iex> pattern.id
      "js-xpath-injection"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XpathInjection.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XpathInjection.pattern()
      iex> vulnerable = ~S|xpath.select("//user[name='" + username + "']")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XpathInjection.pattern()
      iex> safe = ~S|xpath.select("//user[name=$username]", {username: sanitizeInput(username)})|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-xpath-injection",
      name: "XPath Injection",
      description:
        "XPath queries constructed with user input can be manipulated to extract unauthorized data or bypass authentication",
      type: :xpath_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Detects XPath query construction with user input via concatenation or template literals
      regex: ~r/
        # XPath method calls with concatenation
        (?:xpath|xml|doc)\.(?:select|evaluate|selectNodes|selectSingleNode)\s*\(
        .*?
        (?:
          # String concatenation - but not function calls like escape()
          ["']\s*\+\s*(?!escape|sanitize)[a-zA-Z_][\w\.]*
          |
          # Template literal with ${variable} - but not function calls
          \$\{(?!escape|sanitize)[^}]+\}
        )
        .*?
        \)\s*(?:,|\)|$)
      /x,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation:
        "Use parameterized XPath queries or properly escape special characters. Never concatenate user input directly into XPath expressions.",
      test_cases: %{
        vulnerable: [
          ~S|xpath.select("//user[name='" + username + "']")|,
          ~S|doc.evaluate("/users/user[@id='" + userId + "']", doc)|,
          ~S|xml.selectNodes("//product[price<" + maxPrice + "]")|,
          ~S|xpath.select(`//user[@id='${userId}']`)|,
          ~S|doc.evaluate(`/books/book[author="${req.query.author}"]`, doc)|,
          ~S|xpath.evaluate("//user[email='" + req.body.email + "']")|
        ],
        safe: [
          ~S|xpath.select("//user[name=$username]", {username: sanitizeInput(username)})|,
          ~S|const query = xpath.compile("//user[@id=$id]"); query.select({id: userId})|,
          ~S|xpath.select("//product[price<$price]", {price: parseFloat(maxPrice)})|,
          ~S|doc.evaluate("//user[@id='12345']", doc)|,
          ~S|xpath.select("//user[name=?]", [escapeXPath(username)])|
        ]
      }
    }
  end

  @doc """
  Returns comprehensive vulnerability metadata for XPath injection.
  """
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XPath injection is a vulnerability where attackers can inject malicious XPath
      expressions into applications that construct XPath queries from user input.
      This can lead to unauthorized data access, authentication bypass, and 
      information disclosure from XML documents.

      XPath uses special characters and functions that must be properly handled:
      - Single and double quotes: ' and " - String delimiters
      - Square brackets: [ and ] - Predicate expressions
      - Slash: / - Path separator
      - At sign: @ - Attribute selector
      - Functions: text(), node(), position(), etc.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-643",
          title: "Improper Neutralization of Data within XPath Expressions",
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
          title: "OWASP XPath Injection",
          url: "https://owasp.org/www-community/attacks/XPATH_Injection"
        },
        %{
          type: :research,
          id: "xpath_injection_prevention",
          title: "XML Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Authentication bypass: username=' or '1'='1",
        "Data extraction: '] | //user/password | //user[username='",
        "Union attacks: '] | //creditcard/number | //user[name='",
        "Blind injection: ' and substring(//user[1]/password,1,1)='a",
        "Error-based: '] | error() | //user[name='",
        "Function abuse: ' or count(//user)>0 or '"
      ],
      real_world_impact: [
        "Complete authentication bypass",
        "Unauthorized access to entire XML document structure",
        "Extraction of sensitive data from any XML node",
        "Information disclosure about XML schema",
        "Potential for data modification in writable XML stores",
        "Denial of service through expensive XPath operations"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-40318",
          description: "XPath injection in Umbraco CMS allowing information disclosure",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates how XPath injection can expose sensitive CMS data"
        },
        %{
          id: "CVE-2019-12418",
          description: "Apache Fineract XPath injection vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Shows XPath injection leading to data extraction in financial software"
        },
        %{
          id: "CVE-2021-23440",
          description: "XPath injection in xmldom package for Node.js",
          severity: "high",
          cvss: 8.1,
          note: "JavaScript-specific XPath injection in popular npm package"
        }
      ],
      detection_notes: """
      This pattern detects XPath injection by looking for:
      1. XPath query methods (select, evaluate, selectNodes) with string concatenation
      2. User input concatenated into XPath expressions using + operator
      3. Template literals with interpolated user input in XPath contexts
      4. Common XPath syntax patterns combined with user input sources

      The pattern focuses on JavaScript/Node.js XPath libraries and DOM methods.
      """,
      safe_alternatives: [
        "Use parameterized XPath queries: xpath.select('//user[name=$name]', {name: input})",
        "Escape special characters: ' -> &apos;, \" -> &quot;",
        "Use XPath variable binding when available",
        "Validate input against strict patterns before use",
        "Consider using XPath 2.0 with proper variable support",
        "Use query builders that handle escaping automatically",
        "Implement allowlists for acceptable XPath expressions"
      ],
      additional_context: %{
        common_mistakes: [
          "Only escaping quotes but not other XPath metacharacters",
          "Trusting numeric input without validation",
          "Not considering XPath functions in attack payloads",
          "Assuming XML parsers provide automatic escaping",
          "Using blacklist filtering instead of proper escaping"
        ],
        secure_patterns: [
          "Always use parameterized queries when available",
          "Escape all XPath special characters, not just quotes",
          "Validate data types (numbers, booleans) before use",
          "Use XPath libraries with built-in security features",
          "Log and monitor XPath queries for suspicious patterns"
        ],
        xpath_special_chars: %{
          string_delimiters: ["'", "\""],
          operators: ["=", "!=", "<", ">", "<=", ">="],
          path_chars: ["/", "//", "@", "::"],
          logic_operators: ["and", "or", "not()"],
          wildcards: ["*", "node()", "text()"]
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual XPath injection vulnerabilities and:
  - Parameterized XPath queries with proper variable binding
  - Pre-compiled XPath expressions
  - Escaped XPath expressions
  - XPath builder libraries with automatic escaping
  - Static XPath queries without user input

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.XpathInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XpathInjection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XpathInjection.ast_enhancement()
      iex> enhancement.ast_rules.argument_analysis.has_xpath_expression
      true
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XpathInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XpathInjection.ast_enhancement()
      iex> "uses_parameterized_xpath" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        # XPath evaluation methods
        callee_patterns: [
          ~r/xpath\.(select|evaluate)/,
          ~r/doc\.(evaluate|selectNodes|selectSingleNode)/,
          ~r/xml.*\.(select|evaluate)/
        ],
        # XPath expression must have user input
        argument_analysis: %{
          has_xpath_expression: true,
          contains_user_input: true,
          uses_string_building: true,
          not_parameterized: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        # xpath.select(expr, params)
        exclude_if_parameterized: true,
        # XPath escaping
        exclude_if_escaped: true,
        # Pre-compiled XPath
        exclude_if_compiled: true,
        safe_xpath_patterns: ["xpath.compile", "createExpression"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "direct_string_concat_xpath" => 0.5,
          "template_literal_xpath" => 0.4,
          "user_controlled_predicate" => 0.4,
          "uses_parameterized_xpath" => -0.9,
          "pre_compiled_expression" => -0.8,
          "xpath_builder_library" => -0.7,
          "static_xpath_only" => -1.0
        }
      },
      min_confidence: 0.8
    }
  end
end
