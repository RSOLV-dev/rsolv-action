defmodule Rsolv.Security.Patterns.Ruby.XpathInjection do
  @moduledoc """
  Pattern for detecting XPath injection vulnerabilities in Ruby applications.

  This pattern identifies when user input is directly interpolated into XPath
  expressions, allowing attackers to manipulate XML queries and potentially
  extract unauthorized data from XML documents.

  ## Vulnerability Details

  XPath injection occurs when applications construct XPath queries using
  unsanitized user input. Unlike SQL injection which targets databases,
  XPath injection targets XML documents, but can be equally dangerous as
  it can bypass authentication, extract sensitive data, and potentially
  lead to denial of service attacks.

  ### Attack Example
  ```ruby
  # Vulnerable XPath query construction
  class UserController < ApplicationController
    def search
      username = params[:username]  # User input: "admin' or '1'='1"
      password = params[:password]  # User input: "anything"
      
      # VULNERABLE: Direct interpolation into XPath
      xpath = "//user[username='\#{username}' and password='\#{password}']"
      user = xml_doc.xpath(xpath).first
      # Results in: //user[username='admin' or '1'='1' and password='anything']
      # This bypasses authentication by making the condition always true
      
      if user
        session[:user_id] = user.attribute('id').value
        redirect_to dashboard_path
      end
    end
  end

  # Attack result: Authentication bypass
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "ruby-xpath-injection",
      name: "XPath Injection",
      description: "Detects XPath queries with user input interpolation",
      type: :xpath_injection,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/\.xpath\s*\(\s*['\"].*?#\{/,
        ~r/Nokogiri.*?\.xpath\s*\(\s*['\"].*?#\{/,
        ~r/REXML.*?\.elements\s*\[\s*['\"].*?#\{/,
        ~r/\.elements\[\s*['\"].*?#\{/,
        ~r/XPath(?:::)?(?:Parser)?\.parse\s*\(\s*['\"].*?#\{/,
        ~r/\w+\.parse\s*\(\s*['\"].*?#\{/,
        ~r/(?:find_by_xpath|select_xpath|query_xpath|get_xpath)\s*\(\s*['\"].*?#\{/
      ],
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation:
        "Use parameterized XPath queries or sanitize user input before XPath construction",
      test_cases: %{
        vulnerable: [
          ~S|doc.xpath("//user[name='#{params[:name]}']")|,
          ~S|xml.elements["//product[@id='#{id}']"]|,
          ~S|nokogiri.xpath("//item[@category='#{category}']")|,
          ~S|XPath::Parser.parse("//user[age>#{age}]")|
        ],
        safe: [
          ~S|doc.xpath("//user", name: params[:name])|,
          ~S|xml.xpath("//user[@name=$name]", nil, name: params[:name])|,
          ~S|doc.at_xpath("//user[@id=?]", params[:id])|,
          ~S|xml.elements["//static/path"]|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XPath injection is a security vulnerability that occurs when an application
      constructs XPath queries using unsanitized user input. This allows attackers
      to modify the intended XPath query logic and potentially access unauthorized
      data from XML documents.

      **How XPath Injection Works:**
      XPath (XML Path Language) is used to navigate and select nodes in XML documents.
      When user input is directly concatenated into XPath expressions, attackers can
      inject malicious XPath code that changes the query behavior.

      **Common Ruby XML Libraries Affected:**
      - **Nokogiri**: Most popular Ruby HTML/XML parser
      - **REXML**: Ruby's built-in XML library  
      - **LibXML**: Ruby bindings for libxml2
      - **XPath**: Direct XPath parsing libraries

      **Why XPath Injection is Dangerous:**
      Unlike databases with access controls, XML documents are typically
      fully accessible once an XPath injection is successful:
      - **No Access Controls**: XPath queries can access any part of XML document
      - **Authentication Bypass**: Modify login queries to always return true
      - **Data Extraction**: Access sensitive information stored in XML
      - **Denial of Service**: Complex XPath expressions can cause performance issues

      **Common Attack Patterns:**
      - **Authentication bypass**: `' or '1'='1` to make conditions always true
      - **Data extraction**: Use `or` conditions to extract additional nodes
      - **Blind injection**: Use functions like `string-length()` for data extraction
      - **Error-based injection**: Trigger XML parsing errors to reveal structure

      **Ruby-Specific Vulnerabilities:**
      The CVE-2015-20108 vulnerability in the ruby-saml gem demonstrated how
      XPath injection can lead to arbitrary code execution, making this a
      critical security concern for Ruby applications processing XML.
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
          id: "owasp_xpath_injection",
          title: "OWASP XPath Injection",
          url: "https://owasp.org/www-community/attacks/XPATH_Injection"
        },
        %{
          type: :research,
          id: "owasp_testing_xpath",
          title: "OWASP Testing Guide - XPath Injection",
          url:
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection"
        },
        %{
          type: :research,
          id: "xpath_cheat_sheet",
          title: "XPath Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Authentication bypass: username = 'admin' or '1'='1' to bypass login validation",
        "Data extraction: ' or name()='password' to extract sensitive element names",
        "Comment injection: ' or '1'='1' or 'a'=' to terminate XPath expression early",
        "Boolean-based blind injection: Use true/false conditions to extract data",
        "Error-based injection: Trigger XML parsing errors to reveal document structure",
        "Function abuse: Use XPath functions like count(), string-length() for data extraction",
        "Union-style injection: Combine multiple XPath conditions with 'or' operators",
        "Time-based attacks: Use computationally expensive XPath expressions for DoS",
        "Wildcard exploitation: Use * to match any element when structure is unknown",
        "Axis manipulation: Use parent::, child::, following:: axes to navigate XML structure"
      ],
      real_world_impact: [
        "CVE-2015-20108: ruby-saml gem XPath injection allowed arbitrary code execution",
        "FluidAttacks research: Nokogiri XPath injection in book search functionality",
        "GitHub Security Lab: XPath injection detection in Ruby codebases using CodeQL",
        "OWASP documentation: Authentication bypass in XML-based login systems",
        "Vaadata security research: Real-world XPath injection exploitation examples",
        "Enterprise applications: XML-based configuration systems vulnerable to injection",
        "Web services: SOAP/XML APIs with XPath-based data filtering vulnerabilities",
        "Content management: XML-based CMS systems allowing unauthorized data access"
      ],
      cve_examples: [
        %{
          id: "CVE-2015-20108",
          description: "XPath injection and code execution in ruby-saml gem",
          severity: "critical",
          cvss: 9.8,
          note: "The gem was vulnerable to XPath injection allowing arbitrary code execution"
        },
        %{
          id: "CVE-2021-21295",
          description: "XPath injection in XML parsing libraries",
          severity: "high",
          cvss: 7.5,
          note: "Improper XPath query construction in various XML processing libraries"
        }
      ],
      detection_notes: """
      This pattern detects XPath injection by looking for Ruby XML libraries
      combined with string interpolation in XPath expressions:

      **Primary Detection Points:**
      - .xpath() method calls with interpolated strings
      - Nokogiri XPath queries with user input
      - REXML .elements[] access with interpolation
      - XPath::Parser.parse() with dynamic content

      **Ruby Libraries Covered:**
      - Nokogiri (most common): doc.xpath(), xml.xpath()
      - REXML (built-in): xml.elements[], doc.elements[]
      - LibXML: Various XPath methods
      - Generic XPath functions: find_by_xpath, query_xpath

      **False Positive Considerations:**
      - Static XPath expressions without user input (lower risk)
      - Parameterized XPath queries using proper syntax
      - XPath expressions in test files (excluded by AST enhancement)
      - Comments containing XPath syntax (excluded)

      **Detection Limitations:**
      - Complex string building across multiple lines
      - XPath queries built through method chaining
      - Dynamic method calls or metaprogramming
      - XML processing in non-standard libraries
      """,
      safe_alternatives: [
        "Parameterized queries: doc.xpath('//user[@name=$name]', nil, name: params[:name])",
        "Input sanitization: Escape special XPath characters before query construction",
        "Whitelist validation: Validate user input against known safe values",
        "Use Ruby built-ins: Prefer Ruby methods over XPath when possible",
        "Safe query builders: Use library methods that handle escaping automatically",
        "XML schema validation: Validate XML structure before XPath processing",
        "Access controls: Implement application-level access controls on XML data",
        "Alternative approaches: Consider JSON APIs instead of XML when possible"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing XML documents are 'safe' compared to databases",
          "Not realizing XPath has no built-in access controls like SQL",
          "Using string concatenation instead of interpolation (equally dangerous)",
          "Assuming XML validation prevents XPath injection",
          "Thinking XML namespaces provide security isolation",
          "Not escaping single quotes and double quotes in user input",
          "Relying only on client-side validation",
          "Using XPath for authentication without understanding injection risks"
        ],
        secure_patterns: [
          "doc.xpath('//user[@id=$id]', nil, id: params[:id]) # Parameterized query",
          "escaped_name = name.gsub(/['\"\\\\]/, '\\\\\\\\\\0') # Manual escaping",
          "allowed_fields = ['name', 'email']; xpath = \"//user/\#{allowed_fields.include?(field) ? field : 'name'}\" # Whitelist",
          "doc.css('user').find { |u| u['name'] == params[:name] } # Use CSS selectors instead",
          "XML::Node.new(doc, params[:name]) # Use Ruby XML builders",
          "Nokogiri::XML::XPath.quote(user_input) # Library escaping methods"
        ],
        ruby_specific: %{
          vulnerable_patterns: [
            "doc.xpath(\"//user[name='\#{name}']\") - Direct interpolation",
            "xml.elements[\"//item[@id='\#{id}']\"] - REXML element access",
            "nokogiri.search(\"//node[@attr='\#{attr}']\") - Search with interpolation",
            "XPath::Parser.parse(\"//user[role='\#{role}']\") - Direct parser usage",
            "find_by_xpath(\"//product[price>\#{price}]\") - Custom XPath methods"
          ],
          safe_alternatives: [
            "doc.xpath('//user[@name=$name]', nil, name: name) - Nokogiri parameters",
            "doc.at_xpath('//user[@id=?]', id) - Position-based parameters",
            "doc.css('user').find { |u| u['name'] == name } - CSS selectors with Ruby",
            "xml.elements.each('//item') { |e| e['id'] == id } - Ruby iteration",
            "Nokogiri::XML::XPath.quote(user_input) - Proper escaping"
          ],
          libraries: [
            "Nokogiri: Most popular, has parameter support",
            "REXML: Built-in, limited parameter support",
            "LibXML: Lower-level, requires manual escaping",
            "ROXML: Object mapping, less XPath exposure",
            "HappyMapper: XML to object mapping"
          ]
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual XPath injection vulnerabilities
  and safe XPath usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.XpathInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.XpathInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: [
          "xpath",
          "elements",
          "parse",
          "find_by_xpath",
          "select_xpath",
          "query_xpath",
          "get_xpath",
          "search",
          "at_xpath"
        ],
        receiver_analysis: %{
          check_xml_context: true,
          libraries: ["Nokogiri", "REXML", "LibXML", "XPath"],
          xml_indicators: ["doc", "xml", "document", "root", "node"]
        },
        argument_analysis: %{
          check_xpath_syntax: true,
          detect_interpolation: true,
          xpath_pattern: ~r{//|\[@|/\w+},
          interpolation_pattern: ~r/#\{[^}]+\}/
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
        check_xpath_context: true,
        safe_patterns: [
          # Parameter placeholders
          "$",
          "?",
          # Nokogiri parameter syntax
          "nil,",
          # CSS selector alternative
          ".css(",
          # CSS selector alternative
          ".at_css("
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
          "query_string"
        ],
        xpath_specific: %{
          parameter_syntax_safe: true,
          static_xpath_safe: true,
          check_xml_libraries: true,
          require_interpolation_for_danger: true
        }
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "contains_user_input" => 0.4,
          "uses_interpolation" => 0.3,
          "xpath_syntax_detected" => 0.2,
          "xml_library_context" => 0.15,
          "uses_parameters" => -0.9,
          "css_selector_used" => -0.8,
          "static_xpath_only" => -0.7,
          "in_test_code" => -1.0,
          "proper_escaping" => -0.8,
          "whitelisted_values" => -0.6
        }
      },
      min_confidence: 0.75
    }
  end
end
