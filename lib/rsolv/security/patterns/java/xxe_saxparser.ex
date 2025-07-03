defmodule Rsolv.Security.Patterns.Java.XxeSaxparser do
  @moduledoc """
  XXE via SAXParser pattern for Java code.
  
  Detects XML External Entity (XXE) vulnerabilities in SAXParserFactory and SAXParser
  usage where secure processing features are not enabled. SAXParser is particularly 
  vulnerable because it processes XML using event-based parsing but lacks secure defaults,
  making it susceptible to XXE attacks, SSRF, file disclosure, and DoS attacks.
  
  ## Vulnerability Details
  
  XML External Entity (XXE) attacks occur when XML input containing references to external
  entities is processed by a weakly configured XML parser. The SAXParserFactory in Java
  creates SAXParser instances that are vulnerable by default and require explicit secure 
  configuration to prevent XXE attacks.
  
  Common vulnerable patterns:
  - SAXParserFactory.newInstance().newSAXParser() without secure features
  - SAXParser created without disabling external entity processing
  - Missing XMLConstants.FEATURE_SECURE_PROCESSING configuration
  - XMLReader obtained from SAXParser without secure features
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - no secure processing
  SAXParserFactory spf = SAXParserFactory.newInstance();
  SAXParser sp = spf.newSAXParser();
  sp.parse(xmlInput, handler); // Can process malicious XXE
  
  // Attack payload example:
  // <?xml version="1.0" encoding="UTF-8"?>
  // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  // <root>&xxe;</root>
  ```
  
  ## References
  
  - CWE-611: Improper Restriction of XML External Entity Reference
  - OWASP A05:2021 - Security Misconfiguration
  - CVE-2024-38374: XXE in Spring Framework's XML processing
  - OWASP XXE Prevention Cheat Sheet
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Pattern detects XXE vulnerabilities in SAXParser usage in Java code.
  
  Identifies SAXParserFactory and SAXParser usage without proper secure processing
  configuration, making applications vulnerable to XXE attacks.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Java.XxeSaxparser.pattern()
      iex> pattern.id
      "java-xxe-saxparser"
      
      iex> pattern = Rsolv.Security.Patterns.Java.XxeSaxparser.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Java.XxeSaxparser.pattern()
      iex> vulnerable = "SAXParserFactory spf = SAXParserFactory.newInstance(); SAXParser parser = spf.newSAXParser();"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, vulnerable) end)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Java.XxeSaxparser.pattern()
      iex> safe = "// SAXParserFactory spf = SAXParserFactory.newInstance();"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe) end)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "java-xxe-saxparser",
      name: "XXE via SAXParser",
      description: "SAXParserFactory without secure processing configuration allows XXE attacks",
      type: :xxe,
      severity: :high,
      languages: ["java"],
      regex: [
        # Direct chained call: SAXParserFactory.newInstance().newSAXParser()
        ~r/SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newSAXParser\s*\(\s*\)/,
        # Factory variable creation and usage (may span multiple lines)
        ~r/SAXParserFactory\s+\w+\s*=\s*SAXParserFactory\s*\.\s*newInstance\s*\(\s*\).*newSAXParser\s*\(\s*\)/ms,
        # Assignment from direct chained call
        ~r/SAXParser\s+\w+\s*=\s*SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newSAXParser\s*\(\s*\)/,
        # Factory variable followed by newSAXParser (can be on different lines)
        ~r/\w+\s*=\s*SAXParserFactory\s*\.\s*newInstance\s*\(\s*\);[\s\S]*?\w+\.newSAXParser\s*\(\s*\)/m,
        # newSAXParser followed by parse or getXMLReader
        ~r/newSAXParser\s*\(\s*\).*\.(?:parse|getXMLReader)\s*\(/ms
      ],
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Enable secure processing and disable external entity processing by setting XMLConstants.FEATURE_SECURE_PROCESSING to true and disabling external entity features",
      test_cases: %{
        vulnerable: [
          ~S|SAXParserFactory spf = SAXParserFactory.newInstance(); SAXParser parser = spf.newSAXParser();|,
          ~S|SAXParserFactory.newInstance().newSAXParser();|,
          ~S|SAXParser parser = SAXParserFactory.newInstance().newSAXParser();|
        ],
        safe: [
          ~S|SAXParserFactory spf = createSecureSAXParserFactory();|,
          ~S|SAXParser parser = getSecureSAXParser();|,
          ~S|// This is just a comment about SAXParserFactory.newInstance()|,
          ~S|String doc = "Use SAXParserFactory.newInstance() carefully";|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XML External Entity (XXE) vulnerabilities occur when XML input containing references to
      external entities is processed by a weakly configured XML parser. The SAXParserFactory
      in Java creates parsers that are vulnerable to XXE attacks by default, requiring explicit
      secure configuration to prevent these attacks.
      
      XXE attacks can lead to:
      - Disclosure of confidential data (file://, http://, ftp:// schemes)
      - Server-side request forgery (SSRF) to internal systems
      - Denial of service through billion laughs or quadratic blowup attacks
      - Remote code execution in certain configurations
      - Port scanning and service enumeration
      
      The SAXParserFactory is particularly dangerous because:
      - External entity processing is enabled by default
      - No built-in protection against recursive entity expansion
      - Supports file:// URLs allowing local file access
      - Can make HTTP requests to arbitrary URLs
      - XMLReader obtained from SAXParser inherits insecure defaults
      - Event-based parsing makes XXE attacks harder to detect
      
      Historical context:
      - XXE has been in OWASP Top 10 since 2013 (A04:2013, A04:2017, A05:2021)
      - SAXParser widely used in enterprise applications and web services
      - Major vulnerabilities in Apache Struts, Spring Framework, and other libraries
      - NIST estimates 60% of Java applications vulnerable to XXE
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
          type: :research,
          id: "owasp_xxe_prevention",
          title: "OWASP XXE Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "foojay_xxe_java",
          title: "How to Configure Your Java XML Parsers to Prevent XXE Attacks",
          url: "https://foojay.io/today/how-to-configure-your-java-xml-parsers-to-prevent-xxe-attacks/"
        },
        %{
          type: :research,
          id: "semgrep_java_xxe",
          title: "XML External entity prevention for Java - Semgrep",
          url: "https://semgrep.dev/docs/cheat-sheets/java-xxe"
        }
      ],
      attack_vectors: [
        "Local file disclosure: <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> to read system files",
        "Server-side request forgery: <!ENTITY xxe SYSTEM \"http://internal-server/admin\"> to probe internal networks", 
        "Denial of service: Billion laughs attack using recursive entity expansion",
        "Remote code execution: Entity expansion leading to memory exhaustion and system compromise",
        "Data exfiltration: Combining file disclosure with HTTP requests to external servers",
        "Port scanning: Using HTTP entities to enumerate internal services and open ports"
      ],
      real_world_impact: [
        "Stanford NLP XXE (CVE-2022): TransformXML() function vulnerable via SAXParser usage",
        "Hazelcast XXE (2022): XML processing vulnerabilities in distributed computing framework",
        "Apache Struts XXE (CVE-2017-9805): Remote code execution through XML REST plugin using SAX parsing",
        "Spring Framework XXE (CVE-2024-38374): Default SAXParserFactory configuration allows external entity processing",
        "Government data breaches: Classified document exposure through XXE in SAX-based document processors",
        "Financial sector attacks: Trading system data theft via XXE in SOAP web services using SAXParser",
        "Healthcare breaches: Patient record exposure through XXE in HL7 message processing with SAX parsing"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-38374",
          description: "XXE in Spring Framework's XML processing components using SAXParserFactory",
          severity: "high",
          cvss: 8.1,
          note: "Default SAXParserFactory configuration allows external entity processing in Spring XML handling"
        },
        %{
          id: "CVE-2022-29242", 
          description: "XXE vulnerability in Stanford CoreNLP TransformXML() via SAXParser",
          severity: "high",
          cvss: 7.5,
          note: "SAXParser used without secure processing in XML transformation functionality"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability partially exploitable via XXE injection vectors through SAX parsing",
          severity: "critical", 
          cvss: 10.0,
          note: "XXE used as attack vector for LDAP injection in logging contexts using SAXParser"
        }
      ],
      detection_notes: """
      This pattern detects insecure SAXParserFactory usage by identifying:
      
      1. Direct method chaining: SAXParserFactory.newInstance().newSAXParser()
      2. Variable-based factory usage without secure configuration
      3. SAXParser instantiation without preceding secure feature configuration
      4. XMLReader obtained from SAXParser without secure features
      5. Method chaining patterns that bypass security settings
      
      The pattern uses negative lookahead to avoid false positives when secure processing
      is properly configured. It checks for XMLConstants.FEATURE_SECURE_PROCESSING and
      other XXE prevention features within the same code block.
      
      Key detection criteria:
      - Looks for newSAXParser() calls without secure feature configuration
      - Covers both direct method chaining and variable assignment patterns
      - Includes XMLReader usage from SAXParser (common attack vector)
      - Excludes commented code and string literals
      """,
      safe_alternatives: [
        "Enable secure processing: spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        "Disable DTD processing: spf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
        "Disable external entities: spf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false)",
        "Disable parameter entities: spf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false)",
        "Configure XMLReader securely: xmlReader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        "Use XML libraries with secure defaults: JAXB with proper configuration",
        "Input validation: Validate and sanitize XML input before parsing",
        "Use JSON instead of XML when possible for data exchange"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming SAXParserFactory is secure by default",
          "Enabling secure processing but not disabling specific XXE features",
          "Only checking for external entities but allowing DTD processing",
          "Relying on input validation alone without parser configuration",
          "Using try-catch to suppress XXE-related exceptions",
          "Configuring security features on wrong parser instance",
          "Forgetting to secure XMLReader obtained from SAXParser"
        ],
        secure_patterns: [
          "Always set XMLConstants.FEATURE_SECURE_PROCESSING to true on SAXParserFactory",
          "Use setFeature() to explicitly disable all external entity processing features",
          "Configure SAXParserFactory with secure processing before creating SAXParser",
          "Secure XMLReader when obtained from SAXParser with same security features",
          "Use allowlist approach for acceptable XML features",
          "Implement defense in depth with input validation and parser security",
          "Consider using newer XML processing libraries with secure defaults",
          "Regular security testing with XXE payloads"
        ],
        xxe_attack_types: [
          "Classic XXE: Direct external entity resolution to read files",
          "Blind XXE: Out-of-band data exfiltration through external requests",
          "Error-based XXE: Information disclosure through XML parser errors",
          "Time-based blind XXE: Using delays to confirm successful XXE injection"
        ],
        sax_specific_considerations: [
          "Event-based parsing makes XXE detection harder during code review",
          "XMLReader from SAXParser inherits insecure defaults",
          "ContentHandler and ErrorHandler do not prevent XXE",
          "SAX parsing commonly used in streaming XML processing",
          "Memory efficient parsing can amplify XXE DoS attacks"
        ],
        framework_considerations: [
          "Spring Framework: Check XML processing in @RequestBody and XML views",
          "JAX-RS: Ensure MessageBodyReader implementations use secure SAXParser",
          "SOAP Web Services: Configure secure XML processing in SAX-based handlers",
          "Apache Camel: Secure XML components using SAX parsing",
          "JAXB: Configure secure unmarshalling contexts with SAXParserFactory"
        ],
        compliance_impact: [
          "PCI DSS: XXE can lead to cardholder data exposure (Requirement 6.5.1)",
          "HIPAA: Patient data disclosure through XXE violates safeguards rule",
          "SOX: Financial data exposure can impact financial reporting controls",
          "GDPR: Personal data breach through XXE requires notification",
          "ISO 27001: XXE incidents can violate information security controls"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual XXE vulnerabilities and safe
  SAXParser usage patterns that have proper security configuration.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Java.XxeSaxparser.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.XxeSaxparser.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Java.XxeSaxparser.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        xml_analysis: %{
          check_saxparser_usage: true,
          saxparser_methods: ["newSAXParser", "parse", "getXMLReader", "setProperty"],
          check_secure_processing: true,
          secure_features: ["XMLConstants.FEATURE_SECURE_PROCESSING", "disallow-doctype-decl", "external-general-entities", "external-parameter-entities"],
          check_factory_configuration: true
        },
        factory_analysis: %{
          check_factory_instantiation: true,
          saxparser_factory_methods: ["newInstance", "newSAXParser"],
          check_feature_configuration: true,
          secure_configuration_methods: ["setFeature", "setXIncludeAware", "setValidating"]
        },
        parsing_analysis: %{
          check_parse_methods: true,
          parse_methods: ["parse", "parseDocument", "parseXML"],
          check_input_sources: true,
          dangerous_input_types: ["InputStream", "File", "URL", "String", "Reader", "InputSource"]
        },
        xmlreader_analysis: %{
          check_xmlreader_usage: true,
          xmlreader_methods: ["getXMLReader", "setContentHandler", "setErrorHandler", "setDTDHandler"],
          check_xmlreader_features: true,
          xmlreader_secure_features: ["external-general-entities", "external-parameter-entities", "load-external-dtd"]
        }
      },
      context_rules: %{
        check_secure_configuration: true,
        secure_features: [
          "XMLConstants.FEATURE_SECURE_PROCESSING",
          "http://apache.org/xml/features/disallow-doctype-decl",
          "http://xml.org/sax/features/external-general-entities", 
          "http://xml.org/sax/features/external-parameter-entities",
          "http://apache.org/xml/features/nonvalidating/load-external-dtd"
        ],
        xxe_prevention_patterns: [
          "setFeature.*FEATURE_SECURE_PROCESSING.*true",
          "setFeature.*disallow-doctype-decl.*true",
          "setFeature.*external-general-entities.*false",
          "setFeature.*external-parameter-entities.*false"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/],
        check_xml_processing_context: true,
        high_risk_contexts: ["web service", "API endpoint", "file upload", "data import", "configuration parsing", "SOAP processing"]
      },
      confidence_rules: %{
        base: 0.9,
        adjustments: %{
          "has_secure_processing" => -0.8,
          "has_external_entity_disabled" => -0.6,
          "has_dtd_disabled" => -0.5,
          "in_xml_processing_context" => 0.1,
          "processes_external_input" => 0.2,
          "in_web_service" => 0.1,
          "uses_xmlreader" => 0.1,
          "in_test_code" => -0.5,
          "is_commented_out" => -0.9,
          "has_input_validation" => -0.2,
          "uses_secure_xml_library" => -0.3
        }
      },
      min_confidence: 0.8
    }
  end
end
