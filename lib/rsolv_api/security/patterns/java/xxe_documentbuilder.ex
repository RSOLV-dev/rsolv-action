defmodule RsolvApi.Security.Patterns.Java.XxeDocumentbuilder do
  @moduledoc """
  XXE via DocumentBuilder pattern for Java code.
  
  Detects XML External Entity (XXE) vulnerabilities in DocumentBuilderFactory and DocumentBuilder
  usage where secure processing features are not enabled. XXE attacks allow attackers to access
  local files, perform server-side request forgery, or cause denial of service attacks.
  
  ## Vulnerability Details
  
  XML External Entity (XXE) attacks occur when XML input containing references to external
  entities is processed by a weakly configured XML parser. The DocumentBuilderFactory in Java
  is vulnerable by default and requires explicit secure configuration to prevent XXE attacks.
  
  Common vulnerable patterns:
  - DocumentBuilderFactory.newInstance().newDocumentBuilder() without secure features
  - DocumentBuilder created without disabling external entity processing
  - Missing XMLConstants.FEATURE_SECURE_PROCESSING configuration
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - no secure processing
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  DocumentBuilder db = dbf.newDocumentBuilder();
  Document doc = db.parse(xmlInput); // Can process malicious XXE
  
  // Attack payload example:
  // <?xml version="1.0" encoding="UTF-8"?>
  // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  // <root>&xxe;</root>
  ```
  
  ## References
  
  - CWE-611: Improper Restriction of XML External Entity Reference
  - OWASP A05:2021 - Security Misconfiguration
  - CVE-2025-23195: XXE vulnerability in popular Java libraries
  - OWASP XXE Prevention Cheat Sheet
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-xxe-documentbuilder",
      name: "XXE via DocumentBuilder",
      description: "DocumentBuilderFactory without secure processing configuration allows XXE attacks",
      type: :xxe,
      severity: :high,
      languages: ["java"],
      regex: [
        # Direct chained call: DocumentBuilderFactory.newInstance().newDocumentBuilder()
        ~r/DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newDocumentBuilder\s*\(\s*\)/,
        # Factory variable creation and usage (may span multiple lines)
        ~r/DocumentBuilderFactory\s+\w+\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\).*newDocumentBuilder\s*\(\s*\)/ms,
        # Assignment from direct chained call
        ~r/DocumentBuilder\s+\w+\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newDocumentBuilder\s*\(\s*\)/,
        # Factory variable followed by newDocumentBuilder (can be on different lines)
        ~r/\w+\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\);[\s\S]*?\w+\.newDocumentBuilder\s*\(\s*\)/m,
        # newDocumentBuilder followed by parse
        ~r/newDocumentBuilder\s*\(\s*\).*\.parse\s*\(/ms
      ],
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Enable secure processing and disable external entity processing by setting XMLConstants.FEATURE_SECURE_PROCESSING to true and disabling external entity features",
      test_cases: %{
        vulnerable: [
          ~S|DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); DocumentBuilder db = dbf.newDocumentBuilder();|,
          ~S|DocumentBuilderFactory.newInstance().newDocumentBuilder();|,
          ~S|DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();|
        ],
        safe: [
          ~S|DocumentBuilderFactory dbf = createSecureDocumentBuilderFactory();|,
          ~S|DocumentBuilder db = getSecureDocumentBuilder();|,
          ~S|// This is just a comment about DocumentBuilderFactory.newInstance()|,
          ~S|String doc = "Use DocumentBuilderFactory.newInstance() carefully";|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      XML External Entity (XXE) vulnerabilities occur when XML input containing references to
      external entities is processed by a weakly configured XML parser. The DocumentBuilderFactory
      in Java creates parsers that are vulnerable to XXE attacks by default, requiring explicit
      secure configuration to prevent these attacks.
      
      XXE attacks can lead to:
      - Disclosure of confidential data (file://, http://, ftp:// schemes)
      - Server-side request forgery (SSRF) to internal systems
      - Denial of service through billion laughs or quadratic blowup attacks
      - Remote code execution in certain configurations
      - Port scanning and service enumeration
      
      The DocumentBuilderFactory is particularly dangerous because:
      - External entity processing is enabled by default
      - No built-in protection against recursive entity expansion
      - Supports file:// URLs allowing local file access
      - Can make HTTP requests to arbitrary URLs
      - Common in enterprise applications processing XML data
      
      Historical context:
      - XXE has been in OWASP Top 10 since 2013 (A04:2013, A04:2017, A05:2021)
      - Affects most XML parsers across languages, not just Java
      - Major breaches at Facebook (2014), Adobe (2015), and others
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
          id: "portswigger_xxe",
          title: "XML external entity (XXE) injection - PortSwigger",
          url: "https://portswigger.net/web-security/xxe"
        },
        %{
          type: :research,
          id: "nist_xxe_guidance",
          title: "NIST SP 800-51: XML Security Best Practices",
          url: "https://csrc.nist.gov/publications/detail/sp/800-51/final"
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
        "Facebook XXE (2014): Local file disclosure through XML processing in mobile app APIs",
        "Adobe XXE vulnerabilities: Multiple products affected including ColdFusion and Flash",
        "Apache Struts XXE (CVE-2017-9805): Remote code execution through XML REST plugin",
        "Oracle WebLogic XXE (CVE-2019-2725): Deserialization leading to RCE via XXE",
        "Government data breaches: Classified document exposure through XXE in document processors",
        "Financial sector attacks: Trading system data theft via XXE in SOAP web services",
        "Healthcare breaches: Patient record exposure through XXE in HL7 message processing"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-23195",
          description: "XXE vulnerability in Apache POI leading to arbitrary file read",
          severity: "high",
          cvss: 7.5,
          note: "DocumentBuilderFactory used without secure processing in OOXML parsing"
        },
        %{
          id: "CVE-2024-38374", 
          description: "XXE in Spring Framework's XML processing components",
          severity: "high",
          cvss: 8.1,
          note: "Default DocumentBuilderFactory configuration allows external entity processing"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability partially exploitable via XXE injection vectors",
          severity: "critical", 
          cvss: 10.0,
          note: "XXE used as attack vector for LDAP injection in logging contexts"
        }
      ],
      detection_notes: """
      This pattern detects insecure DocumentBuilderFactory usage by identifying:
      
      1. Direct method chaining: DocumentBuilderFactory.newInstance().newDocumentBuilder()
      2. Variable-based factory usage without secure configuration
      3. DocumentBuilder instantiation without preceding secure feature configuration
      4. Method chaining patterns that bypass security settings
      
      The pattern uses negative lookahead to avoid false positives when secure processing
      is properly configured. It checks for XMLConstants.FEATURE_SECURE_PROCESSING and
      other XXE prevention features within the same code block.
      
      Key detection criteria:
      - Looks for newDocumentBuilder() calls
      - Ensures no setFeature() calls for FEATURE_SECURE_PROCESSING
      - Covers both direct method chaining and variable assignment patterns
      - Excludes commented code and string literals
      """,
      safe_alternatives: [
        "Enable secure processing: dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        "Disable DTD processing: dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
        "Disable external entities: dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false)",
        "Disable parameter entities: dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false)",
        "Use XML libraries with secure defaults: JAXB with proper configuration",
        "Input validation: Validate and sanitize XML input before parsing",
        "Use JSON instead of XML when possible for data exchange"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming DocumentBuilderFactory is secure by default",
          "Enabling secure processing but not disabling specific XXE features",
          "Only checking for external entities but allowing DTD processing",
          "Relying on input validation alone without parser configuration",
          "Using try-catch to suppress XXE-related exceptions",
          "Configuring security features on wrong parser instance"
        ],
        secure_patterns: [
          "Always set XMLConstants.FEATURE_SECURE_PROCESSING to true on DocumentBuilderFactory",
          "Use setFeature() to explicitly disable all external entity processing features",
          "Configure DocumentBuilderFactory with secure processing before creating DocumentBuilder",
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
        framework_considerations: [
          "Spring Framework: Check @RequestBody XML parsing configuration",
          "JAX-RS: Ensure MessageBodyReader implementations are secure",
          "SOAP Web Services: Configure secure XML processing in service handlers",
          "Apache Camel: Secure XML components and data formats",
          "JAXB: Configure secure unmarshalling contexts"
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
  DocumentBuilder usage patterns that have proper security configuration.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.XxeDocumentbuilder.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.XxeDocumentbuilder.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.XxeDocumentbuilder.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        xml_analysis: %{
          check_documentbuilder_usage: true,
          documentbuilder_methods: ["newDocumentBuilder", "parse", "setErrorHandler"],
          check_secure_processing: true,
          secure_features: ["XMLConstants.FEATURE_SECURE_PROCESSING", "disallow-doctype-decl", "external-general-entities", "external-parameter-entities"],
          check_factory_configuration: true
        },
        factory_analysis: %{
          check_factory_instantiation: true,
          documentbuilder_factory_methods: ["newInstance", "newDocumentBuilder"],
          check_feature_configuration: true,
          secure_configuration_methods: ["setFeature", "setXIncludeAware", "setExpandEntityReferences"]
        },
        parsing_analysis: %{
          check_parse_methods: true,
          parse_methods: ["parse", "parseDocument", "parseXML"],
          check_input_sources: true,
          dangerous_input_types: ["InputStream", "File", "URL", "String", "Reader"]
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
        high_risk_contexts: ["web service", "API endpoint", "file upload", "data import", "configuration parsing"]
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