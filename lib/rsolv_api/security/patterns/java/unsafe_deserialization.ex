defmodule RsolvApi.Security.Patterns.Java.UnsafeDeserialization do
  @moduledoc """
  Unsafe Deserialization pattern for Java code.
  
  Detects the use of Java's ObjectInputStream.readObject() and related deserialization
  methods that can lead to remote code execution when processing untrusted data.
  Deserialization of untrusted data is one of the most critical vulnerabilities in Java.
  
  ## Vulnerability Details
  
  Java's native serialization mechanism allows arbitrary objects to be converted to
  byte streams and back. When deserializing untrusted data, attackers can craft
  malicious serialized objects that execute code during the deserialization process.
  This happens through "gadget chains" - sequences of existing classes that, when
  deserialized in a specific order, result in arbitrary code execution.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
  Object obj = ois.readObject(); // Arbitrary code execution here!
  
  // Attacker sends a crafted serialized object containing a gadget chain
  // that executes system commands during deserialization
  ```
  
  ### Real-World Impact
  
  This vulnerability has been exploited in numerous high-profile breaches:
  - Equifax breach (CVE-2017-9805 in Apache Struts)
  - PayPal remote code execution
  - Jenkins, WebLogic, JBoss, and many other enterprise applications
  
  ## References
  
  - CWE-502: Deserialization of Untrusted Data
  - OWASP A08:2021 - Software and Data Integrity Failures
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-unsafe-deserialization",
      name: "Insecure Deserialization",
      description: "ObjectInputStream.readObject() can execute arbitrary code",
      type: :deserialization,
      severity: :critical,
      languages: ["java"],
      regex: [
        # ObjectInputStream.readObject()
        ~r/ObjectInputStream[\s\S]*?\.readObject\s*\(\s*\)/,
        # readUnshared() is equally dangerous
        ~r/ObjectInputStream[\s\S]*?\.readUnshared\s*\(\s*\)/,
        # Any variable calling readUnshared()
        ~r/\w+\.readUnshared\s*\(\s*\)/,
        # Direct readObject calls
        ~r/\breadObject\s*\(\s*\)(?!\s*throws)/,
        # XMLDecoder is also vulnerable
        ~r/XMLDecoder[\s\S]*?\.readObject\s*\(\s*\)/,
        # Externalizable.readExternal
        ~r/\.readExternal\s*\(\s*(?:new\s+)?ObjectInput/,
        ~r/\breadExternal\s*\(\s*ObjectInput\s+\w+\s*\)/,
        # Object calling readExternal with any parameter
        ~r/\w+\.readExternal\s*\(\s*\w+\s*\)/,
        # Casting to ObjectInputStream for deserialization
        ~r/\(\s*ObjectInputStream\s*\)[^)]+\.readObject\s*\(\s*\)/,
        # ObjectInput interface methods
        ~r/ObjectInput\s+\w+[\s\S]*?\.readObject\s*\(\s*\)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Never deserialize untrusted data. Use JSON/XML with schema validation instead",
      test_cases: %{
        vulnerable: [
          ~S|ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();|,
          ~S|return new ObjectInputStream(fileInputStream).readObject();|,
          ~S|XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();|
        ],
        safe: [
          ~S|// Use JSON deserialization instead
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);|,
          ~S|// Implement ObjectInputFilter for validation
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("maxdepth=5;maxarray=100");|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Deserialization of untrusted data in Java is one of the most critical security vulnerabilities.
      When Java deserializes an object, it can invoke methods during the deserialization process.
      Attackers exploit this by crafting malicious serialized objects containing "gadget chains" -
      sequences of method invocations on existing classes that ultimately lead to arbitrary code execution.
      
      The vulnerability exists because ObjectInputStream.readObject() will deserialize any serializable
      class found in the classpath, and many common libraries contain classes that can be chained
      together to achieve code execution. Tools like ysoserial can automatically generate these
      malicious payloads for various libraries.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-502",
          title: "Deserialization of Untrusted Data",
          url: "https://cwe.mitre.org/data/definitions/502.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :research,
          id: "java_deserialization_cheat_sheet",
          title: "Java Deserialization Cheat Sheet",
          url: "https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet"
        },
        %{
          type: :tool,
          id: "ysoserial",
          title: "ysoserial - Java deserialization payload generator",
          url: "https://github.com/frohoff/ysoserial"
        },
        %{
          type: :research,
          id: "deserialization_vulnerability_study",
          title: "An In-depth Study of Java Deserialization Remote-Code Execution Exploits",
          url: "https://www.abartel.net/static/p/tosem2022-javadeser.pdf"
        }
      ],
      attack_vectors: [
        "Commons Collections gadget chain for RCE",
        "Spring framework gadget chains",
        "JNDI injection through serialized objects",
        "File system access through serialized File objects",
        "DNS/HTTP callbacks for blind detection",
        "Denial of Service through recursive objects"
      ],
      real_world_impact: [
        "Remote code execution with application privileges",
        "Complete server compromise",
        "Data exfiltration and manipulation",
        "Installation of backdoors and persistence",
        "Lateral movement in the network",
        "Cryptocurrency mining on compromised servers"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-48178",
          description: "Relution MDM remote code execution via Java deserialization",
          severity: "critical",
          cvss: 9.8,
          note: "Unauthenticated RCE through deserialization of user-controlled data"
        },
        %{
          id: "CVE-2024-34102",
          description: "Adobe Commerce critical Java deserialization vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Nested deserialization vulnerability leading to RCE"
        },
        %{
          id: "CVE-2023-25581",
          description: "pac4j-core Java deserialization vulnerability",
          severity: "critical",
          cvss: 9.1,
          note: "RestrictedObjectInputStream bypass allowing gadget chain exploitation"
        },
        %{
          id: "CVE-2017-9805",
          description: "Apache Struts REST plugin deserialization (Equifax breach)",
          severity: "critical",
          cvss: 10.0,
          note: "Led to the massive Equifax data breach affecting 147 million people"
        },
        %{
          id: "CVE-2024-0692",
          description: "H2 Database deserialization vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "JDBC connection string exploitation through deserialization"
        }
      ],
      detection_notes: """
      This pattern detects various forms of Java deserialization:
      - Direct ObjectInputStream.readObject() calls
      - readUnshared() which is equally vulnerable
      - XMLDecoder.readObject() for XML-based deserialization
      - Externalizable.readExternal() implementations
      - ObjectInput interface usage
      
      False positives may occur in custom readObject() implementations that
      properly validate input, but these are rare and still risky.
      """,
      safe_alternatives: [
        "Use JSON with Jackson or Gson for data exchange",
        "Use Protocol Buffers or MessagePack for binary formats",
        "If Java serialization is required, use ObjectInputFilter (Java 9+)",
        "Implement a strict allowlist of classes that can be deserialized",
        "Use sealed classes and records (Java 15+) to limit deserialization scope",
        "Sign serialized data and verify signatures before deserialization",
        "Isolate deserialization in separate processes with limited privileges"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that network isolation prevents exploitation",
          "Thinking that authentication prevents deserialization attacks",
          "Assuming that input validation before deserialization is sufficient",
          "Using blacklists instead of allowlists for class filtering"
        ],
        secure_patterns: [
          "Never deserialize data from untrusted sources",
          "Always prefer data formats that don't allow code execution",
          "If serialization is necessary, use cryptographic signatures",
          "Implement defense in depth with multiple security layers"
        ],
        gadget_chains: [
          "Commons Collections (CC1-CC7)",
          "Spring Framework gadgets",
          "Groovy gadgets",
          "JDK internal gadgets (JDK7u21)",
          "Hibernate gadgets",
          "Rome gadgets",
          "XStream converters"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between dangerous deserialization of untrusted
  data and potentially safe internal deserialization with proper validation.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.UnsafeDeserialization.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.UnsafeDeserialization.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.UnsafeDeserialization.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        deserialization_analysis: %{
          check_method_name: true,
          unsafe_methods: [
            "readObject", "readUnshared", "readExternal",
            "defaultReadObject", "readResolve", "readObjectNoData"
          ],
          check_receiver_type: true,
          unsafe_types: [
            "ObjectInputStream", "ObjectInput", "XMLDecoder",
            "XStream", "Hessian", "Kryo", "FST"
          ]
        },
        input_tracking: %{
          check_data_source: true,
          untrusted_sources: [
            "request", "socket", "network", "user", "external",
            "client", "remote", "upload", "input"
          ],
          safe_sources: [
            "resource", "classpath", "internal", "trusted",
            "signed", "validated"
          ],
          stream_sources: [
            "getInputStream", "getReader", "getParameter",
            "getBody", "getData", "receive"
          ]
        },
        class_loading: %{
          check_dynamic_loading: true,
          dangerous_methods: ["Class.forName", "loadClass", "defineClass"],
          check_classloader_usage: true
        }
      },
      context_rules: %{
        check_custom_readobject: true,
        custom_validation_patterns: [
          ~r/validateObject/,
          ~r/checkPermission/,
          ~r/verifySignature/,
          ~r/ObjectInputFilter/
        ],
        check_input_filtering: true,
        filter_patterns: [
          "ObjectInputFilter", "SerialFilter", "InputValidation"
        ],
        safe_patterns: [
          "JSON deserialization only",
          "Inside test code",
          "Reading from signed/encrypted data",
          "Custom readObject with validation"
        ],
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/example/
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_untrusted_source" => 0.4,
          "uses_network_input" => 0.3,
          "has_class_loading" => 0.2,
          "has_input_filter" => -0.4,
          "has_custom_validation" => -0.3,
          "in_test_code" => -0.8,
          "uses_signed_data" => -0.5,
          "internal_only" => -0.3
        }
      },
      min_confidence: 0.8
    }
  end
end