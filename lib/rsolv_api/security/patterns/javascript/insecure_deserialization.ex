defmodule RsolvApi.Security.Patterns.Javascript.InsecureDeserialization do
  @moduledoc """
  Insecure Deserialization in JavaScript/Node.js
  
  Detects dangerous patterns like:
    JSON.parse(req.body.data)
    yaml.load(userInput)
    deserialize(req.body)
    eval('(' + req.body + ')')
    
  Safe alternatives:
    try { const data = JSON.parse(req.body.data); validateSchema(data) } catch(e) {}
    yaml.safeLoad(userInput)
    JSON.parse(sanitizeJson(req.body))
    
  Insecure deserialization occurs when untrusted data is used to reconstruct objects
  without proper validation. In JavaScript, this can lead to remote code execution
  through various attack vectors including prototype pollution, code injection via
  eval-like behaviors, and exploitation of unsafe parsing libraries.
  
  ## Vulnerability Details
  
  While JavaScript's `JSON.parse()` is generally safer than deserialization in other
  languages, it can still be exploited when combined with other vulnerabilities or
  when using unsafe parsing libraries. The risk increases dramatically when using
  eval-based parsing, YAML deserializers, or custom deserialization functions that
  don't properly validate input structure and content.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct YAML parsing with user input
  const yaml = require('js-yaml');
  
  app.post('/config', (req, res) => {
    // This can execute arbitrary JavaScript!
    const config = yaml.load(req.body.yamlData);
    applyConfig(config);
  });
  
  // Attack payload:
  // !!js/function >
  //   function() {
  //     require('child_process').exec('rm -rf /');
  //   }()
  ```
  
  ### Modern Attack Scenarios
  Insecure deserialization in Node.js applications can lead to:
  - Remote code execution through YAML/XML parsers
  - Prototype pollution via JSON parsing
  - Server-side request forgery through configuration injection
  - Denial of service through resource exhaustion
  - Privilege escalation by manipulating application state
  
  The vulnerability is particularly dangerous in:
  - API endpoints that accept complex data structures
  - Configuration management systems
  - Session handling mechanisms
  - Inter-service communication in microservices
  - Plugin or extension systems that load external code
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the insecure deserialization detection pattern.
  
  This pattern detects dangerous deserialization of untrusted data that can lead to
  remote code execution (RCE) in JavaScript/Node.js applications. It covers multiple
  deserialization vectors including JSON parsing with prototype pollution risks,
  YAML parsing with code execution, eval-based deserialization, and VM module usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> pattern.id
      "js-insecure-deserialization"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> pattern.cwe_id
      "CWE-502"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> vulnerable = "JSON.parse(req.body.data)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> safe = "JSON.parse(hardcodedString)"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> vulnerable = "yaml.load(userInput)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> vulnerable = "eval(req.body)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> vulnerable = "vm.runInContext(req.body)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> safe = "yaml.safeLoad(userInput)"
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> vulnerable = "new Function('return ' + userInput)()"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.pattern()
      iex> pattern.recommendation
      "Validate data structure before deserialization. Use safe parsing methods."
  """
  def pattern do
    %Pattern{
      id: "js-insecure-deserialization",
      name: "Insecure Deserialization",
      description: "Deserializing untrusted data can lead to remote code execution",
      type: :deserialization,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:JSON\.parse|yaml\.load|YAML\.load|YAML\.parse|yamljs\.load|js-yaml\.load|yamlParser\.load|loadYaml|(?<!safe)deserialize|unserialize|eval|Function|vm\.run(?:InContext|InNewContext|InThisContext)?|vm\.Script|runInNewContext|parseXML|parseXmlString|xml2js\.parseString|xmlParse|xmlParser\.parse|xmlToObject|convertXML|processXML|fromJSON|parseObject|reconstruct)\s*\([^)]*?(?:req\.body|request\.body|req\.params|request\.params|req\.query|request\.query|req\b|request\b|params\b|query\b|body\b|user|input|data(?!base64)|payload)/i,
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Validate data structure before deserialization. Use safe parsing methods.",
      test_cases: %{
        vulnerable: [
          "JSON.parse(req.body.data)",
          "yaml.load(userInput)",
          "deserialize(req.body)",
          "eval('(' + req.body + ')')",
          "new Function('return ' + data)()",
          "vm.runInContext(req.body)",
          "xmlParse(userInput)",
          "YAML.load(params.config)"
        ],
        safe: [
          "try { const data = JSON.parse(req.body.data); validateSchema(data) } catch(e) {}",
          "yaml.safeLoad(userInput)",
          "JSON.parse(sanitizeJson(req.body))",
          "JSON.parse(hardcodedString)",
          "JSON.stringify(obj)",
          "if (isValidJSON(input)) { JSON.parse(input) }",
          "const validated = ajv.validate(schema, data) ? JSON.parse(data) : null"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for insecure deserialization.
  
  This metadata documents the critical security implications of unsafe
  deserialization patterns and provides authoritative guidance for secure
  data parsing in JavaScript applications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Insecure deserialization represents a critical vulnerability class where
      untrusted data is used to reconstruct objects or execute code without
      proper validation. While JavaScript's native JSON.parse() is relatively
      safe compared to serialization in languages like Java or PHP, the JavaScript
      ecosystem presents unique risks through various parsing libraries and
      eval-based deserialization patterns.
      
      The vulnerability in JavaScript manifests primarily through:
      1. YAML parsers that support code execution features
      2. XML parsers vulnerable to XXE and code injection
      3. Custom deserialization functions using eval() or Function()
      4. Prototype pollution through malicious JSON structures
      5. VM-based code execution with user-controlled input
      
      Modern Node.js applications are particularly vulnerable due to their
      heavy reliance on configuration files, inter-service communication, and
      dynamic module loading. A single insecure deserialization vulnerability
      can compromise an entire application or even the underlying server.
      
      The rise of microservices architectures has expanded the attack surface,
      as services often exchange complex data structures through APIs. Without
      proper validation at each service boundary, attackers can exploit
      deserialization vulnerabilities to traverse through multiple services,
      achieving lateral movement within the infrastructure.
      
      The JavaScript-specific nature of these attacks often involves exploiting
      the language's dynamic features, prototype chain manipulation, and the
      availability of powerful runtime APIs like child_process in Node.js
      environments.
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
          id: "nodejs_deserialization",
          title: "Exploiting Node.js deserialization bug for Remote Code Execution",
          url: "https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/"
        },
        %{
          type: :vendor,
          id: "snyk_js_yaml",
          title: "Arbitrary Code Execution in js-yaml",
          url: "https://security.snyk.io/vuln/npm:js-yaml:20130623"
        },
        %{
          type: :nist,
          id: "SP_800-53_SI-10",
          title: "NIST SP 800-53 - Information Input Validation",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        },
        %{
          type: :research,
          id: "json_attacks",
          title: "An Exploration of JSON Interoperability Vulnerabilities",
          url: "https://bishopfox.com/blog/json-interoperability-vulnerabilities"
        }
      ],
      attack_vectors: [
        "YAML code execution: Malicious YAML with !!js/function tags",
        "Prototype pollution: JSON payloads targeting __proto__ properties",
        "Eval injection: JSON-like strings executed through eval()",
        "XXE via XML: XML parsing with external entity references",
        "Function constructor: Creating functions from user-controlled strings",
        "VM context manipulation: Exploiting Node.js VM module with user input",
        "Module loading: Tricking require() through deserialized paths",
        "Configuration injection: Overwriting critical app settings via deserialization"
      ],
      real_world_impact: [
        "Remote code execution on application servers",
        "Complete server compromise through reverse shells",
        "Data exfiltration via command execution",
        "Denial of service through resource exhaustion",
        "Privilege escalation by manipulating user objects",
        "Lateral movement in microservice architectures",
        "Cryptocurrency mining through compromised servers",
        "Supply chain attacks via configuration manipulation"
      ],
      cve_examples: [
        %{
          id: "CVE-2017-16138",
          description: "The mime module < 1.4.1, 2.0.0 - 2.0.4 is vulnerable to Regular Expression Denial of Service via a malicious Content-Type header",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates how parsing untrusted input can lead to DoS"
        },
        %{
          id: "CVE-2019-10744",
          description: "Versions of lodash before 4.17.12 are vulnerable to Prototype Pollution via defaultsDeep, merge, and mergeWith functions",
          severity: "critical",
          cvss: 9.1,
          note: "Shows how object merging can lead to prototype pollution"
        },
        %{
          id: "CVE-2013-4660",
          description: "js-yaml before 2.0.5 allows code execution via a crafted YAML document",
          severity: "critical",
          cvss: 9.8,
          note: "Classic example of YAML deserialization leading to RCE"
        },
        %{
          id: "CVE-2020-8203",
          description: "Prototype pollution in lodash versions before 4.17.16",
          severity: "high",
          cvss: 7.4,
          note: "Demonstrates ongoing risks in popular utility libraries"
        },
        %{
          id: "CVE-2021-23449",
          description: "VM2 sandbox escape vulnerability allowing remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "Shows that even sandboxed execution can be exploited"
        }
      ],
      detection_notes: """
      This pattern detects various forms of unsafe deserialization in JavaScript:
      
      1. JSON.parse() with user-controlled input - while generally safe, can lead
         to prototype pollution when combined with unsafe object operations
      2. YAML parsers (yaml.load, YAML.load) - extremely dangerous as they can
         execute arbitrary JavaScript code
      3. Custom deserialize/unserialize functions - often implement unsafe parsing
      4. Eval-based parsing - using eval() or Function() constructor with user data
      5. VM module usage - Node.js VM contexts with user-controlled code
      6. XML parsing functions - can lead to XXE and code injection
      
      The pattern specifically looks for these dangerous functions being called
      with common user input sources like req.body, params, query, userInput, etc.
      The detection prioritizes high-risk deserialization methods while trying
      to minimize false positives from safe usage patterns.
      """,
      safe_alternatives: [
        "Use JSON.parse() with try-catch and schema validation",
        "Replace yaml.load() with yaml.safeLoad() to disable code execution",
        "Implement strict schema validation using libraries like Ajv or Joi",
        "Use JSON Schema to validate structure before parsing",
        "Sanitize input by removing potentially dangerous properties",
        "Create objects without prototypes using Object.create(null)",
        "Use Map objects instead of plain objects when possible",
        "Implement allowlists for acceptable object properties",
        "Never use eval() or Function() constructor with user input",
        "Use static configuration files instead of dynamic user-provided configs"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming JSON.parse() is always safe (it's not with prototype pollution)",
          "Using yaml.load() instead of yaml.safeLoad() for user input",
          "Trusting data from internal APIs without validation",
          "Not validating nested object structures",
          "Using eval() for parsing JSON-like strings",
          "Implementing custom parsers without security considerations"
        ],
        secure_patterns: [
          "Always validate parsed data against a strict schema",
          "Use safeLoad() variants for YAML parsing",
          "Implement defense in depth with multiple validation layers",
          "Log and monitor deserialization failures",
          "Use Content-Type validation before parsing",
          "Implement timeouts for parsing operations",
          "Sandbox any code execution in isolated contexts",
          "Freeze prototypes of critical objects"
        ],
        framework_specific_risks: [
          "Express.js: Body parser middleware can expose deserialization endpoints",
          "Fastify: JSON schema validation should be enforced on all routes",
          "Next.js: API routes need careful input validation",
          "NestJS: DTO validation should use class-validator decorators",
          "Koa: Manual body parsing requires extra validation care",
          "Socket.io: Real-time data exchange needs continuous validation",
          "GraphQL: Complex nested queries can hide deserialization risks"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing deserialization operations.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for deserialization operations
      content != nil ->
        String.contains?(content, "JSON.parse") || 
        String.contains?(content, "yaml.load") ||
        String.contains?(content, "deserialize") ||
        String.contains?(content, "eval(") ||
        String.contains?(content, "new Function")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual insecure deserialization
  and safe parsing practices with proper validation.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.ast_enhancement()
      iex> is_list(enhancement.ast_rules.callee_patterns.json_parsers)
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.InsecureDeserialization.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_patterns: %{
          json_parsers: [
            "JSON.parse",
            "JSON.parseObject",
            "jsonParse"
          ],
          yaml_parsers: [
            "yaml.load",         # Dangerous
            "YAML.load",
            "yamljs.load",
            "js-yaml.load",
            "loadYaml"
          ],
          xml_parsers: [
            "xmlParse",
            "parseXML",
            "xml2js.parseString",
            "xmlParser.parse",
            "parseXmlString"
          ],
          eval_functions: [
            "eval",
            "Function",
            "vm.runInContext",
            "vm.runInNewContext",
            "vm.Script"
          ],
          custom_deserializers: [
            "deserialize",
            "unserialize",
            "fromJSON",
            "parseObject",
            "reconstruct"
          ]
        },
        argument_analysis: %{
          check_user_input: true,
          user_input_patterns: [
            "req.body",
            "request.body",
            "req.params",
            "request.params",
            "req.query",
            "request.query",
            "req",
            "request",
            "params",
            "query",
            "body",
            "user",
            "input",
            "data",
            "payload",
            "userInput",
            "userData"
          ]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/fixtures/,
          ~r/mocks/,
          ~r/examples/,
          ~r/docs/,
          ~r/migrations/,
          ~r/seeds/
        ],
        safe_patterns: [
          "yaml.safeLoad",      # Safe YAML parsing
          "YAML.safeLoad",
          "yamljs.safeLoad",
          "js-yaml.safeLoad",
          "ajv.validate",       # Schema validation
          "joi.validate",
          "validateSchema",
          "schemaValidation",
          "sanitize",
          "escape",
          "DOMPurify",
          "validator",
          "express-validator"
        ],
        check_validation: true,
        validation_patterns: [
          "validate",           # Validation functions
          "sanitize",
          "clean",
          "filter",
          "check",
          "verify",
          "assert",
          "ensure"
        ],
        check_hardcoded: true,
        hardcoded_indicators: [
          "const config =",     # Hardcoded configurations
          "static",
          "default",
          "constant",
          "hardcoded",
          "fixture",
          "'{'",               # Literal JSON strings
          "\"{",
          "`{`"
        ]
      },
      confidence_rules: %{
        base: 0.7,  # High base - deserialization is dangerous
        adjustments: %{
          "yaml_load" => 0.5,                   # Very dangerous
          "eval_deserialization" => 0.5,        # Extremely dangerous
          "xml_external_entities" => 0.4,       # XXE risk
          "user_input" => 0.3,                  # Direct user input
          "no_validation" => 0.3,               # No validation seen
          "vm_execution" => 0.4,                # VM module usage
          "safe_yaml" => -0.9,                  # Using safeLoad
          "schema_validation" => -0.7,          # Schema validation present
          "test_code" => -0.8,                  # Test files
          "hardcoded_input" => -0.6,            # Hardcoded values
          "wrapped_in_try_catch" => -0.3,      # Error handling
          "input_sanitization" => -0.5,         # Sanitization present
          "trusted_source" => -0.4,             # Internal APIs
          "configuration_file" => -0.3          # Config files less risky
        }
      },
      min_confidence: 0.8  # High threshold - many false positives possible
    }
  end
  
end