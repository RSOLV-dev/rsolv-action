defmodule RsolvApi.Security.Patterns.Javascript.PrototypePollution do
  @moduledoc """
  Prototype Pollution in JavaScript/Node.js
  
  Detects dangerous patterns like:
    obj[key] = value
    Object.assign(config, req.body)
    merge(target, userInput)
    
  Safe alternatives:
    if (!key.includes('__proto__')) { obj[key] = value }
    Object.assign(config, sanitize(req.body))
    const safe = Object.create(null); safe[key] = value
    
  Prototype pollution is a vulnerability specific to JavaScript that allows attackers 
  to inject properties into existing JavaScript language construct prototypes, such as 
  objects. An attacker manipulates these prototypes to cause the application to execute 
  attacker-controlled property values, potentially leading to denial of service or 
  remote code execution.
  
  ## Vulnerability Details
  
  Prototype pollution occurs when an application recursively merges or assigns user 
  input to JavaScript objects without proper validation, particularly when handling 
  nested objects that may contain special property names like `__proto__`, `constructor`, 
  or `prototype`. This can allow attackers to modify the behavior of all objects 
  inheriting from the polluted prototype.
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct object property assignment
  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === 'object') {
        target[key] = merge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key]; // <- Dangerous assignment
      }
    }
    return target;
  }
  
  // Attack payload:
  const maliciousPayload = {
    "__proto__": {
      "isAdmin": true,
      "polluted": "value"
    }
  };
  
  merge({}, maliciousPayload);
  
  // Now ALL objects inherit the polluted properties:
  console.log({}.isAdmin); // true
  console.log({}.polluted); // "value"
  ```
  
  ### Modern Attack Scenarios
  Prototype pollution vulnerabilities are particularly dangerous in Node.js applications 
  where they can lead to privilege escalation, authentication bypass, denial of service, 
  and in some cases remote code execution. Common attack vectors include manipulating 
  Express.js middleware configuration, polluting template engine options, bypassing 
  security checks, and corrupting application state.
  
  The vulnerability is especially prevalent in applications that:
  - Use utilities like lodash.merge, Object.assign with user input
  - Process JSON configuration files from user input
  - Implement custom object merging or cloning functions
  - Use recursive assignment patterns without key validation
  - Process URL query parameters that get merged into objects
  
  Modern frameworks and libraries have increasingly implemented protections against 
  prototype pollution, but legacy code and custom implementations remain vulnerable. 
  The attack surface has expanded with the popularity of JSON APIs, configuration 
  management systems, and microservice architectures that frequently merge user-provided 
  data structures.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the prototype pollution detection pattern.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.PrototypePollution.pattern()
      iex> pattern.id
      "js-prototype-pollution"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.PrototypePollution.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.PrototypePollution.pattern()
      iex> vulnerable = "obj[key] = value"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.PrototypePollution.pattern()
      iex> vulnerable = "Object.assign(config, req.body)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.PrototypePollution.pattern()
      iex> safe = "map.set(key, value)"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def pattern do
    %Pattern{
      id: "js-prototype-pollution",
      name: "Prototype Pollution",
      description: "Unsafe object property assignment can pollute object prototypes",
      type: :deserialization,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Simplified regex that catches bracket notation assignment and common merge patterns
      # AST enhancement will filter false positives like safe key validation
      regex: ~r/^(?!.*\/\/).*(?:\[[^\]]+\]\s*=|Object\.assign\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.|payload\.|user|input|data)|\bmerge\s*\([^,)]+,\s*(?:params\b|user\b|input\b|data\b|payload\b))|(?:_\.|lodash\.)(merge|extend)\s*\([^,)]+,\s*[^)]+|(?:\$|jQuery)\.extend\s*\([^,)]+,\s*(?:user|input|.*Data\b)|\bfor\s*\([^)]*\bin\s+(?:req\.|request\.|params\.|query\.|body\.).*\[[^\]]+\]\s*=/mi,
      default_tier: :enterprise,
      cwe_id: "CWE-1321",
      owasp_category: "A08:2021",
      recommendation: "Validate object keys, avoid direct property assignment with user input.",
      test_cases: %{
        vulnerable: [
          "obj[key] = value",
          "Object.assign(config, req.body)",
          "target[userKey] = userValue",
          "_.merge(config, userInput)",
          "for (let key in req.body) { config[key] = req.body[key] }",
          "Object.assign(settings, request.data)",
          "merge(target, params)",
          "config[req.query.prop] = req.query.value",
          "lodash.merge(options, body.config)",
          "jQuery.extend(config, userData)",
          "Object.assign(options, req.params)"
        ],
        safe: [
          "// if (!key.includes('__proto__')) { obj[key] = value }",
          "const safe = Object.create(null); // safe[key] = value",
          "Object.assign(config, sanitize(req.body))",
          "const filtered = pick(req.body, ALLOWED_KEYS)",
          "// if (SAFE_KEYS.includes(key)) obj[key] = value",
          "merge(target, sanitizedData)",
          "merge(target, validateInput(userInput))",
          "const whitelist = ['name', 'email']; config = pick(input, whitelist)",
          "map.set(key, value)",
          "array.push(value)",
          "obj.method(key, value)"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for prototype pollution vulnerabilities.
  
  This metadata documents the critical security implications of unsafe object 
  property assignment patterns and provides authoritative guidance for secure 
  object manipulation in JavaScript applications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Prototype pollution represents a critical vulnerability class specific to 
      JavaScript that exploits the language's prototype-based inheritance system 
      to inject malicious properties into object prototypes. Unlike traditional 
      injection attacks that target specific application components, prototype 
      pollution can affect the global state of JavaScript applications, making 
      it an extremely powerful and dangerous attack vector.
      
      The vulnerability stems from JavaScript's dynamic nature and prototype chain 
      mechanism, where objects inherit properties from their prototypes. When 
      applications merge or assign user-controlled data to objects without proper 
      key validation, attackers can manipulate special property names like 
      `__proto__`, `constructor`, or `prototype` to modify the behavior of all 
      objects inheriting from the polluted prototype.
      
      Prototype pollution is particularly devastating in Node.js server-side 
      applications where a single successful attack can compromise the entire 
      application instance. The attack can lead to authentication bypass, privilege 
      escalation, denial of service, and in sophisticated scenarios, remote code 
      execution through template engine exploitation or configuration manipulation.
      
      The complexity of modern JavaScript applications, with their extensive use 
      of object merging utilities, JSON configuration processing, and dynamic 
      property assignment, has significantly expanded the attack surface for 
      prototype pollution. Popular libraries like lodash, jQuery, and numerous 
      npm packages have historically contained prototype pollution vulnerabilities, 
      affecting millions of applications worldwide.
      
      The subtlety of prototype pollution makes it particularly dangerous, as 
      polluted properties may not immediately manifest their effects, leading to 
      delayed exploitation and difficult-to-debug security issues. The global 
      nature of prototype pollution means that a single vulnerable code path can 
      compromise the security assumptions of entirely unrelated application 
      components, making comprehensive protection essential.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-1321",
          title: "Improperly Controlled Modification of Object Prototype Attributes",
          url: "https://cwe.mitre.org/data/definitions/1321.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :research,
          id: "prototype_pollution_snyk",
          title: "Prototype pollution attack in NodeJS applications",
          url: "https://learn.snyk.io/lessons/prototype-pollution/javascript/"
        },
        %{
          type: :vendor,
          id: "portswigger_prototype_pollution",
          title: "PortSwigger Web Security Academy - Prototype pollution",
          url: "https://portswigger.net/web-security/prototype-pollution"
        },
        %{
          type: :nist,
          id: "SP_800-53_SI-10",
          title: "NIST SP 800-53 - Information Input Validation",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        },
        %{
          type: :research,
          id: "blackhat_prototype_pollution",
          title: "Prototype pollution attacks in NodeJS applications",
          url: "https://github.com/HoLyVieR/prototype-pollution-nsec18"
        }
      ],
      attack_vectors: [
        "JSON payload injection: Malicious JSON containing __proto__ properties",
        "Query parameter pollution: URL parameters that get merged into configuration objects",
        "Form data manipulation: POST data with polluting property names in nested structures",
        "Configuration file injection: Malicious configuration data processed by merging utilities",
        "API endpoint abuse: REST API calls that merge request bodies into application state",
        "Template data pollution: Polluting template engine options to achieve code execution",
        "Middleware poisoning: Corrupting Express.js or similar middleware configuration",
        "Package.json manipulation: Exploiting npm install or package processing vulnerabilities"
      ],
      real_world_impact: [
        "Authentication bypass: Polluting properties that control authentication logic",
        "Privilege escalation: Injecting admin flags or role properties into user objects",
        "Denial of service: Polluting properties that cause application crashes or infinite loops",
        "Remote code execution: Exploiting template engines or eval-like functionality",
        "Configuration corruption: Modifying security settings or feature flags globally",
        "Data integrity compromise: Polluting validation logic or sanitization functions",
        "Session hijacking: Manipulating session handling or token validation mechanisms",
        "Business logic bypass: Corrupting application state to bypass payment or access controls"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-0144",
          description: "Prototype pollution in shelljs package affecting command execution",
          severity: "high",
          cvss: 7.1,
          note: "Allows arbitrary command execution through polluted shell options"
        },
        %{
          id: "CVE-2021-25928",
          description: "Prototype pollution in flat package used for object flattening",
          severity: "high", 
          cvss: 7.5,
          note: "Enables denial of service through polluted object properties"
        },
        %{
          id: "CVE-2020-28499",
          description: "Prototype pollution in lodash merge function",
          severity: "medium",
          cvss: 6.5,
          note: "One of the most widespread prototype pollution vulnerabilities affecting millions of applications"
        },
        %{
          id: "CVE-2019-10744",
          description: "Prototype pollution in lodash defaultsDeep function",
          severity: "critical",
          cvss: 9.1,
          note: "Critical vulnerability allowing property injection in widely-used utility library"
        },
        %{
          id: "CVE-2018-3721",
          description: "Prototype pollution in Hoek library deep merge functionality",
          severity: "medium",
          cvss: 5.6,
          note: "Early prominent example demonstrating prototype pollution in utility libraries"
        }
      ],
      detection_notes: """
      This pattern detects unsafe object property assignment and merging operations 
      that are susceptible to prototype pollution attacks. The detection covers:
      
      1. Dynamic property assignment: obj[key] = value patterns
      2. Object.assign with user input: Object.assign(target, userInput)
      3. Merge utility usage: _.merge, lodash.merge, jQuery.extend
      4. For-in loops: for (key in userInput) assignment patterns
      5. Direct user input merging: Functions receiving req.body, params, query data
      
      The regex pattern identifies property assignment using bracket notation followed 
      by assignment operators, Object.assign calls with user-controlled source objects, 
      common merge utility invocations, and for-in iteration patterns that directly 
      assign user input to target objects.
      
      The detection prioritizes high sensitivity to catch various object manipulation 
      patterns while focusing on scenarios where user-controlled data flows into 
      object property assignment operations. Special attention is given to Express.js 
      request object properties (req.body, req.query, req.params) and other common 
      user input sources.
      """,
      safe_alternatives: [
        "Validate property names: Check keys against __proto__, constructor, prototype",
        "Use Object.create(null): Create objects without prototype chains",
        "Implement property whitelists: Only allow specific, safe property names",
        "Use Map objects: Maps don't have prototype pollution vulnerabilities",
        "Sanitize input objects: Remove dangerous properties before merging",
        "Use schema validation: Validate object structure and property names",
        "Implement deep freezing: Freeze prototype objects to prevent modification",
        "Use safe merge libraries: Libraries with built-in prototype pollution protection",
        "Apply strict property assignment: Use defineProperty with non-configurable properties"
      ],
      additional_context: %{
        framework_specific_risks: [
          "Express.js: Request body parsing automatically creates nested objects",
          "Next.js: Server-side props and API routes vulnerable to pollution",
          "Nuxt.js: SSR context and module configuration susceptible to pollution",
          "Gatsby: Build-time data processing vulnerable to polluted configurations",
          "React SSR: Server-side rendering props can be polluted affecting hydration",
          "Vue.js SSR: Server-side data injection vulnerable to prototype pollution",
          "Electron: IPC message handling can introduce prototype pollution vectors"
        ],
        common_vulnerable_patterns: [
          "Configuration merging: Merging user-provided config with default settings",
          "Plugin systems: Dynamic plugin configuration loading and merging",
          "Template data binding: User data merged into template rendering contexts",
          "API response transformation: Converting user input to response object structures",
          "Form processing: Converting form data to JavaScript objects",
          "JSON schema processing: Validating and merging JSON against schemas",
          "Cache key generation: Using user input to construct cache key objects"
        ],
        exploitation_techniques: [
          "Constructor pollution: Targeting constructor.prototype for global effects",
          "Proto pollution: Using __proto__ to directly modify prototype chains",
          "Nested pollution: Deep object merging to reach prototype properties",
          "Numeric indices: Using array-like notation to pollute Array prototypes",
          "Symbol pollution: Exploiting Symbol-based property keys in modern applications",
          "Async pollution: Timing attacks using async object processing",
          "Conditional pollution: Exploiting conditional object assignment logic"
        ],
        detection_evasion: [
          "Property name encoding: Using encoded or obfuscated property names",
          "Indirect assignment: Using intermediate variables or functions",
          "Computed properties: Using bracket notation with computed property names",
          "Proxy objects: Using Proxy handlers to intercept and modify assignments",
          "Descriptor manipulation: Using Object.defineProperty for stealthy pollution",
          "Inheritance chains: Targeting specific points in complex inheritance hierarchies"
        ],
        remediation_steps: [
          "Audit all object merging and assignment operations for user input usage",
          "Implement comprehensive input validation including property name validation",
          "Replace vulnerable libraries with secure alternatives or updated versions",
          "Add runtime protection using Object.freeze on critical prototypes",
          "Implement Content Security Policy headers to limit execution contexts",
          "Use static analysis tools to identify potential prototype pollution vectors",
          "Add monitoring for unexpected prototype modifications in production",
          "Train development teams on secure object manipulation practices"
        ],
        testing_strategies: [
          "Use automated prototype pollution scanners and security testing tools",
          "Test with malicious payloads containing __proto__ and constructor properties",
          "Verify object merging functions with nested pollution payloads",
          "Test API endpoints with JSON payloads designed to trigger pollution",
          "Implement fuzzing for object processing functions with prototype pollution vectors",
          "Create unit tests that verify prototype integrity after object operations"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual prototype pollution vulnerabilities and:
  - Key validation that checks for dangerous properties
  - Objects created without prototype chains (Object.create(null))
  - Use of Maps instead of objects
  - Schema validation that prevents dangerous keys
  - Frozen prototypes that can't be polluted
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PrototypePollution.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PrototypePollution.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "AssignmentExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PrototypePollution.ast_enhancement()
      iex> enhancement.ast_rules.left_side_analysis.is_computed_member_expression
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PrototypePollution.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.PrototypePollution.ast_enhancement()
      iex> "uses_map_not_object" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "AssignmentExpression",
        # Assigning to object properties dynamically
        left_side_analysis: %{
          is_computed_member_expression: true,  # obj[key] pattern
          has_prototype_chain_risk: true,       # Could affect __proto__
          uses_user_input_as_key: true
        },
        # Or object spread/merge with user input
        alternate_patterns: [
          %{type: "CallExpression", callee: ~r/Object\.(assign|merge)|_\.merge|merge/},
          %{type: "SpreadElement", in_object_expression: true}
        ]
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/polyfill/],
        exclude_if_prototype_frozen: true,    # Object.freeze on prototypes
        exclude_if_key_validated: true,       # Checking against __proto__, constructor
        exclude_if_using_map: true,          # Map instead of object
        exclude_if_schema_validated: true,    # JSON schema validation
        dangerous_keys: ["__proto__", "constructor", "prototype"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "direct_proto_assignment" => 0.6,
          "user_key_in_bracket_notation" => 0.4,
          "object_merge_with_user_data" => 0.3,
          "validates_against_proto" => -0.9,
          "uses_object_create_null" => -0.8,  # No prototype chain
          "has_schema_validation" => -0.7,
          "uses_map_not_object" => -1.0
        }
      },
      min_confidence: 0.7
    }
  end
  
end