defmodule RsolvApi.Security.Patterns.Javascript.UnsafeRegex do
  @moduledoc """
  Regular Expression Denial of Service (ReDoS) in JavaScript/Node.js
  
  Detects dangerous patterns like:
    new RegExp("(a+)+$")
    /(x+x+)+y/.test(input)
    const pattern = /(a*)*b/
    
  Safe alternatives:
    new RegExp("a+$")
    /x+y/.test(input)
    const pattern = /a*b/
    
  Regular Expression Denial of Service (ReDoS) is a security vulnerability that 
  exploits catastrophic backtracking in regular expression engines. When maliciously 
  crafted input is processed by vulnerable regex patterns, it can cause exponential 
  time complexity, leading to application freezes, CPU exhaustion, and denial of service.
  
  ## Vulnerability Details
  
  ReDoS attacks exploit specific regex patterns that create exponential backtracking:
  
  1. **Nested Quantifiers**: Patterns like (a+)+ or (a*)* create exponential states
  2. **Alternation with Overlap**: Patterns like (a|a)* where alternatives overlap
  3. **Catastrophic Backtracking**: Engine tries all possible matches exponentially
  4. **Evil Regex**: Patterns that can be exploited with specific malicious input
  
  ### Attack Example
  ```javascript
  // Vulnerable: Nested quantifiers
  const emailRegex = /([a-zA-Z0-9_\.-]+)+@/;
  const maliciousInput = "a".repeat(50000) + "X"; 
  emailRegex.test(maliciousInput); // <- Causes infinite loop/CPU spike
  
  // Vulnerable: Alternation with overlap
  const pattern = /(a|a)*b/;
  const payload = "a".repeat(30) + "c"; // No 'b' at end
  pattern.test(payload); // <- Exponential backtracking
  ```
  
  ### Modern Attack Scenarios
  ReDoS vulnerabilities are particularly dangerous in Node.js applications because 
  JavaScript is single-threaded. A single ReDoS attack can freeze the entire 
  application, affecting all users. Common targets include email validation, 
  URL parsing, input sanitization, log processing, and API parameter validation.
  
  The attack vectors have evolved with modern web applications, targeting 
  JSON parsing, GraphQL query validation, markdown processing, and route 
  matching systems where regex patterns process user-controlled input.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  def pattern do
    %Pattern{
      id: "js-unsafe-regex",
      name: "Regular Expression Denial of Service (ReDoS)",
      description: "Regex with nested quantifiers can cause exponential backtracking",
      type: :denial_of_service,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:new\s+RegExp|\/)[^)\/]*\([^)]*[*+].*?\)[^)]*[*+\{]|(?:new\s+RegExp|\/)[^)\/]*\([^)]*\{[^}]*\}.*?\)[^)]*[*+\{]|(?:new\s+RegExp|\/)[^)\/]*\([^)]*\|.*?\)[^)]*[*+\{]/i,
      cwe_id: "CWE-1333",
      owasp_category: "A05:2021",
      recommendation: "Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers.",
      test_cases: %{
        vulnerable: [
          "new RegExp(\"(a+)+$\")",
          "/(x+x+)+y/.test(input)",
          "const pattern = /(a*)*b/",
          "/^(a+)+$/.test(userInput)",
          "new RegExp(\"(.*a){20}\")",
          "/(a|a)*/.test(text)",
          "pattern = /(a|a)*b/",
          "new RegExp(\"(a*|a*)*)\")",
          "/(.*)*$/.test(input)",
          "/([a-zA-Z]+)*/.test(input)",
          "new RegExp(\"(\\\\d+)*\\\\d\")",
          "/(a+)+(b+)+c/.test(data)",
          "/([a-zA-Z0-9_\\.-]+)+@/",
          "new RegExp(\"(\\\\w+)+@(\\\\w+)+\\\\.\")",
          "/(\\w*)*@.*\\..*/.test(email)"
        ],
        safe: [
          "new RegExp(\"a+$\")",
          "/x+y/.test(input)",
          "const pattern = /a*b/",
          "/a++b/.test(input)",
          "new RegExp(\"\\\\d{1,10}\")",
          "/[a-z]+/.test(text)",
          "/(cat|dog)/.test(animal)",
          "new RegExp(\"(yes|no)\")",
          "/\\d+|\\w+/.test(input)",
          "/a{1,5}/.test(input)",
          "new RegExp(\"\\\\w{3,20}\")",
          "/[0-9]{1,3}/.test(number)",
          "/[a-zA-Z]+/.test(input)",
          "new RegExp(\"\\\\d+\")",
          "/\\w+@\\w+\\.\\w+/.test(email)"
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for ReDoS vulnerabilities.
  
  This metadata documents the critical security implications of regex patterns 
  that can cause catastrophic backtracking and provides authoritative guidance 
  for secure regular expression design.
  """
  def vulnerability_metadata do
    %{
      description: """
      Regular Expression Denial of Service (ReDoS) represents a critical 
      vulnerability class that exploits exponential time complexity in regex 
      pattern matching to cause application-level denial of service. Unlike 
      traditional DoS attacks that require high traffic volumes, ReDoS can be 
      triggered by a single maliciously crafted input string, making it an 
      extremely efficient attack vector against web applications.
      
      The vulnerability stems from the inherent design of backtracking regex 
      engines used in JavaScript and most programming languages. When processing 
      patterns with nested quantifiers or overlapping alternations, the engine 
      explores exponentially increasing numbers of possible match paths. Attackers 
      exploit this by providing input that maximizes backtracking without 
      producing successful matches, forcing the engine into worst-case behavior.
      
      ReDoS is particularly devastating in Node.js applications due to JavaScript's 
      single-threaded event loop architecture. A single ReDoS attack can freeze 
      the entire application, blocking all concurrent requests and effectively 
      taking the service offline. This amplifies the impact beyond traditional 
      DoS scenarios, where load balancing might mitigate individual server failures.
      
      Modern web applications are increasingly vulnerable due to the proliferation 
      of regex usage in input validation, data parsing, route matching, and content 
      processing. The complexity of contemporary regex patterns, combined with the 
      need to handle diverse user input formats, creates extensive attack surface 
      for ReDoS exploitation. Additionally, the adoption of microservices 
      architectures means that a single vulnerable regex pattern can cascade 
      failures across entire application ecosystems.
      
      The subtlety of ReDoS vulnerabilities makes them particularly insidious. 
      Patterns that appear reasonable and perform well under normal conditions 
      can exhibit catastrophic behavior when presented with specifically crafted 
      malicious input. This unpredictability, combined with the difficulty of 
      comprehensive testing against all possible input variations, makes ReDoS 
      a persistent and evolving threat in web application security.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-1333",
          title: "Inefficient Regular Expression Complexity",
          url: "https://cwe.mitre.org/data/definitions/1333.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :vendor,
          id: "MDN_REGEX",
          title: "MDN Web Docs - Regular Expression Performance",
          url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions"
        },
        %{
          type: :research,
          id: "redos_analysis",
          title: "Regular Expression Denial of Service - ReDoS",
          url: "https://www.checkmarx.com/knowledge/knowledgebase/ReDoS"
        },
        %{
          type: :nist,
          id: "SP_800-53_SC-5",
          title: "NIST SP 800-53 - Denial of Service Protection",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        },
        %{
          type: :sans,
          id: "redos_prevention",
          title: "SANS - Regular Expression Denial of Service Prevention",
          url: "https://www.sans.org/white-papers/redos-prevention/"
        }
      ],
      attack_vectors: [
        "Nested quantifier exploitation: Input designed to maximize backtracking in (a+)+ patterns",
        "Alternation overlap attacks: Crafted strings that exploit overlapping choices in (a|a)* patterns", 
        "Catastrophic backtracking induction: Inputs that force exponential state exploration",
        "Email regex attacks: Malformed email strings that trigger ReDoS in validation patterns",
        "URL parsing exploitation: Crafted URLs that cause ReDoS in routing or validation regex",
        "JSON field validation attacks: Malicious JSON values that trigger ReDoS in parsing logic",
        "Search query exploitation: Search terms designed to trigger ReDoS in content filtering",
        "File upload attacks: Malicious filename patterns that cause ReDoS in validation regex"
      ],
      real_world_impact: [
        "Complete application freeze: Single-threaded JavaScript applications become unresponsive",
        "Service unavailability: API endpoints become inaccessible due to blocking regex operations",
        "Resource exhaustion: CPU usage spikes to 100% causing server instability",
        "Cascading failures: ReDoS in one service can trigger timeouts and failures in dependent services",
        "User experience degradation: Application becomes slow or completely unusable",
        "Financial impact: Service downtime results in revenue loss and SLA violations",
        "Security monitoring bypass: ReDoS attacks can overwhelm logging and monitoring systems",
        "Load balancer saturation: Multiple ReDoS attacks can exhaust load balancer capacity"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-25851",
          description: "jpeg-js npm package ReDoS vulnerability in file type validation regex",
          severity: "high",
          cvss: 7.5,
          note: "Malicious JPEG files could trigger ReDoS via nested quantifiers in metadata parsing"
        },
        %{
          id: "CVE-2021-3807",
          description: "ansi-regex npm package ReDoS vulnerability affecting terminal output processing",
          severity: "high", 
          cvss: 7.5,
          note: "Malformed ANSI escape sequences could cause catastrophic backtracking"
        },
        %{
          id: "CVE-2020-28469",
          description: "glob-parent npm package ReDoS in path globbing regex patterns",
          severity: "high",
          cvss: 7.5,
          note: "Crafted glob patterns could trigger exponential backtracking in path processing"
        },
        %{
          id: "CVE-2019-20838",
          description: "trim npm package ReDoS vulnerability in whitespace trimming regex",
          severity: "medium",
          cvss: 6.5,
          note: "Malicious whitespace patterns could cause performance degradation"
        },
        %{
          id: "CVE-2018-1000620",
          description: "Cryprtographically Secure Pseudo-Random Number Generator (CSPRNG) ReDoS in crypto operations",
          severity: "medium",
          cvss: 5.3,
          note: "ReDoS in cryptographic input validation could impact security operations"
        }
      ],
      detection_notes: """
      This pattern detects regular expressions with nested quantifiers that are 
      susceptible to catastrophic backtracking. The detection covers:
      
      1. Nested plus quantifiers: (a+)+ patterns
      2. Nested star quantifiers: (a*)* patterns  
      3. Mixed nested quantifiers: (a+)* or (a*)+ patterns
      4. RegExp constructor with nested quantifiers
      5. Literal regex patterns with nested quantifiers
      6. Complex nested structures with multiple quantifier levels
      
      The regex pattern looks for quantifier characters (+, *, {n,m}) followed by 
      closing parentheses and then additional quantifiers, indicating nested 
      quantification structures. It uses case-insensitive matching and handles 
      both literal regex syntax (/pattern/) and RegExp constructor patterns.
      
      The detection is designed for high sensitivity to catch potentially vulnerable 
      patterns while minimizing false positives on legitimate bounded quantifiers 
      and non-overlapping alternations. However, some complex ReDoS patterns may 
      require additional analysis beyond basic pattern matching.
      """,
      safe_alternatives: [
        "Use bounded quantifiers: {1,10} instead of + or * to limit backtracking",
        "Avoid nested quantifiers: Rewrite (a+)+ as a+ with proper bounds",
        "Use atomic groups where supported: (?>a+) prevents backtracking",
        "Implement input length limits before regex processing to bound execution time",
        "Use non-backtracking regex engines or libraries where available",
        "Replace complex regex with string manipulation methods for simple cases",
        "Implement regex timeout mechanisms to prevent indefinite blocking",
        "Use regex analysis tools to identify potentially vulnerable patterns",
        "Test regex patterns with worst-case input scenarios during development"
      ],
      additional_context: %{
        framework_specific_risks: [
          "Express.js: ReDoS in route parameter validation affecting request routing",
          "Next.js: ReDoS in dynamic route matching causing page load failures", 
          "React: ReDoS in input validation hooks affecting form processing",
          "Vue.js: ReDoS in template directive parsing causing render blocking",
          "Angular: ReDoS in form validators affecting user interface responsiveness",
          "Node.js APIs: ReDoS in request parsing affecting server stability",
          "GraphQL: ReDoS in query validation affecting API performance"
        ],
        common_vulnerable_patterns: [
          "Email validation regex with nested quantifiers in address parsing",
          "URL validation patterns with complex domain matching logic",
          "Phone number validation with international format support",
          "Credit card number validation with flexible formatting",
          "Password strength validation with complex character class requirements",
          "HTML tag stripping with nested element matching",
          "Log parsing regex with flexible timestamp and message formats"
        ],
        exploitation_techniques: [
          "Linear growth input: Provide input length that grows linearly but causes exponential processing",
          "Non-matching suffixes: Add characters at the end that prevent successful matches",
          "Prefix matching: Use prefixes that match the beginning but fail overall pattern",
          "Character class exploitation: Use edge cases in character ranges to maximize backtracking",
          "Unicode exploitation: Use Unicode characters to trigger unexpected behavior",
          "Length amplification: Use minimum length inputs that trigger maximum processing time",
          "Boundary condition testing: Target regex anchors and word boundaries for edge cases"
        ],
        performance_characteristics: [
          "Linear patterns: O(n) time complexity with input length",
          "Vulnerable patterns: O(2^n) exponential time complexity in worst case",
          "Backtracking depth: Can reach thousands of recursive calls",
          "Memory impact: Stack overflow possible in deeply nested backtracking",
          "CPU utilization: Single-core saturation during ReDoS attack",
          "Response time degradation: Seconds to minutes for small malicious inputs"
        ],
        detection_evasion: [
          "Dynamic regex construction: Building patterns at runtime to avoid static analysis",
          "Regex concatenation: Combining safe fragments that become dangerous together",
          "Conditional patterns: Using different regex based on input characteristics",
          "Library indirection: ReDoS patterns hidden in third-party validation libraries",
          "Configuration-based patterns: Vulnerable regex defined in config files",
          "Template-generated regex: Patterns created from user-configurable templates"
        ],
        remediation_steps: [
          "Audit all regex patterns for nested quantifiers and overlapping alternations",
          "Implement comprehensive ReDoS testing with malicious input generation",
          "Add regex execution timeouts to prevent indefinite blocking",
          "Replace vulnerable patterns with safer alternatives or string methods",
          "Use regex analysis tools to identify potential ReDoS vulnerabilities",
          "Implement input sanitization and length limits before regex processing",
          "Add monitoring for unusual regex execution times in production",
          "Train development teams on secure regex design principles"
        ],
        testing_strategies: [
          "Generate worst-case inputs using ReDoS testing tools",
          "Measure regex execution time under various input conditions", 
          "Test with exponentially growing input sizes to identify O(2^n) patterns",
          "Use fuzzing tools to generate malicious regex input automatically",
          "Implement performance regression testing for regex-heavy code paths",
          "Create unit tests with known ReDoS payloads for pattern validation"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing regex operations.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for regex operations
      content != nil ->
        String.contains?(content, "RegExp") || 
        String.contains?(content, ".test(") ||
        String.contains?(content, ".match(") ||
        # Look for regex literal syntax
        Regex.match?(~r/\/[^\/]+\/[gimuy]*/, content)
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual ReDoS vulnerabilities
  and safe regex patterns or test code.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.UnsafeRegex.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.UnsafeRegex.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "NewExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.UnsafeRegex.ast_enhancement()
      iex> enhancement.ast_rules.regex_analysis.check_nested_quantifiers
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.UnsafeRegex.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "NewExpression",  # new RegExp() calls
        alternate_node_types: ["RegExpLiteral"],  # /pattern/ syntax
        callee_check: %{
          name: "RegExp"
        },
        regex_analysis: %{
          check_nested_quantifiers: true,
          check_overlapping_alternation: true,
          check_unbounded_repetition: true,
          dangerous_patterns: [
            "(\\w+)+",      # Nested plus quantifiers
            "(\\w*)*",      # Nested star quantifiers
            "(\\w+)*",      # Mixed quantifiers
            "(a|a)*",       # Overlapping alternation
            "(.*)+",        # Greedy nested quantifiers
            "(.+)+",        # Multiple greedy quantifiers
            "{\\d+,}+"      # Unbounded curly brace with quantifier
          ],
          safe_indicators: [
            "{1,",          # Bounded quantifiers
            "{0,",          # Explicit bounds
            "(?:",          # Non-capturing groups
            "(?=",          # Lookahead assertions
            "(?!",          # Negative lookahead
            "(?<=",         # Lookbehind assertions
            "(?<!",         # Negative lookbehind
            "\\b",          # Word boundaries
            "^", "$"        # Anchors
          ]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/__mocks__/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/docs/,
          ~r/benchmark/,
          ~r/perf/
        ],
        safe_patterns: [
          "sanitize-regex",     # Safe regex library
          "safe-regex",         # ReDoS prevention library
          "re2",                # Non-backtracking regex engine
          "node-re2",           # Node.js RE2 binding
          "regex-timeout",      # Timeout protection
          "redos-detector",     # ReDoS detection library
          "vuln-regex-detector" # Vulnerability detection
        ],
        check_usage_context: true,
        safe_contexts: [
          "regex_test",         # Testing regex patterns
          "performance_test",   # Performance benchmarks
          "validation_library", # Validation framework
          "static_analysis",    # Code analysis tools
          "linter",            # Linting rules
          "formatter"          # Code formatters
        ],
        check_input_source: true,
        trusted_sources: [
          "constants",          # Hardcoded patterns
          "configuration",      # Config files
          "allowlist",          # Predefined safe values
          "sanitized"           # Pre-sanitized input
        ]
      },
      confidence_rules: %{
        base: 0.6,  # Medium-high base - ReDoS can be subtle
        adjustments: %{
          "nested_quantifiers" => 0.4,          # Strong indicator
          "overlapping_alternation" => 0.4,     # Strong indicator
          "unbounded_repetition" => 0.3,        # Medium indicator
          "complex_pattern" => 0.2,             # Pattern complexity
          "user_input" => 0.3,                  # Processing user data
          "bounded_quantifiers" => -0.5,        # Safe pattern
          "test_file" => -0.6,                  # Test code OK
          "safe_library" => -0.8,               # Using safe regex lib
          "static_pattern" => -0.3,             # Hardcoded patterns
          "input_validation" => -0.4,           # Has input limits
          "timeout_protection" => -0.7,         # Has timeout mechanism
          "non_backtracking_engine" => -0.9,   # Using RE2 or similar
          "performance_monitoring" => -0.3      # Monitoring in place
        }
      },
      min_confidence: 0.75  # High threshold - ReDoS needs careful analysis
    }
  end
  
end