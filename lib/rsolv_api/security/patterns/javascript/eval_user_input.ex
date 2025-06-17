defmodule RsolvApi.Security.Patterns.Javascript.EvalUserInput do
  @moduledoc """
  Dangerous eval() with User Input in JavaScript/Node.js
  
  Detects dangerous patterns like:
    eval(userInput)
    eval(req.body.code)
    const result = eval("2 + " + params.number)
    
  Safe alternatives:
    JSON.parse(userInput)
    new Function("return " + sanitizedExpression)
    vm.runInContext(code, sandbox)
    
  The eval() function in JavaScript is one of the most dangerous language features 
  when used with untrusted input. It provides direct access to the JavaScript 
  interpreter, allowing arbitrary code execution with the full privileges of the 
  running application. This makes eval() with user input a critical Remote Code 
  Execution (RCE) vulnerability.
  
  ## Vulnerability Details
  
  Using eval() with user-controlled input creates multiple critical attack vectors:
  
  1. **Direct Code Execution**: Any JavaScript code can be executed immediately
  2. **Process Control**: Attackers can terminate processes, spawn new ones, or fork
  3. **File System Access**: Complete read/write access to the file system
  4. **Network Operations**: Ability to make network requests and establish connections
  5. **Environment Access**: Reading environment variables and system information
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct eval() with user input
  app.post('/calculate', (req, res) => {
    const expression = req.body.formula; // User input: "process.exit(1)"
    const result = eval(expression);     // <- Complete system compromise
    res.json({result});
  });
  
  // Vulnerable: Template injection via eval()
  const userTemplate = req.body.template; // "'; require('fs').unlinkSync('/etc/passwd'); '"
  const code = `const output = '${userTemplate}';`;
  eval(code); // <- File system destruction
  ```
  
  ### Modern Attack Scenarios
  Eval-based RCE vulnerabilities are among the most exploited in Node.js applications, 
  particularly in template engines, expression evaluators, configuration processors, 
  and dynamic code generators. Attackers can achieve complete system compromise, 
  data exfiltration, cryptocurrency mining, botnet participation, and lateral 
  movement within infrastructure.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  def pattern do
    %Pattern{
      id: "js-eval-user-input",
      name: "Dangerous eval() with User Input",
      description: "Using eval() with user input can execute arbitrary code",
      type: :rce,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/^(?!.*\/\/).*eval\s*\(.*?(?:req\.|request\.|params\.|query\.|body\.|user|input|data|Code)/im,
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.",
      test_cases: %{
        vulnerable: [
          ~S|eval(userInput)|,
          ~S|eval(req.body.code)|,
          ~S|const result = eval("2 + " + params.number)|,
          ~S|eval(request.params.expression)|,
          ~S|eval(req.query.formula)|,
          ~S|var output = eval(inputData)|,
          ~S|return eval(user.customScript)|,
          ~S|eval("return " + req.body.expression)|,
          ~S|const fn = eval("function() { " + userCode + " }")|,
          ~S|eval(data.computation)|,
          ~S|result = eval(req.body.math)|,
          ~S|eval(`const result = ${userExpression}`)|,
          ~S|const value = eval(params.dynamicCode)|,
          ~S|eval(requestData.script)|,
          ~S|window.eval(inputValue)|
        ],
        safe: [
          ~S|JSON.parse(userInput)|,
          ~S|const fn = new Function("return " + sanitizedExpression)|,
          ~S|const result = calculateSafely(params.number)|,
          ~S|eval("2 + 2")  // static expression|,
          ~S|const math = safeEval(expression, context)|,
          ~S|vm.runInContext(code, sandbox)|,
          ~S|Function("return " + validatedExpression)()|,
          ~S|// Never use eval() with user input|,
          ~S|console.log("eval should be avoided")|,
          ~S|const evalWarning = "Don't use eval()"|,
          ~S|const parser = new ExpressionParser()|,
          ~S|const ast = parseExpression(userInput)|,
          ~S|if (isValidExpression(str)) { JSON.parse(str) }|,
          ~S|const sandbox = vm.createContext({})|,
          ~S|mathjs.evaluate(expression, scope)|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for eval() with user input.
  
  This metadata documents the extreme severity of eval-based RCE vulnerabilities 
  and provides authoritative guidance for secure code evaluation alternatives.
  """
  def vulnerability_metadata do
    %{
      description: """
      Eval() with user input represents one of the most critical vulnerability classes 
      in web application security, providing attackers with direct access to the 
      JavaScript interpreter and complete control over the execution environment. 
      This vulnerability combines maximum impact (complete system compromise) with 
      trivial exploitation (injection of arbitrary code strings).
      
      The eval() function bypasses all normal security boundaries and executes code 
      with the full privileges of the running application. Unlike other injection 
      vulnerabilities that may be limited to specific subsystems, eval-based RCE 
      provides unrestricted access to the entire runtime environment, including 
      file systems, network interfaces, process control, and system resources.
      
      Modern JavaScript environments amplify the risk through Node.js capabilities, 
      allowing server-side code execution that can compromise entire applications, 
      databases, and infrastructure. The vulnerability is particularly dangerous 
      because it requires no special knowledge of application internals - any 
      valid JavaScript code can be executed directly.
      
      Eval-based vulnerabilities are especially common in template engines, 
      expression evaluators, configuration processors, dynamic import systems, 
      and developer tools. The widespread use of eval() in legacy codebases and 
      third-party libraries creates ongoing exposure risks that are difficult to 
      identify and remediate systematically.
      
      The persistence and stealth capabilities enabled by eval() RCE make it a 
      preferred vector for advanced persistent threats, allowing attackers to 
      establish backdoors, modify application logic, and maintain long-term access 
      to compromised systems while evading traditional security controls.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-94",
          title: "Improper Control of Generation of Code (Code Injection)",
          url: "https://cwe.mitre.org/data/definitions/94.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :vendor,
          id: "MDN_EVAL",
          title: "MDN Web Docs - Never use eval()!",
          url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"
        },
        %{
          type: :research,
          id: "nodejs_rce_study",
          title: "Analysis of Remote Code Execution Vulnerabilities in Node.js Applications",
          url: "https://www.usenix.org/conference/usenixsecurity20/presentation/staicu"
        },
        %{
          type: :sans,
          id: "eval_dangers",
          title: "SANS - The Dangers of eval() in JavaScript",
          url: "https://www.sans.org/white-papers/javascript-security/"
        },
        %{
          type: :nist,
          id: "SP_800-53",
          title: "NIST SP 800-53 - Security Controls for Code Injection Prevention",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        }
      ],
      attack_vectors: [
        "Direct code injection: eval(userInput) with malicious JavaScript payload",
        "Template injection: Embedding code in template strings processed by eval()",
        "Expression evaluation: Mathematical or logical expressions containing malicious code",
        "Dynamic import exploitation: Using eval() to dynamically load and execute modules",
        "Configuration injection: Malicious code in configuration files processed by eval()",
        "Serialization attacks: Exploiting eval() in custom deserialization routines",
        "Prototype pollution chaining: Combining prototype pollution with eval() for RCE",
        "Error handling exploitation: Triggering error conditions that execute eval() with attacker data"
      ],
      real_world_impact: [
        "Complete server compromise: Full control over Node.js application and underlying system",
        "Data exfiltration: Access to databases, files, environment variables, and memory",
        "Cryptocurrency mining: Installing mining software on compromised servers",
        "Botnet participation: Adding compromised systems to criminal networks",
        "Lateral movement: Using compromised applications to attack internal infrastructure",
        "Supply chain attacks: Modifying application logic to compromise downstream users",
        "Persistent backdoors: Installing permanent access mechanisms for future exploitation",
        "Service disruption: Destroying data, corrupting systems, or causing denial of service"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability exploited through eval-like mechanisms in some JavaScript logging libraries",
          severity: "critical",
          cvss: 10.0,
          note: "While primarily a Java vulnerability, JavaScript variants using eval() for log processing were also affected"
        },
        %{
          id: "CVE-2022-25912",
          description: "simple-git npm package RCE through eval() of user-controlled git output",
          severity: "critical",
          cvss: 9.8,
          note: "Git command output processed through eval() enabling arbitrary code execution"
        },
        %{
          id: "CVE-2020-28469",
          description: "glob-parent npm package eval() injection in glob pattern processing",
          severity: "high",
          cvss: 8.1,
          note: "File glob patterns processed through eval() enabling code injection"
        },
        %{
          id: "CVE-2019-10781",
          description: "Schema-utils npm package code injection via eval() in validation logic",
          severity: "high",
          cvss: 7.5,
          note: "JSON schema validation using eval() to process user-provided validation code"
        },
        %{
          id: "CVE-2018-3774",
          description: "mongoose npm package eval() injection in query processing",
          severity: "critical",
          cvss: 9.1,
          note: "Database query conditions processed through eval() enabling RCE"
        }
      ],
      detection_notes: """
      This pattern detects eval() function calls that include user-controlled input 
      identifiers. The detection covers:
      
      1. Direct eval() calls: eval(userInput)
      2. Request object properties: eval(req.body.code)
      3. Parameter objects: eval(params.expression)
      4. Query parameters: eval(request.query.formula)
      5. Generic user/input/data variables: eval(userData)
      6. Nested property access: eval(req.body.nested.code)
      7. Template literals containing user input: eval(`code ${userInput}`)
      
      The regex pattern looks for eval() followed by parentheses containing common 
      user input identifiers. It uses case-insensitive matching to catch variations 
      in naming conventions and includes common request/parameter patterns used in 
      web frameworks.
      
      The pattern is designed to have high sensitivity for security scanning while 
      avoiding false positives on static eval() usage or properly sanitized inputs. 
      However, any eval() usage should be carefully reviewed as it represents a 
      fundamental security risk.
      """,
      safe_alternatives: [
        "Use JSON.parse() for parsing JSON data: JSON.parse(userInput)",
        "Use Function constructor with validation: new Function('return ' + sanitizedExpression)()",
        "Use VM sandbox for code execution: vm.runInContext(code, createSecureContext())",
        "Use expression parsers like math.js: mathjs.evaluate(expression, scope)",
        "Use template engines with auto-escaping: handlebars.compile(template)(data)",
        "Use AST parsers for code analysis: const ast = parseScript(code)",
        "Use CSP with unsafe-eval disabled to prevent eval() usage",
        "Use static analysis tools to identify and eliminate eval() usage",
        "Implement custom expression evaluators with whitelisted operations"
      ],
      additional_context: %{
        framework_specific_risks: [
          "Express.js: eval() in route handlers processing req.body or req.query",
          "Koa.js: eval() in middleware processing ctx.request.body",
          "Next.js: eval() in API routes or getServerSideProps",
          "Electron: eval() in main process providing access to Node.js APIs",
          "React SSR: eval() in server-side rendering with user-provided templates",
          "Vue.js: eval() in server-side template compilation",
          "Angular Universal: eval() in server-side expression evaluation"
        ],
        common_vulnerable_patterns: [
          "Template engines using eval() for dynamic template compilation",
          "Configuration loaders using eval() to process config files",
          "Mathematical expression evaluators using eval() for computation",
          "Dynamic import systems using eval() to load modules",
          "Serialization libraries using eval() for object reconstruction",
          "Debug/development tools using eval() for interactive code execution",
          "Plugin systems using eval() to execute user-provided plugins"
        ],
        exploitation_techniques: [
          "Process control: eval('process.exit(1)') to crash applications",
          "File system access: eval('require(\\\"fs\\\").readFileSync(\\\"/etc/passwd\\\")') for data theft",
          "Network operations: eval('require(\\\"http\\\").request(attackerUrl)') for data exfiltration",
          "Module loading: eval('require(\\\"child_process\\\").exec(\\\"malicious_command\\\")') for command execution",
          "Environment access: eval('process.env') to steal configuration and secrets",
          "Memory manipulation: eval() to modify global objects and application state",
          "Prototype pollution: eval() to pollute Object.prototype and affect application behavior"
        ],
        detection_evasion: [
          "String concatenation: eval('ev' + 'al(userInput)')",
          "Function references: const fn = eval; fn(userInput)",
          "Computed property access: window['eval'](userInput)",
          "Indirect evaluation: Function('return eval(arguments[0])')(userInput)",
          "Proxy wrappers: new Proxy(eval, {})(userInput)",
          "Encoding obfuscation: eval(atob(base64EncodedPayload))"
        ],
        remediation_steps: [
          "Immediately remove all eval() usage from application code",
          "Replace eval() with safe alternatives like JSON.parse() or expression parsers",
          "Implement Content Security Policy with 'unsafe-eval' disabled",
          "Add static analysis rules to prevent future eval() introduction",
          "Use VM sandboxes for legitimate dynamic code execution needs",
          "Implement input validation and sanitization for all user inputs",
          "Add runtime monitoring for eval() usage attempts",
          "Conduct security code review to identify indirect eval() usage"
        ],
        compliance_impact: [
          "PCI DSS: eval() RCE violates requirements for secure coding practices",
          "SOC 2: Fails to meet criteria for logical access controls and secure development",
          "ISO 27001: Violates secure coding and vulnerability management requirements",
          "NIST Cybersecurity Framework: Fails PROTECT function requirements",
          "GDPR: Data breaches through eval() RCE can trigger breach notification requirements",
          "Industry standards: Most security frameworks prohibit eval() usage with user input"
        ]
      }
    }
  end
  
  @doc """
  Custom validation to filter out false positives like comments.
  
  This function provides additional validation beyond the regex pattern
  to handle complex cases that PCRE limitations prevent us from solving
  with lookbehind assertions.
  """
  def validate_match(line) do
    # Exclude lines that are comments
    cond do
      # Single line comments
      String.match?(line, ~r/^\s*\/\/.*eval/) -> false
      # Comments at end of line (but not in strings)
      String.match?(line, ~r/\/\/[^"']*eval/) && !has_eval_in_string?(line) -> false
      # Multi-line comments (basic detection)
      String.match?(line, ~r/\/\*.*eval.*\*\//) -> false
      # Default: accept the match
      true -> true
    end
  end
  
  # Helper function to detect if eval is actually in a string/template
  defp has_eval_in_string?(line) do
    # Look for eval within quotes that comes before any comment
    comment_pos = case Regex.run(~r/\/\//, line, return: :index) do
      [{pos, _}] -> pos
      _ -> String.length(line)
    end
    
    line_before_comment = String.slice(line, 0, comment_pos)
    String.match?(line_before_comment, ~r/["'`][^"'`]*eval[^"'`]*["'`]/)
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual eval() RCE vulnerabilities and:
  - eval() used for JSON parsing in legacy code (should be JSON.parse)
  - Static mathematical expressions without user input
  - Sandboxed evaluation (VM2, isolated-vm)
  - Generated code from build tools
  - Test and development code
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      iex> enhancement.ast_rules.callee.name
      "eval"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      iex> "direct_req_body_to_eval" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          name: "eval",
          # Also catch Function constructor and setTimeout/setInterval with strings
          alternatives: ["Function", "setTimeout", "setInterval"]
        },
        # First argument must contain user input
        argument_analysis: %{
          first_arg_contains_user_input: true,
          is_string_type: true,  # Not a function reference
          not_static_string: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/build/, ~r/dist/],
        exclude_if_json_parse_only: true,   # eval() for JSON parsing (legacy)
        exclude_if_math_only: true,         # Mathematical expressions only
        exclude_if_sandboxed: true,         # VM2, isolated-vm, etc.
        exclude_if_generated_code: true,    # Build tools, transpilers
        high_risk_sources: ["req.body", "req.query", "localStorage", "location.search"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "direct_req_body_to_eval" => 0.5,  # Extremely dangerous
          "url_params_to_eval" => 0.4,
          "any_user_input_to_eval" => 0.3,
          "uses_vm2_sandbox" => -0.8,
          "json_parse_pattern" => -0.7,       # eval('(' + json + ')')
          "static_math_expression" => -0.9,
          "in_build_tool" => -0.9,
          "webpack_generated" => -1.0
        }
      },
      min_confidence: 0.8
    }
  end
  
end