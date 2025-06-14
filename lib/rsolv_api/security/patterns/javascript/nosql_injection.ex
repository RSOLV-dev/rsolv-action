defmodule RsolvApi.Security.Patterns.Javascript.NosqlInjection do
  @moduledoc """
  Detects NoSQL injection vulnerabilities in JavaScript/TypeScript code.
  
  NoSQL databases like MongoDB are vulnerable to injection attacks when user input
  is directly used in queries without proper sanitization. Attackers can inject
  operators like $where, $ne, $gt to bypass authentication or extract data.
  
  ## Vulnerability Details
  
  NoSQL injection occurs when untrusted data is inserted into NoSQL database queries,
  allowing attackers to:
  - Bypass authentication (e.g., using {$ne: null})
  - Execute arbitrary JavaScript ($where operator)
  - Extract or manipulate data
  - Cause denial of service
  
  ### Attack Example
  ```javascript
  // Vulnerable: Direct use of req.body in MongoDB query
  app.post('/login', (req, res) => {
    db.users.findOne({
      username: req.body.username,  // {"$ne": null} bypasses auth
      password: req.body.password   // {"$ne": null}
    });
  });
  
  // Attacker sends: {"username": {"$ne": null}, "password": {"$ne": null}}
  // This matches any user, logging in as the first user found
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the pattern definition for NoSQL injection detection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.NosqlInjection.pattern()
      iex> pattern.id
      "js-nosql-injection"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.NosqlInjection.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.NosqlInjection.pattern()
      iex> vulnerable = "db.users.find({username: req.body.username})"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.NosqlInjection.pattern()
      iex> safe = "db.users.find({username: sanitize(req.body.username)})"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "js-nosql-injection",
      name: "NoSQL Injection",
      description: "NoSQL databases can be vulnerable to injection attacks when user input is used directly in queries",
      type: :nosql_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Detects MongoDB/Mongoose queries with direct user input
      # Matches: db.collection.find(req.body), User.find(req.query), etc.
      # Also detects $where usage and update operations with user input
      regex: ~r/
        # Mongoose model patterns - Model.method(userInput) including where
        \b[A-Z]\w*\.(?:find|findOne|findById|update|updateOne|updateMany|deleteOne|deleteMany|where)\s*\(\s*
        (?:req\.(?:body|query|params)|user(?:Input|Data)|input|data)\b
        |
        # Direct collection method with user input - handles collection.update({}, req.body)
        \w+\.(?:find|findOne|update|updateOne|updateMany|remove|deleteOne|deleteMany)\s*\(\s*
        [^,)]*,\s*(?:req\.(?:body|query|params)|user(?:Input|Data)|input|data)\b
        |
        # MongoDB native driver patterns - db.collection.method({field: userInput})
        # Must not match if the user input is wrapped in a function call like sanitize()
        (?:db|collection|database)\.\w+\.(?:find|findOne|update|updateOne|updateMany|delete|deleteOne|deleteMany|aggregate)\s*\(\s*
        \{[^}]*:\s*(?:req\.(?:body|query|params)|user(?:Input|Data)|input|data)(?:\.[\w\[\]]+)*(?:\s*[,}])
        |
        # $where operator usage
        \$where\s*:\s*(?:req\.(?:body|query|params)|user(?:Input|Data)|input|data)
      /x,
      default_tier: :public,
      cwe_id: "CWE-943",
      owasp_category: "A03:2021",
      recommendation: "Sanitize and validate all user input before using in NoSQL queries. Use parameterized queries or ODM/ORM features that handle escaping.",
      test_cases: %{
        vulnerable: [
          "db.users.find({username: req.body.username})",
          "User.findOne(req.body.filter)",
          "collection.update({_id: id}, req.body)",
          "db.products.find({$where: req.query.condition})",
          "Model.where(userInput)",
          "db.users.findOne({email: req.params.email})"
        ],
        safe: [
          "db.users.find({username: sanitize(req.body.username)})",
          "User.findOne({_id: mongoose.Types.ObjectId(id)})",
          "db.collection.find({status: 'active'})",
          "User.find({email: validator.isEmail(email) ? email : null})",
          "Model.findById(sanitizedId)",
          "db.users.find({username: String(req.body.username).replace(/[^\\w]/g, '')})"
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for NoSQL injection.
  """
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      NoSQL injection is a vulnerability where attackers can inject malicious operators or
      JavaScript code into NoSQL database queries. Unlike SQL injection, NoSQL injection often
      involves manipulating query operators ($ne, $gt, $where) or injecting JavaScript code.
      
      This is particularly dangerous in authentication systems where operators like {$ne: null}
      can bypass login checks entirely. MongoDB's $where operator is especially dangerous as
      it allows arbitrary JavaScript execution within the database engine.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-943",
          title: "Improper Neutralization of Special Elements in Data Query Logic",
          url: "https://cwe.mitre.org/data/definitions/943.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "nosql_injection_owasp",
          title: "OWASP NoSQL Injection",
          url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
        },
        %{
          type: :research,
          id: "mongodb_security",
          title: "MongoDB Security Checklist",
          url: "https://www.mongodb.com/docs/manual/administration/security-checklist/"
        }
      ],
      attack_vectors: [
        "Authentication bypass: {username: {$ne: null}, password: {$ne: null}}",
        "Data extraction: {price: {$gt: 0, $lt: userInput}}",
        "JavaScript injection: {$where: 'this.password == \"' + userInput + '\"'}",
        "Type confusion: {age: {$type: userInput}}",
        "Regex injection: {email: {$regex: userInput}}",
        "Array operator abuse: {roles: {$in: [userInput]}}"
      ],
      real_world_impact: [
        "Complete authentication bypass allowing login as any user",
        "Unauthorized data access and extraction",
        "Data manipulation or deletion",
        "Remote code execution via $where operator",
        "Denial of service through expensive queries",
        "Privilege escalation by modifying user roles"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-2386",
          description: "MongoDB injection vulnerability in multiple products allowing authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates real-world NoSQL injection leading to complete system compromise"
        },
        %{
          id: "CVE-2020-7923",
          description: "NoSQL injection in MongoDB Compass via connection string manipulation",
          severity: "high",
          cvss: 7.5,
          note: "Shows how NoSQL injection can occur even in database management tools"
        },
        %{
          id: "CVE-2021-22911",
          description: "Rocket.Chat NoSQL injection allowing authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Real application vulnerability where {$regex: ''} could bypass authentication"
        }
      ],
      detection_notes: """
      This pattern detects common NoSQL injection vulnerabilities by looking for:
      1. Direct use of request data (req.body, req.query, req.params) in database queries
      2. Common MongoDB/Mongoose query methods with unsanitized input
      3. Usage of the dangerous $where operator with user input
      4. Model.where() calls with direct user input
      
      The pattern uses alternation to catch various query patterns while avoiding false positives
      from safe parameterized queries or queries with proper validation.
      """,
      safe_alternatives: [
        "Validate and sanitize all inputs: const username = String(req.body.username)",
        "Use MongoDB's ObjectId validation: mongoose.Types.ObjectId(id)",
        "Implement allow-lists for query operators",
        "Disable JavaScript execution: db.adminCommand({setParameter: 1, javascriptEnabled: false})",
        "Use projection to limit returned fields: find({}, {password: 0})",
        "Implement query complexity limits",
        "Use ODM/ORM features that handle escaping automatically"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming NoSQL databases are immune to injection attacks",
          "Not validating the structure of JSON input",
          "Allowing query operators in user input",
          "Using $where operator with any user-controlled data",
          "Not type-checking inputs (strings vs objects)"
        ],
        secure_patterns: [
          "Always validate input is the expected type (string, not object)",
          "Use schema validation libraries like Joi or Yup",
          "Implement strict input sanitization functions",
          "Use parameterized queries where available",
          "Disable dangerous features like JavaScript execution in production"
        ],
        framework_specific: %{
          mongoose: [
            "Use Model.findById() instead of Model.find({_id: userInput})",
            "Enable strict query mode to prevent query injection",
            "Use schema validation to enforce data types"
          ],
          mongodb_native: [
            "Use MongoDB's BSON type validation",
            "Implement custom sanitization for all user inputs",
            "Consider using MongoDB's aggregation pipeline with $match"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual NoSQL injection vulnerabilities and:
  - Queries with proper input sanitization or validation
  - Use of MongoDB ObjectId validation
  - Parameterized queries or safe query builders
  - Static queries without user input
  - Test/mock database operations
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.NosqlInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.NosqlInjection.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.NosqlInjection.ast_enhancement()
      iex> enhancement.ast_rules.query_analysis.has_user_input
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.NosqlInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.NosqlInjection.ast_enhancement()
      iex> "uses_sanitization" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        # MongoDB/Mongoose query methods
        callee_patterns: [
          ~r/\.(?:find|findOne|findById|update|updateOne|updateMany|delete|deleteOne|deleteMany|where|aggregate)/,
          ~r/db\.\w+\.(?:find|update|delete|aggregate)/,
          ~r/collection\.(?:find|update|delete)/
        ],
        # Query must contain user input
        query_analysis: %{
          has_user_input: true,
          contains_query_operators: true,  # $ne, $gt, $where, etc.
          not_parameterized: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/, ~r/mocks/],
        exclude_if_sanitized: true,         # Uses sanitization functions
        exclude_if_parameterized: true,     # Parameterized query builders
        exclude_if_validated: true,         # Input validation present
        safe_functions: ["sanitize", "escape", "validate", "ObjectId", "parseInt", "String"]
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "direct_user_input" => 0.4,
          "has_query_operators" => 0.3,
          "where_operator_usage" => 0.4,
          "uses_sanitization" => -0.8,
          "uses_object_id" => -0.7,
          "type_conversion" => -0.6,       # String(), parseInt()
          "schema_validation" => -0.7,
          "static_query_only" => -1.0
        }
      },
      min_confidence: 0.7
    }
  end
end