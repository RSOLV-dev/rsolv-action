defmodule RsolvApi.Security.Patterns.JavascriptEnhanced do
  @moduledoc """
  Enhanced JavaScript patterns with AST configuration and reduced false positives.
  
  These patterns use the enhanced pattern format with:
  - AST matching rules
  - Context requirements
  - Confidence scoring
  - AI review configuration
  """
  
  alias RsolvApi.Security.EnhancedPattern
  
  @doc """
  Returns enhanced JavaScript patterns for the specified tier.
  
  ## Examples
  
      iex> patterns = JavascriptEnhanced.all(:public)
      iex> Enum.all?(patterns, &match?(%EnhancedPattern{}, &1))
      true
  """
  def all(tier) when tier in [:public, :protected, :ai, :enterprise] do
    all_patterns()
    |> filter_by_tier(tier)
    |> Enum.map(&struct(EnhancedPattern, &1))
  end
  
  defp all_patterns do
    [
      sql_injection_enhanced(),
      nosql_injection_enhanced(),
      missing_logging_enhanced(),
      command_injection_enhanced(),
      xss_enhanced()
    ]
  end
  
  defp filter_by_tier(patterns, :public) do
    # Public tier gets only high-confidence patterns
    patterns
    |> Enum.filter(fn pattern -> 
      # Check if pattern has ai_review with min_confidence
      confidence = get_in(pattern, [:ai_review, :min_confidence]) || 1.0
      confidence >= 0.8
    end)
    |> Enum.take(2)
  end
  
  defp filter_by_tier(patterns, :protected) do
    # Protected tier gets more patterns
    Enum.take(patterns, 4)
  end
  
  defp filter_by_tier(patterns, tier) when tier in [:ai, :enterprise] do
    # AI and Enterprise get all patterns with AI review
    patterns
  end
  
  defp sql_injection_enhanced do
    %{
      id: "js-sql-injection-enhanced",
      name: "SQL Injection (Enhanced)",
      type: :sql_injection,
      severity: :critical,
      description: "SQL injection with context-aware detection and low false positives",
      languages: ["javascript", "typescript"],
      frameworks: [],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      test_cases: %{
        vulnerable: [
          "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
          "connection.execute('SELECT * FROM users WHERE name = ' + userName)",
          "db.query('DELETE FROM posts WHERE id = ' + postId)"
        ],
        safe: [
          "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
          "db.query('SELECT * FROM users WHERE id = $1', [userId])",
          "const stmt = db.prepare('SELECT * FROM users WHERE name = ?')"
        ]
      },
      
      # Traditional regex for pre-filtering
      regex: ~r/\.(query|execute|exec|run)\s*\(/i,
      
      # AST configuration
      ast_rules: [%{
        node_type: :call_expression,
        properties: %{
          callee: %{
            type: "MemberExpression",
            property_names: ["query", "execute", "exec", "run", "prepare"]
          },
          arguments: [
          %{
            position: 0,
            checks: [
              %{
                type: "TemplateLiteral",
                contains_pattern: ~r/\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b/i,
                has_expressions: true
              },
              %{
                type: "BinaryExpression",
                operator: "+",
                contains_user_input: true
              }
            ]
          }
        ]
        }
      }],
      
      # Context requirements
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/\.test\./],
        exclude_if_imports: ["@testing-library", "jest", "mocha"],
        require_user_input_source: true,
        user_input_patterns: [
          ~r/req\./,
          ~r/request\./,
          ~r/params\./,
          ~r/query\./,
          ~r/body\./
        ]
      },
      
      # Confidence rules
      confidence_rules: %{
        base_score: 0.7,
        modifiers: [
          %{condition: "has_parameterized_query", adjustment: -0.8},
          %{condition: "has_orm_wrapper", adjustment: -0.6},
          %{condition: "direct_user_input", adjustment: 0.2},
          %{condition: "in_database_module", adjustment: 0.1},
          %{condition: "has_validation", adjustment: -0.3}
        ]
      },
      
      # Enhanced recommendation
      recommendation: %{
        summary: "Use parameterized queries to prevent SQL injection",
        steps: [
          "Replace string concatenation with parameterized queries",
          "Use query builders or ORMs that handle escaping",
          "Validate and sanitize all user input",
          "Use prepared statements for dynamic queries"
        ],
        examples: %{
          vulnerable: """
          // Vulnerable code
          db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
          """,
          fixed: """
          // Fixed code
          db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
          """
        },
        references: [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
      },
      
      # Enhanced recommendation with additional details
      enhanced_recommendation: %{
        quick_fix: "Replace string concatenation with parameterized queries",
        detailed_steps: [
          "Identify all SQL query construction using string concatenation",
          "Replace with parameterized queries using ? or $1 placeholders",
          "Use query builders or ORMs that handle escaping automatically",
          "Implement input validation and sanitization",
          "Test with SQL injection attack vectors to verify fixes"
        ],
        references: [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
          "https://bobby-tables.com/"
        ]
      },
      
      # AI review configuration (for ai/enterprise tiers)
      ai_review: %{
        enabled: true,
        min_confidence: 0.6,
        prompt_template: """
        Analyze this potential SQL injection vulnerability:
        
        Code: {{code}}
        Context: {{context}}
        Detected pattern: {{pattern}}
        
        Questions to consider:
        1. Is the user input actually reaching the SQL query?
        2. Are there any framework protections in place?
        3. Is the input validated or sanitized before use?
        4. Could this be exploited in a real attack?
        
        Provide a confidence score (0-1) and explanation.
        """
      },
      
      # Telemetry configuration
      telemetry: %{
        track_matches: true,
        track_false_positives: true,
        sample_rate: 1.0
      }
    }
  end
  
  defp nosql_injection_enhanced do
    %{
      id: "js-nosql-injection-enhanced",
      name: "NoSQL Injection (Enhanced)",
      type: :nosql_injection,
      severity: :high,
      description: "MongoDB injection with framework awareness",
      languages: ["javascript", "typescript"],
      frameworks: ["mongodb", "mongoose"],
      default_tier: :protected,
      cwe_id: "CWE-943",
      owasp_category: "A03:2021",
      test_cases: %{
        vulnerable: [
          "User.find(req.body.query)",
          "collection.find({$where: userInput})",
          "db.collection.find(JSON.parse(req.params.filter))"
        ],
        safe: [
          "User.find({email: req.body.email})",
          "collection.find(sanitize(query))",
          "db.collection.find({_id: ObjectId(req.params.id)})"
        ]
      },
      
      regex: ~r/\.(find|findOne|update|delete|aggregate)\s*\(/,
      
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          type: "MemberExpression",
          property_names: ["find", "findOne", "findById", "update", "updateOne", "updateMany", "delete", "deleteOne", "deleteMany", "aggregate"]
        },
        arguments: [
          %{
            position: 0,
            checks: [
              %{
                type: "ObjectExpression",
                has_user_input: true,
                dangerous_keys: ["$where", "$expr", "$function", "$accumulator"]
              }
            ]
          }
        ]
      },
      
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/],
        framework_protections: %{
          mongoose: ["sanitizeFilter", "trusted"],
          mongodb: ["sanitize"]
        }
      },
      
      confidence_scoring: %{
        base_score: 0.75,
        modifiers: [
          %{condition: "uses_dangerous_operator", adjustment: 0.2},
          %{condition: "has_type_validation", adjustment: -0.4},
          %{condition: "uses_mongoose_schema", adjustment: -0.3},
          %{condition: "direct_parse_json", adjustment: 0.3}
        ]
      },
      
      recommendation: %{
        summary: "Validate input types and avoid dangerous MongoDB operators",
        steps: [
          "Use Mongoose schemas for automatic type validation",
          "Explicitly cast user input to expected types",
          "Avoid $where and other code execution operators",
          "Use MongoDB's built-in sanitization"
        ],
        examples: %{
          vulnerable: """
          // Vulnerable - accepts any object structure
          db.users.find(req.body.query);
          """,
          fixed: """
          // Fixed - validate and sanitize
          const { name, age } = req.body;
          db.users.find({
            name: String(name),
            age: parseInt(age) || 0
          });
          """
        }
      }
    }
  end
  
  defp missing_logging_enhanced do
    %{
      id: "js-missing-logging-enhanced",
      name: "Missing Security Logging (Enhanced)",
      type: :logging,
      severity: :medium,
      languages: ["javascript", "typescript"],
      frameworks: ["express", "koa", "fastify"],
      default_tier: :protected,
      cwe_id: "CWE-778",
      owasp_category: "A09:2021",
      test_cases: %{
        vulnerable: [
          "if (req.user.role !== 'admin') { return res.status(403).send('Forbidden'); }",
          "app.post('/admin', (req, res) => { /* no logging */ })",
          "if (password !== hashedPassword) { return false; }"
        ],
        safe: [
          "if (req.user.role !== 'admin') { logger.warn('Unauthorized access attempt', {user: req.user.id}); return res.status(403).send('Forbidden'); }",
          "app.post('/admin', (req, res) => { logger.info('Admin action', {user: req.user}); })",
          "if (password !== hashedPassword) { logger.warn('Failed login attempt', {email}); return false; }"
        ]
      },
      description: "Security-critical operations without audit logging",
      
      # Only match actual function definitions
      regex: ~r/function\s+(login|authenticate|authorize|payment|transfer|delete\w+|reset\w+)\s*\(/,
      
      ast_rules: %{
        node_type: "FunctionDeclaration",
        name_pattern: ~r/^(login|authenticate|authorize|process.*Payment|delete.*|reset.*Password|transfer.*)/,
        body_checks: %{
          must_not_contain: [
            %{type: "CallExpression", callee_pattern: ~r/log|logger|audit|console\.log/}
          ],
          exceptions: [
            %{delegates_to: ~r/^(authenticate|authorizeUser|processAuth)/}
          ]
        }
      },
      
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/mock/, ~r/stub/],
        exclude_if_contains: ["@skip", "TODO", "FIXME"],
        require_production_code: true
      },
      
      confidence_scoring: %{
        base_score: 0.6,
        modifiers: [
          %{condition: "is_test_helper", adjustment: -1.0},
          %{condition: "delegates_to_logged_function", adjustment: -0.8},
          %{condition: "has_try_catch_without_log", adjustment: 0.3},
          %{condition: "modifies_user_data", adjustment: 0.2}
        ]
      },
      
      recommendation: %{
        summary: "Add audit logging for security-critical operations",
        steps: [
          "Log authentication attempts (success and failure)",
          "Log authorization decisions",
          "Log data modifications with who/what/when",
          "Use structured logging for easy analysis"
        ],
        examples: %{
          vulnerable: """
          function deleteUser(userId) {
            return db.users.deleteOne({ _id: userId });
          }
          """,
          fixed: """
          function deleteUser(userId, deletedBy) {
            logger.audit('USER_DELETION', {
              userId,
              deletedBy,
              timestamp: new Date().toISOString(),
              ip: req.ip
            });
            return db.users.deleteOne({ _id: userId });
          }
          """
        }
      }
    }
  end
  
  defp command_injection_enhanced do
    %{
      id: "js-command-injection-enhanced",
      name: "Command Injection (Enhanced)",
      type: :command_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      frameworks: [],
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      test_cases: %{
        vulnerable: [
          "exec(`git clone ${req.body.repo}`)",
          "spawn('rm', ['-rf', userInput])",
          "execSync('ping ' + req.params.host)"
        ],
        safe: [
          "exec('git clone', [sanitizeRepo(req.body.repo)])",
          "spawn('rm', ['-rf', path.join(SAFE_DIR, filename)])",
          "ping.probe(req.params.host, callback)"
        ]
      },
      description: "System command execution with user input",
      
      regex: ~r/(exec|spawn|execFile|execSync|spawnSync)\s*\(/,
      
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          names: ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"],
          from_modules: ["child_process", "shelljs"]
        },
        arguments: [
          %{
            position: 0,
            has_user_input: true,
            not_escaped_by: ["escapeShellArg", "shellEscape", "escapeshellarg"]
          }
        ]
      },
      
      context_rules: %{
        severity_upgrade_if: %{
          runs_as_root: true,
          in_web_handler: true
        }
      },
      
      confidence_scoring: %{
        base_score: 0.85,
        modifiers: [
          %{condition: "input_is_escaped", adjustment: -0.9},
          %{condition: "uses_array_syntax", adjustment: -0.4},
          %{condition: "whitelist_validation", adjustment: -0.7}
        ]
      },
      
      recommendation: %{
        summary: "Avoid system commands or use safe alternatives",
        steps: [
          "Use built-in Node.js APIs instead of shell commands",
          "If shell required, use array syntax with spawn",
          "Escape all user input with escapeShellArg",
          "Validate against a strict whitelist"
        ]
      }
    }
  end
  
  defp xss_enhanced do
    %{
      id: "js-xss-enhanced",
      name: "Cross-Site Scripting (Enhanced)",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      frameworks: ["react", "vue", "angular"],
      default_tier: :protected,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      test_cases: %{
        vulnerable: [
          "element.innerHTML = req.body.content",
          "document.write(userInput)",
          "$(element).html(req.params.message)"
        ],
        safe: [
          "element.textContent = req.body.content",
          "element.appendChild(document.createTextNode(userInput))",
          "$(element).text(req.params.message)"
        ]
      },
      description: "DOM XSS with framework awareness",
      
      regex: ~r/\.innerHTML\s*=|document\.write\s*\(/,
      
      ast_rules: %{
        checks: [
          %{
            node_type: "AssignmentExpression",
            left: %{property_name: "innerHTML"},
            right: %{contains_user_input: true}
          },
          %{
            node_type: "CallExpression",
            callee: "document.write",
            arguments: %{contains_user_input: true}
          }
        ]
      },
      
      context_rules: %{
        framework_safe_methods: %{
          react: ["setState", "useState"],
          vue: ["v-text", "{{}}"],
          angular: ["[innerText]", "{{}}"]
        }
      },
      
      confidence_scoring: %{
        base_score: 0.8,
        modifiers: [
          %{condition: "uses_framework_escaping", adjustment: -0.9},
          %{condition: "has_sanitization", adjustment: -0.7},
          %{condition: "from_url_params", adjustment: 0.2}
        ]
      },
      
      recommendation: %{
        summary: "Use safe DOM manipulation methods",
        steps: [
          "Use textContent instead of innerHTML",
          "Use framework's built-in escaping",
          "Sanitize HTML with DOMPurify if needed",
          "Validate and escape all user input"
        ]
      }
    }
  end
end