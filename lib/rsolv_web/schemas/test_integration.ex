defmodule RsolvWeb.Schemas.TestIntegration do
  @moduledoc """
  OpenAPI schemas for test integration endpoints (AST-based test generation).
  """

  alias OpenApiSpex.Schema

  defmodule TestAnalyzeRequest do
    @moduledoc "Test code analysis request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestAnalyzeRequest",
      description: "Request to analyze test code structure using AST",
      type: :object,
      properties: %{
        code: %Schema{
          type: :string,
          description: "Test code to analyze"
        },
        language: %Schema{
          type: :string,
          description: "Programming language",
          enum: ["javascript", "typescript", "python", "ruby"],
          example: "javascript"
        },
        framework: %Schema{
          type: :string,
          description: "Test framework (optional)",
          example: "jest"
        }
      },
      required: [:code, :language],
      example: %{
        "code" => "describe('User authentication', () => { it('should login', () => {}); });",
        "language" => "javascript",
        "framework" => "jest"
      }
    })
  end

  defmodule TestAnalyzeResponse do
    @moduledoc "Test code analysis response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestAnalyzeResponse",
      description: "Analysis results for test code structure",
      type: :object,
      properties: %{
        structure: %Schema{
          type: :object,
          properties: %{
            suites: %Schema{type: :array, items: %Schema{type: :object}},
            tests: %Schema{type: :array, items: %Schema{type: :object}},
            hooks: %Schema{type: :array, items: %Schema{type: :object}}
          }
        },
        framework_detected: %Schema{type: :string},
        suggestions: %Schema{
          type: :array,
          items: %Schema{type: :string}
        }
      }
    })
  end

  defmodule TestNamingRequest do
    @moduledoc "Test naming suggestion request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestNamingRequest",
      description: "Request test name suggestions based on code being tested",
      type: :object,
      properties: %{
        code: %Schema{
          type: :string,
          description: "Code being tested"
        },
        language: %Schema{
          type: :string,
          description: "Programming language",
          example: "javascript"
        },
        test_type: %Schema{
          type: :string,
          description: "Type of test",
          enum: ["unit", "integration", "e2e", "security"],
          example: "security"
        },
        context: %Schema{
          type: :object,
          description: "Additional context",
          properties: %{
            vulnerability_type: %Schema{type: :string},
            function_name: %Schema{type: :string}
          }
        }
      },
      required: [:code, :language, :test_type],
      example: %{
        "code" => "function sanitizeInput(input) { return input.replace(/<script>/g, ''); }",
        "language" => "javascript",
        "test_type" => "security",
        "context" => %{
          "vulnerability_type" => "xss",
          "function_name" => "sanitizeInput"
        }
      }
    })
  end

  defmodule TestNamingResponse do
    @moduledoc "Test naming suggestion response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestNamingResponse",
      description: "Suggested test names and descriptions",
      type: :object,
      properties: %{
        suggestions: %Schema{
          type: :array,
          items: %Schema{
            type: :object,
            properties: %{
              test_name: %Schema{type: :string},
              description: %Schema{type: :string},
              category: %Schema{type: :string}
            }
          },
          description: "Array of test name suggestions"
        }
      },
      required: [:suggestions],
      example: %{
        "suggestions" => [
          %{
            "test_name" => "should block XSS via script tag injection",
            "description" => "Verifies that sanitizeInput prevents XSS through script tags",
            "category" => "security"
          },
          %{
            "test_name" => "should remove malicious script content",
            "description" => "Tests removal of script tags from user input",
            "category" => "sanitization"
          }
        ]
      }
    })
  end

  defmodule TestGenerateRequest do
    @moduledoc """
    Test generation request

    ## Examples

    ### RED Test (Security - Failing Test)
    ```json
    {
      "code": "function sanitizeInput(input) {\\n  return input.replace(/<script>/g, '');\\n}",
      "language": "javascript",
      "test_type": "red",
      "vulnerability_type": "xss",
      "framework": "jest"
    }
    ```

    ### GREEN Test (After Fix)
    ```json
    {
      "code": "function sanitizeInput(input) {\\n  const div = document.createElement('div');\\n  div.textContent = input;\\n  return div.innerHTML;\\n}",
      "language": "javascript",
      "test_type": "green",
      "vulnerability_type": "xss",
      "framework": "jest"
    }
    ```

    ### REFACTOR Test (Performance & Best Practices)
    ```json
    {
      "code": "function sanitizeInput(input) {\\n  return DOMPurify.sanitize(input);\\n}",
      "language": "javascript",
      "test_type": "refactor",
      "framework": "jest"
    }
    ```

    ### Python RED Test (SQL Injection)
    ```json
    {
      "code": "def get_user(user_id):\\n    query = f\\"SELECT * FROM users WHERE id = {user_id}\\"\\n    return db.execute(query)",
      "language": "python",
      "test_type": "red",
      "vulnerability_type": "sql_injection",
      "framework": "pytest"
    }
    ```

    ### Ruby RED Test (Command Injection)
    ```json
    {
      "code": "def ping_host(host)\\n  system('ping ' + host)\\nend",
      "language": "ruby",
      "test_type": "red",
      "vulnerability_type": "command_injection",
      "framework": "rspec"
    }
    ```

    ## Complete RED/GREEN/REFACTOR Workflow

    ### Phase 1: Generate RED Test (Proves Vulnerability)
    ```javascript
    // Request
    {
      "code": "const query = 'SELECT * FROM users WHERE name = ' + userName;",
      "language": "javascript",
      "test_type": "red",
      "vulnerability_type": "sql_injection",
      "framework": "jest"
    }

    // Response
    {
      "test_code": "describe('SQL Injection Security', () => {\\n  it('should reject SQL injection attempts', () => {\\n    const maliciousInput = \\\"admin' OR '1'='1\\";\\n    expect(() => getUserByName(maliciousInput)).toThrow();\\n  });\\n});",
      "test_name": "should reject SQL injection attempts",
      "framework": "jest",
      "imports": ["const { getUserByName } = require('./user');"]
    }
    ```

    ### Phase 2: Generate GREEN Test (After Fix)
    ```javascript
    // After fixing with parameterized queries
    {
      "code": "const query = 'SELECT * FROM users WHERE name = ?';\\ndb.execute(query, [userName]);",
      "language": "javascript",
      "test_type": "green",
      "vulnerability_type": "sql_injection",
      "framework": "jest"
    }

    // Response
    {
      "test_code": "describe('SQL Injection Security', () => {\\n  it('should safely handle user input', () => {\\n    const safeInput = \\\"admin' OR '1'='1\\";\\n    const result = getUserByName(safeInput);\\n    expect(result).toBeDefined();\\n    expect(result.name).not.toContain(\\"OR\\");\\n  });\\n});",
      "test_name": "should safely handle user input",
      "framework": "jest",
      "imports": ["const { getUserByName } = require('./user');"]
    }
    ```

    ### Phase 3: Generate REFACTOR Test (Best Practices)
    ```javascript
    {
      "code": "async function getUserByName(name) {\\n  const [rows] = await db.query('SELECT * FROM users WHERE name = ?', [name]);\\n  return rows[0];\\n}",
      "language": "javascript",
      "test_type": "refactor",
      "framework": "jest"
    }

    // Response includes performance, edge cases, validation tests
    ```

    ## Client Code Examples

    ### JavaScript (Complete TDD Workflow)
    ```javascript
    const axios = require('axios');

    async function generateTDDTests(code, language, framework, apiKey) {
      const phases = ['red', 'green', 'refactor'];
      const tests = {};

      for (const phase of phases) {
        const response = await axios.post(
          'https://api.rsolv.dev/api/v1/test-integration/generate',
          {
            code: code[phase],
            language: language,
            test_type: phase,
            vulnerability_type: phase === 'red' ? 'sql_injection' : undefined,
            framework: framework
          },
          {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json'
            }
          }
        );

        tests[phase] = response.data;
      }

      return tests;
    }

    // Usage
    const codeVersions = {
      red: "const query = 'SELECT * FROM users WHERE id = ' + userId;",
      green: "const query = 'SELECT * FROM users WHERE id = ?'; db.execute(query, [userId]);",
      refactor: "async function getUser(id) { const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]); return rows[0]; }"
    };

    const allTests = await generateTDDTests(codeVersions, 'javascript', 'jest', process.env.API_KEY);

    // Write test files
    fs.writeFileSync('user.red.test.js', allTests.red.test_code);
    fs.writeFileSync('user.green.test.js', allTests.green.test_code);
    fs.writeFileSync('user.refactor.test.js', allTests.refactor.test_code);
    ```

    ### Python (Security Test Generation)
    ```python
    import requests
    import os

    def generate_security_test(code, language, vulnerability_type, framework, api_key):
        response = requests.post(
            'https://api.rsolv.dev/api/v1/test-integration/generate',
            json={
                'code': code,
                'language': language,
                'test_type': 'red',
                'vulnerability_type': vulnerability_type,
                'framework': framework
            },
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
        )

        response.raise_for_status()
        return response.json()

    # Generate RED test for SQL injection
    vulnerable_code = '''
    def get_user(user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return db.execute(query)
    '''

    test_data = generate_security_test(
        vulnerable_code,
        'python',
        'sql_injection',
        'pytest',
        os.environ['API_KEY']
    )

    # Write test file
    with open('test_user_security.py', 'w') as f:
        for import_line in test_data['imports']:
            f.write(f"{import_line}\\n")
        f.write("\\n")
        f.write(test_data['test_code'])

    print(f"Generated test: {test_data['test_name']}")
    ```

    ### cURL (Single Test Generation)
    ```bash
    curl -X POST https://api.rsolv.dev/api/v1/test-integration/generate \\
      -H "Authorization: Bearer $API_KEY" \\
      -H "Content-Type: application/json" \\
      -d '{
        "code": "function sanitizeInput(input) { return input.replace(/<script>/g, '\"'\"''\"); }",
        "language": "javascript",
        "test_type": "red",
        "vulnerability_type": "xss",
        "framework": "jest"
      }' | jq -r '.test_code'
    ```

    ## Integration with CI/CD

    ### GitHub Actions Example
    ```yaml
    name: Generate Security Tests

    on:
      push:
        paths:
          - 'src/**/*.js'

    jobs:
      generate-tests:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: Generate RED Tests
            run: |
              for file in src/**/*.js; do
                code=$(cat "$file")
                curl -X POST https://api.rsolv.dev/api/v1/test-integration/generate \\
                  -H "Authorization: Bearer $RSOLV_API_KEY" \\
                  -H "Content-Type: application/json" \\
                  -d "{\\"code\\": \\"$code\\", \\"language\\": \\"javascript\\", \\"test_type\\": \\"red\\", \\"framework\\": \\"jest\\"}" \\
                  | jq -r '.test_code' > "tests/$(basename $file .js).test.js"
              done
            env:
              RSOLV_API_KEY: ${{ secrets.RSOLV_API_KEY }}

          - name: Run Generated Tests
            run: npm test

          - name: Commit Generated Tests
            if: success()
            run: |
              git config user.name "RSOLV Bot"
              git config user.email "bot@rsolv.dev"
              git add tests/
              git commit -m "Add generated security tests"
              git push
    ```
    """
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestGenerateRequest",
      description: "Request to generate test code using AST templates",
      type: :object,
      properties: %{
        code: %Schema{type: :string, description: "Code to test"},
        language: %Schema{type: :string, description: "Programming language"},
        test_type: %Schema{type: :string, enum: ["red", "green", "refactor"]},
        vulnerability_type: %Schema{type: :string, nullable: true},
        framework: %Schema{type: :string, description: "Test framework", nullable: true}
      },
      required: [:code, :language, :test_type]
    })
  end

  defmodule TestGenerateResponse do
    @moduledoc "Test generation response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestGenerateResponse",
      description: "Generated test code",
      type: :object,
      properties: %{
        test_code: %Schema{type: :string, description: "Generated test code"},
        test_name: %Schema{type: :string, description: "Suggested test name"},
        framework: %Schema{type: :string, description: "Test framework used"},
        imports: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Required imports"
        }
      },
      required: [:test_code]
    })
  end
end
