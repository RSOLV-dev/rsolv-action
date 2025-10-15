defmodule Rsolv.AST.AnalysisServiceIntegrationTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Rsolv.AST.{AnalysisService, SessionManager}

  setup do
    # Services are already started by the application
    {:ok, session} = SessionManager.create_session("test-customer")
    {:ok, session: session}
  end

  describe "SQL injection detection" do
    test "detects string concatenation SQL injection in JavaScript", %{session: _session} do
      file = %{
        path: "app.js",
        language: "javascript",
        content: """
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.execute(query);
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      assert length(findings) >= 1
      sql_finding = Enum.find(findings, &(&1.patternId == "js-sql-injection-concat"))
      assert sql_finding != nil
      assert sql_finding.severity == "high"
      assert sql_finding.confidence >= 0.7
      assert sql_finding.location.startLine == 2
    end

    test "does not flag safe parameterized queries", %{session: _session} do
      file = %{
        path: "safe.js",
        language: "javascript",
        content: """
        function getUserDataSafe(userId) {
          const query = "SELECT * FROM users WHERE id = ?";
          return db.execute(query, [userId]);
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # Should not find SQL injection in parameterized query
      sql_findings = Enum.filter(findings, &String.contains?(&1.patternId, "sql"))
      assert length(sql_findings) == 0
    end

    test "detects SQL injection in Python", %{session: _session} do
      file = %{
        path: "app.py",
        language: "python",
        content: """
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            return db.execute(query)
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      sql_finding = Enum.find(findings, &String.contains?(&1.type, "sql"))
      assert sql_finding != nil
      assert sql_finding.severity in ["high", "critical"]
    end
  end

  describe "XSS detection" do
    test "detects XSS in JavaScript innerHTML", %{session: _session} do
      file = %{
        path: "xss.js",
        language: "javascript",
        content: """
        function displayUserContent(content) {
          document.getElementById('output').innerHTML = content;
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      xss_finding = Enum.find(findings, &String.contains?(&1.type, "xss"))
      assert xss_finding != nil
    end

    test "does not flag safe text content updates", %{session: _session} do
      file = %{
        path: "safe-dom.js",
        language: "javascript",
        content: """
        function displayUserContentSafe(content) {
          document.getElementById('output').textContent = content;
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # textContent is safe, should not trigger XSS
      xss_findings = Enum.filter(findings, &String.contains?(&1.type, "xss"))
      assert length(xss_findings) == 0
    end
  end

  describe "command injection detection" do
    test "detects command injection in exec calls", %{session: _session} do
      file = %{
        path: "cmd.js",
        language: "javascript",
        content: """
        const { exec } = require('child_process');

        function runCommand(userInput) {
          exec('ls ' + userInput, (err, stdout) => {
            console.log(stdout);
          });
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      cmd_finding = Enum.find(findings, &String.contains?(&1.type, "command"))
      assert cmd_finding != nil
      assert cmd_finding.severity in ["high", "critical"]
    end
  end

  describe "context-aware analysis" do
    test "reduces confidence for test files", %{session: _session} do
      file = %{
        path: "test/sql_test.js",
        language: "javascript",
        content: """
        describe('SQL tests', () => {
          it('should handle SQL', () => {
            const query = "SELECT * FROM users WHERE id = " + testId;
            mockDb.execute(query);
          });
        });
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # Should have very low confidence due to test file
      if length(findings) > 0 do
        assert Enum.all?(findings, &(&1.confidence < 0.5))
      end
    end

    test "skips vendor/node_modules files", %{session: _session} do
      file = %{
        path: "node_modules/some-lib/index.js",
        language: "javascript",
        content: """
        // This has obvious SQL injection but should be skipped
        function bad() {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.execute(query);
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # Vendor files should be skipped entirely
      assert findings == []
    end
  end

  describe "false positive prevention" do
    test "does not flag arithmetic operations as injections", %{session: _session} do
      file = %{
        path: "math.js",
        language: "javascript",
        content: """
        function calculateTotal(price, quantity) {
          const subtotal = price * quantity;
          const tax = subtotal * 0.08;
          const total = subtotal + tax;
          return total;
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # Pure arithmetic should not trigger any security findings
      assert length(findings) == 0
    end

    test "does not flag safe string concatenation", %{session: _session} do
      file = %{
        path: "greeting.js",
        language: "javascript",
        content: """
        function greet(firstName, lastName) {
          const fullName = firstName + ' ' + lastName;
          const message = 'Hello, ' + fullName + '!';
          return message;
        }
        """
      }

      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      # Simple string concatenation without security context should be safe
      injection_findings = Enum.filter(findings, &String.contains?(&1.type, "injection"))
      assert length(injection_findings) == 0
    end
  end

  describe "performance and error handling" do
    test "handles syntax errors gracefully", %{session: _session} do
      file = %{
        path: "broken.js",
        language: "javascript",
        content: "function broken( { // missing closing paren"
      }

      # AnalysisService returns error tuple for parse errors
      {:error, reason} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})

      assert reason != nil
    end

    test "respects includeSecurityPatterns option", %{session: _session} do
      file = %{
        path: "app.js",
        language: "javascript",
        content: """
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.execute(query);
        }
        """
      }

      # With patterns disabled
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => false})
      assert findings == []

      # With patterns enabled
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      assert length(findings) > 0
    end

    test "provides performance metrics", %{session: _session} do
      file = %{
        path: "app.js",
        language: "javascript",
        content: "const x = 1 + 2;"
      }

      {:ok, _findings, metrics} =
        AnalysisService.analyze_file_with_metrics(
          file,
          %{"includeSecurityPatterns" => true}
        )

      assert metrics.ast_parse_time >= 0
      assert metrics.pattern_match_time >= 0
      assert metrics.total_time_ms >= 0
      assert metrics.node_count > 0
      assert is_boolean(metrics.cache_hit)
    end
  end

  describe "batch analysis" do
    test "analyzes multiple files in parallel", %{session: session} do
      files = [
        %{
          path: "file1.js",
          language: "javascript",
          content: "const safe = 1 + 2;"
        },
        %{
          path: "file2.js",
          language: "javascript",
          content: """
          function risky(input) {
            eval(input);
          }
          """
        },
        %{
          path: "file3.js",
          language: "javascript",
          content: "console.log('hello');"
        }
      ]

      {:ok, results} =
        AnalysisService.analyze_batch(
          files,
          %{"includeSecurityPatterns" => true},
          session
        )

      assert length(results) == 3

      # First file should be safe
      assert Enum.find(results, &(&1.path == "file1.js")).findings == []

      # Second file should have eval finding
      file2_result = Enum.find(results, &(&1.path == "file2.js"))
      assert length(file2_result.findings) > 0
      assert Enum.any?(file2_result.findings, &String.contains?(&1.type, "eval"))

      # Third file should be safe
      assert Enum.find(results, &(&1.path == "file3.js")).findings == []
    end
  end
end
