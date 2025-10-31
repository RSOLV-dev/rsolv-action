defmodule Rsolv.AST.IntegrationTest do
  use Rsolv.IntegrationCase

  alias Rsolv.AST.{AnalysisService, SessionManager, PortSupervisor}
  alias Rsolv.Security.PatternRegistry

  setup do
    # Start required services if not running
    if Process.whereis(Rsolv.Security.PatternServer) == nil do
      {:ok, _} = start_supervised(Rsolv.Security.PatternServer)
    end

    if Process.whereis(Rsolv.AST.AnalysisService) == nil do
      {:ok, _} = start_supervised(Rsolv.AST.AnalysisService)
    end

    # Create a session
    {:ok, session} = SessionManager.create_session("test-customer")

    {:ok, session: session}
  end

  describe "full analysis flow" do
    test "detects SQL injection in JavaScript using AST patterns", %{session: _session} do
      # Create a JavaScript file with SQL injection vulnerability
      file = %{
        path: "vulnerable.js",
        language: "javascript",
        content: """
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.execute(query);
        }
        """
      }

      # Analyze with security patterns enabled
      options = %{"includeSecurityPatterns" => true}

      {:ok, findings} = AnalysisService.analyze_file(file, options)

      # Should detect SQL injection
      assert length(findings) > 0

      sql_injection = Enum.find(findings, &(&1.type == "js-sql-injection-concat"))
      assert sql_injection != nil
      assert sql_injection.severity == "high"
      assert sql_injection.confidence >= 0.7
      # Line with concatenation
      assert sql_injection.location.startLine == 2
    end

    test "skips vendor files", %{session: _session} do
      # Create a vendor file
      file = %{
        path: "node_modules/some-lib/index.js",
        language: "javascript",
        content: """
        // This has SQL injection but should be skipped
        const query = "SELECT * FROM users WHERE id = " + userId;
        """
      }

      options = %{"includeSecurityPatterns" => true}

      {:ok, findings} = AnalysisService.analyze_file(file, options)

      # Should skip vendor files
      assert findings == []
    end

    test "respects confidence thresholds", %{session: _session} do
      # Create a file with potential false positive
      file = %{
        path: "safe.js",
        language: "javascript",
        content: """
        // This looks like SQL but is actually safe
        const message = "User selected option: SELECT * FROM menu";
        console.log(message + userChoice);
        """
      }

      options = %{"includeSecurityPatterns" => true}

      {:ok, findings} = AnalysisService.analyze_file(file, options)

      # Should not report low-confidence matches
      assert Enum.empty?(findings)
    end

    test "includes context information in findings", %{session: _session} do
      file = %{
        path: "app.js",
        language: "javascript",
        content: """
        function processUserInput(input) {
          // Dangerous eval
          eval(input);
        }
        """
      }

      options = %{"includeSecurityPatterns" => true}

      {:ok, findings} = AnalysisService.analyze_file(file, options)

      assert length(findings) > 0

      eval_finding = Enum.find(findings, &String.contains?(&1.type, "eval"))
      assert eval_finding != nil
      assert eval_finding.context.nodeType != nil
      assert eval_finding.context.inTestFile == false
    end

    test "handles syntax errors gracefully", %{session: _session} do
      file = %{
        path: "broken.js",
        language: "javascript",
        # Invalid syntax
        content: "function broken( {"
      }

      options = %{"includeSecurityPatterns" => true}

      result = AnalysisService.analyze_file(file, options)
      assert {:error, {:parser_error, %{type: "ParseError", message: message}}} = result
      assert message.type == :syntax_error
      assert message.message != nil
    end

    test "works with multiple languages", %{session: _session} do
      # Test Python file
      python_file = %{
        path: "app.py",
        language: "python",
        content: """
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            return db.execute(query)
        """
      }

      options = %{"includeSecurityPatterns" => true}

      {:ok, findings} = AnalysisService.analyze_file(python_file, options)

      # Should detect SQL injection in Python
      assert length(findings) > 0
      sql_finding = Enum.find(findings, &String.contains?(&1.type, "sql"))
      assert sql_finding != nil
    end
  end

  describe "performance" do
    test "analyzes files within performance budget", %{session: _session} do
      # Create 10 test files
      files =
        for i <- 1..10 do
          %{
            path: "file#{i}.js",
            language: "javascript",
            content: """
            function process#{i}(data) {
              // Some code
              const result = data.map(x => x * 2);
              return result;
            }
            """
          }
        end

      options = %{"includeSecurityPatterns" => true}

      start_time = System.monotonic_time(:millisecond)

      # Analyze all files
      results =
        Enum.map(files, fn file ->
          AnalysisService.analyze_file(file, options)
        end)

      end_time = System.monotonic_time(:millisecond)
      total_time = end_time - start_time

      # Performance budget: 2s locally, 5s in CI (accounts for resource constraints)
      timeout = if System.get_env("CI"), do: 5000, else: 2000

      assert total_time < timeout,
             "Analysis took #{total_time}ms, expected < #{timeout}ms (CI: #{System.get_env("CI") != nil})"

      # All should succeed
      assert Enum.all?(results, fn result ->
               match?({:ok, _}, result)
             end)
    end
  end
end
