defmodule RsolvApi.AST.IntegrationTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.AST.{AnalysisService, SessionManager, PortSupervisor}
  alias RsolvApi.Security.PatternRegistry
  
  setup do
    # Services are already started by the application
    # Just create a session
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
      assert sql_injection.location.startLine == 2  # Line with concatenation
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
      assert length(findings) == 0
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
        content: "function broken( {"  # Invalid syntax
      }
      
      options = %{"includeSecurityPatterns" => true}
      
      {:error, details} = AnalysisService.analyze_file(file, options)
      assert details.type == :syntax_error
      assert details.message != nil
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
      files = for i <- 1..10 do
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
      results = Enum.map(files, fn file ->
        AnalysisService.analyze_file(file, options)
      end)
      
      end_time = System.monotonic_time(:millisecond)
      total_time = end_time - start_time
      
      # Should complete within 2 seconds
      assert total_time < 2000
      
      # All should succeed
      assert Enum.all?(results, fn result ->
        match?({:ok, _}, result)
      end)
    end
  end
end