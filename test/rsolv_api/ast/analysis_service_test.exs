defmodule RsolvApi.AST.AnalysisServiceTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.AST.AnalysisService
  alias RsolvApi.AST.SessionManager
  alias RsolvApi.AST.ParserRegistry
  
  setup do
    # Ensure the application is started
    Application.ensure_all_started(:rsolv_api)
    :ok
  end
  
  describe "file analysis" do
    test "analyzes JavaScript file for security patterns" do
      file = %{
        path: "src/api.js",
        content: """
        function handleRequest(userInput) {
          // SQL injection vulnerability
          const query = "SELECT * FROM users WHERE id = " + userInput;
          db.query(query);
        }
        """,
        language: "javascript",
        metadata: %{}
      }
      
      options = %{
        "patternFormat" => "enhanced",
        "includeSecurityPatterns" => true
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, options)
      
      assert is_list(findings)
      assert length(findings) > 0
      
      # Should find SQL injection vulnerability - check for pattern IDs containing "sql"
      sql_injection = Enum.find(findings, &(String.contains?(&1.type, "sql") || String.contains?(&1.patternId, "sql")))
      assert sql_injection != nil
      assert sql_injection.severity in ["high", "critical"]
    end
    
    test "analyzes Python file for security patterns" do
      file = %{
        path: "app.py",
        content: """
        import os
        
        def run_command(user_input):
            # Command injection vulnerability
            cmd = "echo " + user_input
            os.system(cmd)
        """,
        language: "python",
        metadata: %{}
      }
      
      options = %{
        "patternFormat" => "enhanced",
        "includeSecurityPatterns" => true
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, options)
      
      assert is_list(findings)
      
      # Should find command injection
      cmd_injection = Enum.find(findings, &(String.contains?(&1.type, "command") || String.contains?(&1.patternId, "command")))
      assert cmd_injection != nil
      assert cmd_injection.severity in ["high", "critical"]
    end
    
    test "returns empty findings for safe code" do
      file = %{
        path: "safe.js",
        content: """
        function add(a, b) {
          return a + b;
        }
        """,
        language: "javascript",
        metadata: %{}
      }
      
      options = %{"includeSecurityPatterns" => true}
      
      {:ok, findings} = AnalysisService.analyze_file(file, options)
      
      assert findings == []
    end
    
    test "handles parsing errors gracefully" do
      file = %{
        path: "invalid.js",
        content: "function broken( { invalid syntax",
        language: "javascript",
        metadata: %{}
      }
      
      options = %{"includeSecurityPatterns" => true}
      
      {:error, {:parser_error, details}} = AnalysisService.analyze_file(file, options)
      
      assert details.type == "SyntaxError"
      assert details.message =~ "Unexpected token"
    end
    
    test "respects timeout limits" do
      file = %{
        path: "timeout.js",
        content: "FORCE_TIMEOUT_SIGNAL",
        language: "javascript",
        metadata: %{}
      }
      
      options = %{
        "performance" => %{
          "maxParseTime" => 100  # 100ms timeout
        }
      }
      
      {:error, :timeout} = AnalysisService.analyze_file(file, options)
    end
  end
  
  describe "batch analysis" do
    test "analyzes multiple files concurrently" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      files = [
        %{
          path: "file1.js",
          content: "const x = 1;",
          language: "javascript"
        },
        %{
          path: "file2.py",
          content: "x = 1",
          language: "python"
        }
      ]
      
      options = %{"includeSecurityPatterns" => false}
      
      {:ok, results} = AnalysisService.analyze_batch(files, options, session)
      
      assert length(results) == 2
      assert Enum.all?(results, &(&1.status == "success"))
    end
    
    test "continues on individual file failures" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      files = [
        %{
          path: "good.js",
          content: "const x = 1;",
          language: "javascript"
        },
        %{
          path: "bad.js",
          content: "function broken( {",
          language: "javascript"
        }
      ]
      
      options = %{"includeSecurityPatterns" => false}
      
      {:ok, results} = AnalysisService.analyze_batch(files, options, session)
      
      assert length(results) == 2
      
      good_result = Enum.find(results, &(&1.path == "good.js"))
      assert good_result.status == "success"
      
      bad_result = Enum.find(results, &(&1.path == "bad.js"))
      assert bad_result.status == "error"
    end
  end
  
  describe "AST pattern matching" do
    test "identifies patterns using AST structure" do
      file = %{
        path: "vulnerable.js",
        content: """
        function getUserData(userId) {
          // Direct string concatenation in SQL
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.query(query);
        }
        """,
        language: "javascript"
      }
      
      # Use a more comprehensive options for this test
      options = %{
        "patternFormat" => "enhanced",
        "includeSecurityPatterns" => true,
        "minConfidence" => 0.1  # Lower threshold to see all patterns
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, options)
      
      sql_finding = Enum.find(findings, &(String.contains?(&1.type, "sql") || String.contains?(&1.patternId, "sql")))
      
      # Should have AST context
      assert sql_finding != nil
      assert sql_finding.context.nodeType == "BinaryExpression"
      assert sql_finding.context.parentNodeType != nil
      assert sql_finding.context.hasValidation == false
    end
    
    test "detects secure pattern usage" do
      file = %{
        path: "secure.js",
        content: """
        function getUserData(userId) {
          // Parameterized query - safe
          return db.query('SELECT * FROM users WHERE id = ?', [userId]);
        }
        """,
        language: "javascript"
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{})
      
      # Should not find SQL injection when using parameterized queries
      sql_findings = Enum.filter(findings, &(&1.type == "sql_injection"))
      assert sql_findings == []
    end
  end
  
  describe "performance" do
    test "tracks parsing performance metrics" do
      file = %{
        path: "test.js",
        content: "const x = 1;",
        language: "javascript"
      }
      
      {:ok, findings, metrics} = AnalysisService.analyze_file_with_metrics(file, %{})
      
      assert metrics.ast_parse_time >= 0
      assert metrics.pattern_match_time > 0  # Should be at least 1ms as per code
      assert metrics.total_time_ms > 0
      assert metrics.node_count > 0
    end
    
    test "caches parsed AST for repeated analysis" do
      file = %{
        path: "cached.js",
        content: "const x = 1;",
        language: "javascript"
      }
      
      # First parse
      {:ok, _, metrics1} = AnalysisService.analyze_file_with_metrics(file, %{})
      
      # Second parse (should use cache)
      {:ok, _, metrics2} = AnalysisService.analyze_file_with_metrics(file, %{})
      
      # Second analysis should hit cache (cache_hit: true)
      assert metrics2.cache_hit == true
      assert metrics1.cache_hit == false
    end
  end
end