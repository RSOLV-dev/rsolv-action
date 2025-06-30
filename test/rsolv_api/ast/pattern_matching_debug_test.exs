defmodule RsolvApi.AST.PatternMatchingDebugTest do
  @moduledoc """
  TDD Red Phase: Tests to expose exactly where AST pattern matching breaks down.
  
  This test suite isolates each component to identify the root cause of why
  the AST service detects 0 vulnerabilities despite having working infrastructure.
  """
  
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{AnalysisService, SecurityPatternMatcher}
  alias RsolvApi.Security.{PatternRegistry, PatternAdapter}
  alias RsolvApi.Security.Patterns.Python.SqlInjectionConcat
  
  describe "RED Phase: AST Parser Output Structure" do
    test "python parser generates expected AST structure for SQL injection" do
      # Test the raw AST output to understand what the parser actually produces
      code = "query = \"SELECT * FROM users WHERE id = \" + user_id"
      
      {:ok, ast} = AnalysisService.parse_code(code, "python")
      
      # Debug: What does the AST actually look like?
      IO.inspect(ast, label: "Raw Python AST")
      
      # Expected structure based on Python AST:
      # Module(body=[Assign(targets=[Name(id='query')], 
      #                    value=BinOp(left=Constant(value="SELECT..."), 
      #                                op=Add(), 
      #                                right=Name(id='user_id')))])
      
      assert ast["type"] == "Module"
      assert is_list(ast["body"])
      assert length(ast["body"]) >= 1
      
      # Find the assignment statement
      assignment = hd(ast["body"])
      assert assignment["type"] == "Assign"
      
      # Find the BinOp (binary operation)
      bin_op = assignment["value"]
      assert bin_op["type"] == "BinOp"
      
      # This is the key test - what operator structure do we get?
      operator = bin_op["op"]
      IO.inspect(operator, label: "Python AST Operator Structure")
      
      # Document what we actually receive vs what patterns expect
      assert is_map(operator)
    end
    
    test "javascript parser generates expected AST structure for SQL injection" do
      code = "const query = \"SELECT * FROM users WHERE id = \" + userId;"
      
      {:ok, ast} = AnalysisService.parse_code(code, "javascript")
      
      IO.inspect(ast, label: "Raw JavaScript AST")
      
      # Expected structure: BinaryExpression with operator: "+"
      # Find the variable declaration
      assert ast["type"] == "Program"
      assert is_list(ast["body"])
      
      var_decl = hd(ast["body"])
      assert var_decl["type"] == "VariableDeclaration"
      
      declarator = hd(var_decl["declarations"])
      bin_expr = declarator["init"]
      assert bin_expr["type"] == "BinaryExpression"
      
      # Document actual operator format
      operator = bin_expr["operator"]
      IO.inspect(operator, label: "JavaScript AST Operator")
      
      assert operator == "+"
    end
  end
  
  describe "RED Phase: Pattern Structure Expectations" do
    test "sql injection pattern has correct ast_rules structure" do
      pattern = SqlInjectionConcat.pattern()
      enhancement = SqlInjectionConcat.ast_enhancement()
      
      IO.inspect(pattern, label: "SQL Injection Pattern")
      IO.inspect(enhancement, label: "AST Enhancement")
      
      # What does the pattern expect?
      ast_rules = enhancement.ast_rules
      IO.inspect(ast_rules, label: "Expected AST Rules")
      
      # Verify pattern structure
      assert ast_rules.node_type == "BinOp"
      
      # What operator format does the pattern expect?
      if Map.has_key?(ast_rules, :operator) do
        IO.inspect(ast_rules.operator, label: "Pattern Expected Operator")
      end
      
      if Map.has_key?(ast_rules, :op) do
        IO.inspect(ast_rules.op, label: "Pattern Expected Op")
      end
    end
    
    test "pattern expects correct context requirements" do
      enhancement = SqlInjectionConcat.ast_enhancement()
      
      # Check if context requirements are too strict
      context_rules = enhancement[:context_rules] || %{}
      confidence_rules = enhancement[:confidence_rules] || %{}
      min_confidence = enhancement[:min_confidence] || 0.0
      
      IO.inspect(%{
        context_rules: context_rules,
        confidence_rules: confidence_rules, 
        min_confidence: min_confidence
      }, label: "Pattern Requirements")
      
      # Document what might be filtering out matches
      assert is_number(min_confidence)
      assert min_confidence >= 0.0
      assert min_confidence <= 1.0
    end
  end
  
  describe "RED Phase: Pattern Matching Algorithm" do
    test "SecurityPatternMatcher can find BinOp nodes" do
      # Create a controlled AST structure to test matching
      test_ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "Assign",
            "value" => %{
              "type" => "BinOp",
              "op" => %{"type" => "Add"},
              "left" => %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
              "right" => %{"type" => "Name", "id" => "user_id"}
            }
          }
        ]
      }
      
      pattern = SqlInjectionConcat.pattern()
      enhancement = SqlInjectionConcat.ast_enhancement()
      
      # Test the core matching logic
      result = SecurityPatternMatcher.find_matches(test_ast, pattern, enhancement)
      
      IO.inspect(result, label: "Pattern Matching Result")
      
      # This test should fail initially, showing us why matches aren't found
      assert length(result) > 0, "Pattern matcher should find the BinOp node"
    end
    
    test "pattern loading works correctly" do
      # Verify patterns are actually loaded
      python_patterns = PatternRegistry.get_patterns_for_language("python")
      
      IO.inspect(length(python_patterns), label: "Number of Python patterns loaded")
      
      assert length(python_patterns) > 0, "Should load Python patterns"
      
      # Find our SQL injection pattern
      sql_pattern = Enum.find(python_patterns, fn p -> p.id == "python-sql-injection-concat" end)
      
      assert sql_pattern != nil, "SQL injection pattern should be loaded"
      
      IO.inspect(sql_pattern, label: "Loaded SQL Injection Pattern")
    end
  end
  
  describe "RED Phase: End-to-End Integration" do
    test "simple SQL injection should be detected" do
      # This is our main failing test - it should pass after we fix the issues above
      code = "query = \"SELECT * FROM users WHERE id = \" + user_id"
      
      options = %{
        language: "python",
        patterns: ["python-sql-injection-concat"]
      }
      
      session = %{id: "test-session"}
      
      result = AnalysisService.analyze_file(code, options, session)
      
      IO.inspect(result, label: "End-to-End Analysis Result")
      
      # This test should fail initially, but will pass after we fix the component issues
      assert length(result.findings) > 0, "Should detect SQL injection vulnerability"
      
      finding = hd(result.findings)
      assert finding.pattern_type == "sql_injection"
      assert finding.severity == "critical"
    end
  end
end