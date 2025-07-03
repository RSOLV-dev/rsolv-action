defmodule Rsolv.Security.PatternsTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns
  
  describe "Pattern struct" do
    test "has required fields" do
      pattern = %Pattern{
        id: "test-pattern",
        name: "Test Pattern",
        description: "Test description",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        regex: ~r/test/,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use prepared statements",
        test_cases: %{
          vulnerable: ["vulnerable code"],
          safe: ["safe code"]
        }
      }
      
      assert pattern.id == "test-pattern"
      assert pattern.severity in [:low, :medium, :high, :critical]
    end
  end
  
  describe "Pattern modules exist" do
    # Only test modules that are actually implemented
    @languages ~w(javascript python java elixir php cve)a
    
    for language <- @languages do
      test "#{language} pattern module exists" do
        module = Module.concat(Rsolv.Security.Patterns, unquote(language |> to_string() |> Macro.camelize()))
        assert Code.ensure_loaded?(module), "Expected module #{module} to exist"
      end
    end
  end
  
  describe "JavaScript patterns" do
    test "module exports sql_injection_concat/0" do
      assert function_exported?(Rsolv.Security.Patterns.Javascript, :sql_injection_concat, 0)
    end
    
    test "module exports all/0 returning all patterns" do
      assert function_exported?(Rsolv.Security.Patterns.Javascript, :all, 0)
      patterns = Rsolv.Security.Patterns.Javascript.all()
      assert length(patterns) == 30
    end
    
    test "sql_injection_concat pattern structure is valid" do
      pattern = Rsolv.Security.Patterns.Javascript.sql_injection_concat()
      
      assert pattern.id == "js-sql-injection-concat"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert "javascript" in pattern.languages
      assert %Regex{} = pattern.regex
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "sql_injection_concat detects vulnerable code" do
      pattern = Rsolv.Security.Patterns.Javascript.sql_injection_concat()
      
      vulnerable_code = ~s(const query = "SELECT * FROM users WHERE id = " + userId)
      assert Regex.match?(pattern.regex, vulnerable_code),
        "Pattern should match: #{vulnerable_code}"
        
      safe_code = ~s(const query = "SELECT * FROM users WHERE id = ?")
      refute Regex.match?(pattern.regex, safe_code),
        "Pattern should not match: #{safe_code}"
    end
  end
  
  describe "Pattern count verification" do
    test "total working pattern count is 116" do
      # Only count working modules
      working_languages = ~w(javascript python java elixir php cve)a
      total = Enum.reduce(working_languages, 0, fn language, acc ->
        module = Module.concat(Patterns, language |> to_string() |> Macro.camelize())
        patterns = apply(module, :all, [])
        acc + length(patterns)
      end)
      
      assert total == 116, "Expected 116 patterns but got #{total}"
    end
    
    test "pattern counts by language" do
      # Only test working modules
      expected_counts = %{
        javascript: 30,
        python: 12,
        java: 17,
        elixir: 28,
        php: 25,
        cve: 4
      }
      
      Enum.each(expected_counts, fn {language, expected_count} ->
        module = Module.concat(Patterns, language |> to_string() |> Macro.camelize())
        patterns = apply(module, :all, [])
        actual_count = length(patterns)
        
        assert actual_count == expected_count,
          "Expected #{expected_count} #{language} patterns but got #{actual_count}"
      end)
    end
  end
  
  describe "Pattern validation" do
    # Only test working modules
    @languages ~w(javascript python java elixir php cve)a
    
    for language <- @languages do
      test "all #{language} patterns have valid structure" do
        module = Module.concat(Rsolv.Security.Patterns, unquote(language |> to_string() |> Macro.camelize()))
        patterns = apply(module, :all, [])
        
        Enum.each(patterns, fn pattern ->
          # ID validation
          assert is_binary(pattern.id)
          assert pattern.id =~ ~r/^[a-z0-9-]+$/
          
          # Required fields
          assert is_binary(pattern.name)
          assert is_binary(pattern.description)
          assert is_atom(pattern.type)
          assert pattern.severity in [:low, :medium, :high, :critical]
          assert is_list(pattern.languages)
          assert is_binary(pattern.recommendation)
          
          # Regex validation
          assert (match?(%Regex{}, pattern.regex) or is_list(pattern.regex))
          
          # Test cases
          assert is_map(pattern.test_cases)
          assert is_list(pattern.test_cases.vulnerable)
          assert is_list(pattern.test_cases.safe)
          assert length(pattern.test_cases.vulnerable) >= 1
          assert length(pattern.test_cases.safe) >= 1
        end)
      end
      
      test "all #{language} patterns detect their vulnerable test cases" do
        module = Module.concat(Rsolv.Security.Patterns, unquote(language |> to_string() |> Macro.camelize()))
        patterns = apply(module, :all, [])
        
        Enum.each(patterns, fn pattern ->
          regexes = case pattern.regex do
            %Regex{} = r -> [r]
            list when is_list(list) -> list
          end
          
          # Each vulnerable case should match at least one regex
          Enum.each(pattern.test_cases.vulnerable, fn vuln_code ->
            matches = Enum.any?(regexes, fn regex ->
              Regex.match?(regex, vuln_code)
            end)
            
            assert matches,
              "Pattern #{pattern.id} should match vulnerable code: #{inspect(vuln_code)}"
          end)
          
          # Safe cases should not match any regex
          Enum.each(pattern.test_cases.safe, fn safe_code ->
            matches = Enum.any?(regexes, fn regex ->
              Regex.match?(regex, safe_code)
            end)
            
            refute matches,
              "Pattern #{pattern.id} should not match safe code: #{inspect(safe_code)}"
          end)
        end)
      end
    end
  end
end