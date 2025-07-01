defmodule RsolvApi.Security.Patterns.PatternBaseTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Pattern
  
  # Create a test module to verify PatternBase behavior
  defmodule TestPattern do
    use RsolvApi.Security.Patterns.PatternBase
    
    @impl true
    def pattern do
      %Pattern{
        id: "test-pattern",
        name: "Test Pattern",
        description: "A test pattern",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        regex: ~r/test/,
        recommendation: "Test recommendation",
        test_cases: %{
          vulnerable: ["test vulnerable"],
          safe: ["test safe"]
        }
      }
    end
    
    # Define vulnerability_metadata as a public function
    def vulnerability_metadata do
      %{
        description: "Test metadata",
        references: [],
        attack_vectors: [],
        safe_alternatives: []
      }
    end
  end
  
  describe "PatternBase macro" do
    test "exports pattern/0 function" do
      assert function_exported?(TestPattern, :pattern, 0)
    end
    
    test "exports vulnerability_metadata/0 function" do
      assert function_exported?(TestPattern, :vulnerability_metadata, 0)
    end
    
    test "does not export applies_to_file?/1 function" do
      refute function_exported?(TestPattern, :applies_to_file?, 1)
    end
    
    test "exports applies_to_file?/2 function" do
      assert function_exported?(TestPattern, :applies_to_file?, 2)
    end
    
    test "pattern/0 returns expected structure" do
      pattern = TestPattern.pattern()
      assert %Pattern{} = pattern
      assert pattern.id == "test-pattern"
    end
    
    test "vulnerability_metadata/0 returns expected structure" do
      metadata = TestPattern.vulnerability_metadata()
      assert is_map(metadata)
      assert metadata.description == "Test metadata"
    end
    
    test "applies_to_file?/1 works with file extensions" do
      assert TestPattern.applies_to_file?("test.js", nil)
      refute TestPattern.applies_to_file?("test.py", nil)
    end
  end
  
  describe "applies_to_file? with cross-language patterns" do
    defmodule CrossLanguagePattern do
      use RsolvApi.Security.Patterns.PatternBase
      
      @impl true
      def pattern do
        %Pattern{
          id: "cross-lang",
          name: "Cross Language",
          description: "Applies to all languages",
          type: :sql_injection,
          severity: :high,
          languages: ["all"],
          regex: ~r/test/,
          recommendation: "Test",
          test_cases: %{vulnerable: ["test"], safe: ["test"]}
        }
      end
      
      def vulnerability_metadata, do: %{}
    end
    
    test "cross-language patterns apply to all files" do
      assert CrossLanguagePattern.applies_to_file?("test.js", nil)
      assert CrossLanguagePattern.applies_to_file?("test.py", nil)
      assert CrossLanguagePattern.applies_to_file?("test.rb", nil)
      assert CrossLanguagePattern.applies_to_file?("test.unknown", nil)
    end
  end
end