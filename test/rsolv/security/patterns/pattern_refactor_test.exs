defmodule Rsolv.Security.Patterns.PatternRefactorTest do
  use ExUnit.Case
  alias Rsolv.Security.Pattern

  describe "refactored pattern structure" do
    test "javascript pattern module can be loaded and returns valid pattern" do
      # RED: This module doesn't exist yet
      pattern = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert "javascript" in pattern.languages
    end

    test "cross-language patterns can be loaded from common directory" do
      # RED: Common pattern module doesn't exist yet
      pattern = Rsolv.Security.Patterns.Common.WeakJwtSecret.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "weak-jwt-secret"
      assert pattern.languages == ["all"] or pattern.languages == ["*"]
      assert pattern.type == :jwt
    end

    test "pattern module includes comprehensive AST rules" do
      # Now testing enhanced pattern which has AST rules
      module = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat
      enhanced_pattern = module.enhanced_pattern()
      
      assert enhanced_pattern.ast_rules != nil
      assert enhanced_pattern.ast_rules.node_type == "BinaryExpression"
      assert enhanced_pattern.ast_rules.operator != nil
      assert enhanced_pattern.context_rules != nil
      assert enhanced_pattern.confidence_rules != nil
    end

    test "pattern module includes doctests showing vulnerable and safe code" do
      # Module docs are returned as a map with language keys
      module_docs = Code.fetch_docs(Rsolv.Security.Patterns.Javascript.SqlInjectionConcat)
      
      assert {:docs_v1, _, _, _, module_doc, _, _} = module_docs
      assert module_doc != :none
      
      # Extract the English documentation
      doc_text = case module_doc do
        %{"en" => text} -> text
        text when is_binary(text) -> text
      end
      
      assert doc_text =~ "Detects dangerous patterns"
      assert doc_text =~ "Safe patterns:"
    end

    test "pattern includes structured vulnerability metadata" do
      # Each pattern must include vulnerability metadata
      pattern = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()
      metadata = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.vulnerability_metadata()
      
      # Verify required metadata fields
      assert metadata.description =~ "SQL injection"
      assert is_list(metadata.references)
      assert length(metadata.references) > 0
      
      # Each reference should have structured format
      [first_ref | _] = metadata.references
      assert Map.has_key?(first_ref, :type)  # :cwe, :owasp, :nist, :research, :blog, etc.
      assert Map.has_key?(first_ref, :id)    # CWE-89, A03:2021, etc.
      assert Map.has_key?(first_ref, :url)   # Direct link
      assert Map.has_key?(first_ref, :title) # Human-readable title
      
      # Should include attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) > 0
      
      # Should include real-world examples or CVEs if applicable
      assert Map.has_key?(metadata, :known_exploits) or Map.has_key?(metadata, :cve_examples)
    end

    test "pattern registry can collect patterns from individual modules" do
      # RED: Registry doesn't exist yet
      patterns = Rsolv.Security.PatternRegistry.get_patterns_for_language("javascript")
      
      assert length(patterns) > 0
      assert Enum.any?(patterns, fn p -> p.id == "js-sql-injection-concat" end)
    end

    test "AST enhancement still works with refactored patterns" do
      # RED: Integration not updated yet
      pattern = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()
      enhanced = Rsolv.Security.ASTPattern.enhance(pattern)
      
      assert enhanced.ast_rules != nil
      assert enhanced.min_confidence == 0.8
    end
  end

  describe "backward compatibility" do
    test "old pattern module structure still works during migration" do
      # This should still work until we complete migration
      patterns = Rsolv.Security.Patterns.Javascript.all()
      
      assert length(patterns) > 0
      assert Enum.any?(patterns, fn p -> p.id == "js-sql-injection-concat" end)
    end
  end
end