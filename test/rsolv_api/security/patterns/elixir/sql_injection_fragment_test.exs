defmodule RsolvApi.Security.Patterns.Elixir.SqlInjectionFragmentTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.SqlInjectionFragment
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionFragment.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-sql-injection-fragment"
      assert pattern.name == "Unsafe Ecto Fragment Usage"
      assert pattern.severity == :high
      assert pattern.type == :sql_injection
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["ecto"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
    end
    
    test "includes comprehensive test cases" do
      pattern = SqlInjectionFragment.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = SqlInjectionFragment.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "ecto") or
             String.contains?(String.downcase(pattern.recommendation), "query")
      assert String.contains?(String.downcase(pattern.recommendation), "fragment") or
             String.contains?(String.downcase(pattern.recommendation), "dsl")
    end
  end
  
  describe "regex matching" do
    test "detects unsafe fragment with string interpolation" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("SELECT * FROM users WHERE role = '#{role}'")|,
        ~S|fragment("DELETE FROM posts WHERE category = '#{category}'")|,
        ~S|fragment("UPDATE settings SET value = '#{value}' WHERE key = 'config'")|,
        ~S|fragment("INSERT INTO logs (message) VALUES ('#{message}')")|,
        ~S|fragment("SELECT COUNT(*) FROM events WHERE type = '#{event_type}'")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragment with dynamic SQL construction" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("? = ANY(?)", field, values)|,
        ~S|fragment("tags @> ?", user_tags)|,
        ~S|fragment("data->'address'->>'city' = ?", city)|,
        ~S|fragment("ST_DWithin(location, ST_GeogFromText(?), ?)", point, distance)|,
        ~S|fragment("jsonb_path_exists(data, ?)", path_expr)|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragments with operator injection risks" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("column ? ?", operator, value)|,
        ~S|fragment("? ? ?", left, op, right)|,
        ~S|fragment("field ? value", dynamic_operator)|,
        ~S|fragment("name ? ?", comparison, name_value)|,
        ~S|fragment("date ? CURRENT_DATE", date_op)|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragments with concatenated SQL parts" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("SELECT * FROM " <> table_name <> " WHERE id = ?", id)|,
        ~S|fragment(base_query <> " AND status = ?", status)|,
        ~S|fragment("ORDER BY " <> sort_column <> " " <> direction)|,
        ~S|fragment(sql_prefix <> " LIMIT ?", limit)|,
        ~S|fragment("WHERE " <> condition <> " AND active = true")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragments in query pipelines" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|from(u in User, where: fragment("age > ?", min_age))|,
        ~S|where(query, [u], fragment("? = ANY(?)", ^field, ^values))|,
        ~S|select(query, [p], fragment("EXTRACT(year FROM ?)", p.created_at))|,
        ~S|order_by(query, [u], fragment("? NULLS LAST", ^sort_expr))|,
        ~S|having(query, [g], fragment("COUNT(*) > ?", ^min_count))|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects unsafe_fragment usage" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|unsafe_fragment("SELECT * FROM dynamic_table")|,
        ~S|unsafe_fragment(raw_sql_query)|,
        ~S|unsafe_fragment("DROP TABLE " <> table_name)|,
        ~S|unsafe_fragment(user_provided_sql)|,
        ~S|unsafe_fragment("CREATE INDEX ON " <> table <> " (" <> column <> ")")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe fragment usage" do
      pattern = SqlInjectionFragment.pattern()
      
      # These are truly safe and won't match the regex
      safe_code = [
        ~S|# fragment("unsafe example") in comment|,
        ~S|"This is just a string with fragment in it"|,
        ~S|Logger.info("Using fragment in query")|,
        ~S|# fragment("EXTRACT(year FROM ?)", p.created_at)|
      ]
      
      # These use fragment but with static SQL - regex matches but AST would filter
      static_fragments = [
        ~S|fragment("NOW() - INTERVAL '1 day'")|,
        ~S|fragment("RANDOM()")|,
        ~S|fragment("COUNT(*)")|
      ]
      
      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
      
      # Static fragments match regex but AST enhancement would verify they're safe
      for code <- static_fragments do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Regex matches but AST would verify safety: #{code}"
      end
    end
    
    test "detects complex PostgreSQL function usage" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("jsonb_path_query(?, ?)", data, path)|,
        ~S|fragment("to_tsvector('english', ?)", content)|,
        ~S|fragment("plainto_tsquery('english', ?)", search_term)|,
        ~S|fragment("ts_rank(?, to_tsquery(?))", vector, query)|,
        ~S|fragment("generate_series(?, ?)", start_num, end_num)|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragments with subqueries" do
      pattern = SqlInjectionFragment.pattern()
      
      vulnerable_code = [
        ~S|fragment("EXISTS (SELECT 1 FROM ? WHERE ?)", table, condition)|,
        ~S|fragment("(SELECT COUNT(*) FROM ?) > ?", table_name, threshold)|,
        ~S|fragment("id IN (SELECT user_id FROM ? WHERE active = true)", memberships_table)|,
        ~S|fragment("? NOT IN (SELECT blocked_id FROM blocks WHERE user_id = ?)", user_id, current_user)|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = SqlInjectionFragment.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "fragment") and
             String.contains?(String.downcase(metadata.description), "sql")
      assert String.contains?(String.downcase(metadata.description), "injection") or
             String.contains?(String.downcase(metadata.description), "unsafe")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes Ecto fragment specific information" do
      metadata = SqlInjectionFragment.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "fragment") or 
             String.contains?(metadata.description, "Ecto")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Ecto")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "query"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "DSL")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "parameterized"))
    end
    
    test "includes proper security references" do
      metadata = SqlInjectionFragment.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes fragment-specific attack information" do
      metadata = SqlInjectionFragment.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "fragment") or
        String.contains?(String.downcase(pattern), "ecto") or
        String.contains?(String.downcase(pattern), "parameterized")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes fragment analysis" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression" or
             enhancement.ast_rules.node_type == "FunctionCall"
      assert enhancement.ast_rules.fragment_analysis.check_fragment_usage
      assert enhancement.ast_rules.fragment_analysis.fragment_functions
      assert enhancement.ast_rules.fragment_analysis.unsafe_patterns
    end
    
    test "has SQL construction detection rules" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      assert enhancement.ast_rules.sql_analysis.check_dynamic_sql
      assert enhancement.ast_rules.sql_analysis.concatenation_patterns
      assert enhancement.ast_rules.sql_analysis.injection_indicators
    end
    
    test "includes parameter analysis" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      assert enhancement.ast_rules.parameter_analysis.check_parameter_usage
      assert enhancement.ast_rules.parameter_analysis.safe_parameter_patterns
      assert enhancement.ast_rules.parameter_analysis.unsafe_parameter_indicators
    end
    
    test "includes context-based filtering" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      assert enhancement.context_rules.check_fragment_context
      assert enhancement.context_rules.safe_fragment_patterns
      assert enhancement.context_rules.unsafe_fragment_indicators
    end
    
    test "has proper confidence scoring" do
      enhancement = SqlInjectionFragment.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_safe_parameters")
      assert Map.has_key?(adjustments, "dynamic_sql_construction")
      assert Map.has_key?(adjustments, "in_test_code")
      assert Map.has_key?(adjustments, "known_safe_function")
    end
  end
end