defmodule Rsolv.Security.Patterns.Elixir.SqlInjectionInterpolationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Elixir.SqlInjectionInterpolation
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-sql-injection-interpolation"
      assert pattern.name == "Ecto SQL Injection via String Interpolation"
      assert pattern.severity == :critical
      assert pattern.type == :sql_injection
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["ecto"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
    end
    
    test "includes comprehensive test cases" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "parameterized") or
             String.contains?(String.downcase(pattern.recommendation), "variable")
      assert String.contains?(String.downcase(pattern.recommendation), "ecto") or
             String.contains?(String.downcase(pattern.recommendation), "query")
    end
  end
  
  describe "regex matching" do
    test "detects Repo.query! with string interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Repo.query!("SELECT * FROM users WHERE name = '#{name}'")|,
        ~S|Repo.query!("DELETE FROM posts WHERE id = #{id}")|,
        ~S|Repo.query!("UPDATE users SET email = '#{email}' WHERE id = #{user_id}")|,
        ~S|MyApp.Repo.query!("INSERT INTO logs (message) VALUES ('#{message}')")|,
        ~S|repo.query!("SELECT * FROM accounts WHERE balance > #{amount}")|,
        ~S|Repo.query!("SELECT COUNT(*) FROM sessions WHERE user_id = #{id}")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Repo.query with string interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Repo.query("SELECT * FROM products WHERE category = '#{category}'")|,
        ~S|Repo.query("SELECT id FROM users WHERE username = '#{username}'")|,
        ~S|App.Repo.query("DELETE FROM temp_data WHERE created_at < '#{date}'")|,
        ~S|repo.query("UPDATE settings SET value = '#{value}' WHERE key = 'config'")|,
        ~S|MyRepo.query("SELECT * FROM orders WHERE status = '#{status}'")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Ecto.Adapters.SQL.query! with string interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Ecto.Adapters.SQL.query!(Repo, "SELECT * FROM users WHERE role = '#{role}'")|,
        ~S|Ecto.Adapters.SQL.query!(MyApp.Repo, "DELETE FROM sessions WHERE token = '#{token}'")|,
        ~S|Ecto.Adapters.SQL.query!(repo, "UPDATE counters SET value = #{count} WHERE name = 'visitors'")|,
        ~S|Ecto.Adapters.SQL.query!(Repo, "INSERT INTO audit_logs (action) VALUES ('#{action}')")|,
        ~S|Ecto.Adapters.SQL.query!(App.Repo, "SELECT id FROM permissions WHERE user_id = #{user_id}")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Ecto.Adapters.SQL.query with string interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Ecto.Adapters.SQL.query(Repo, "SELECT * FROM articles WHERE status = '#{status}'")|,
        ~S|Ecto.Adapters.SQL.query(MyRepo, "DELETE FROM cache WHERE key = '#{cache_key}'")|,
        ~S|Ecto.Adapters.SQL.query(repo, "UPDATE metrics SET count = #{new_count} WHERE type = 'page_views'")|,
        ~S|Ecto.Adapters.SQL.query(App.Repo, "SELECT email FROM subscribers WHERE active = #{is_active}")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects fragment with string interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|fragment("SELECT * FROM users WHERE name = '#{name}'")|,
        ~S|fragment("COUNT(*) FILTER (WHERE status = '#{status}')")|,
        ~S|fragment("CASE WHEN role = '#{role}' THEN 1 ELSE 0 END")|,
        ~S|fragment("json_extract(data, '$.#{field}')")|,
        ~S|fragment("date_trunc('day', created_at) > '#{date}'")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects multiline queries with interpolation" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Repo.query!("SELECT u.id, u.name, p.title FROM users u JOIN posts p ON p.user_id = u.id WHERE u.role = '#{role}'")|,
        ~S|Ecto.Adapters.SQL.query!(Repo, "UPDATE statistics SET count = count + 1 WHERE category = '#{category}'")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe parameterized queries" do
      pattern = SqlInjectionInterpolation.pattern()
      
      safe_code = [
        ~S|Repo.query!("SELECT * FROM users WHERE name = $1", [name])|,
        ~S|Ecto.Adapters.SQL.query!(Repo, "DELETE FROM posts WHERE id = $1", [id])|,
        ~S|from(u in User, where: u.name == ^name)|,
        ~S|from(p in Post, where: p.user_id == ^user_id)|,
        ~S|query = from u in User, select: u.email|,
        ~S|Repo.all(from u in User, where: u.active == ^active)|,
        ~S|Repo.query!("SELECT * FROM users WHERE id = ?", [user_id])|,
        ~S|// SQL injection via interpolation: "SELECT * FROM users WHERE id = #{id}"|,
        ~S|"This is just a string with #{interpolation} but not SQL"|,
        ~S|IO.puts("Debug: user_id = #{user_id}")|,
        ~S|Logger.info("Processing user #{username}")|
      ]
      
      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects various repo naming patterns" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|MyApp.Repo.query!("SELECT * FROM users WHERE role = '#{role}'")|,
        ~S|App.MainRepo.query("DELETE FROM logs WHERE level = '#{level}'")|,
        ~S|ProjectRepo.query!("UPDATE settings WHERE key = '#{key}'")|,
        ~S|Accounts.Repo.query("SELECT id FROM permissions WHERE name = '#{permission}'")|,
        ~S|Core.DatabaseRepo.query!("INSERT INTO events (type) VALUES ('#{event_type}')")|
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects interpolation with different variable patterns" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_code = [
        ~S|Repo.query!("SELECT * FROM users WHERE name = '#{user.name}'")|,
        ~S|Repo.query!("DELETE FROM posts WHERE id = #{@post_id}")|,
        ~S|Repo.query!("UPDATE accounts SET balance = #{account[:balance]}")|,
        ~S|Repo.query!("SELECT * FROM logs WHERE level = '#{params["level"]}'")|,
        ~S|Repo.query!("INSERT INTO events (data) VALUES ('#{Map.get(event, :data)}')")|,
        ~S|Repo.query!("SELECT id FROM sessions WHERE token = '#{conn.assigns.token}'")|
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
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "sql") and
             String.contains?(String.downcase(metadata.description), "injection")
      assert String.contains?(String.downcase(metadata.description), "interpolation") or
             String.contains?(String.downcase(metadata.description), "string")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes Elixir/Ecto specific information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "Ecto") or 
             String.contains?(metadata.description, "Repo.query")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "parameterized")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "$1"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "^")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "binding"))
    end
    
    test "includes proper security references" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes OWASP Top 10 information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert Enum.any?(metadata.references, fn ref ->
        String.contains?(String.downcase(ref.title), "owasp") and 
        String.contains?(String.downcase(ref.title), "a03")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes Elixir-specific attack information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "ecto") or
        String.contains?(String.downcase(pattern), "parameterized") or
        String.contains?(String.downcase(pattern), "binding")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes SQL query analysis" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "StringLiteral" or
             enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.sql_analysis.check_query_methods
      assert enhancement.ast_rules.sql_analysis.repo_methods
      assert enhancement.ast_rules.sql_analysis.interpolation_patterns
    end
    
    test "has interpolation detection rules" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert enhancement.ast_rules.interpolation_analysis.check_string_interpolation
      assert enhancement.ast_rules.interpolation_analysis.interpolation_markers
      assert enhancement.ast_rules.interpolation_analysis.variable_patterns
    end
    
    test "includes Ecto-specific analysis" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert enhancement.ast_rules.ecto_analysis.check_ecto_usage
      assert enhancement.ast_rules.ecto_analysis.safe_query_methods
      assert enhancement.ast_rules.ecto_analysis.unsafe_query_methods
    end
    
    test "includes context-based filtering" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert enhancement.context_rules.check_parameterization
      assert enhancement.context_rules.safe_if_parameterized
      assert enhancement.context_rules.unsafe_interpolation_indicators
    end
    
    test "has proper confidence scoring" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_parameterization")
      assert Map.has_key?(adjustments, "direct_interpolation")
      assert Map.has_key?(adjustments, "in_test_code")
      assert Map.has_key?(adjustments, "ecto_safe_method")
    end
  end
end