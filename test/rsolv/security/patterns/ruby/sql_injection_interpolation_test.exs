defmodule Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolation
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-sql-injection-interpolation"
      assert pattern.name == "SQL Injection via String Interpolation"
      assert pattern.severity == :critical
      assert pattern.type == :sql_injection
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SqlInjectionInterpolation.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches ActiveRecord connection execute with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")|,
        ~S|connection.execute("UPDATE users SET name = '#{name}' WHERE id = #{id}")|,
        ~S|conn.execute("DELETE FROM posts WHERE user_id = #{user_id}")|,
        ~S|db.execute("INSERT INTO logs (message) VALUES ('#{msg}')")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches find_by_sql with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")|,
        ~S|Post.find_by_sql("SELECT posts.* FROM posts WHERE title LIKE '%#{search}%'")|,
        ~S|Model.find_by_sql("SELECT * FROM table WHERE status = #{status}")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches where clause with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.where("name = '#{params[:name]}'")|,
        ~S|Post.where("title = '#{title}' AND status = #{status}")|,
        ~S|Model.where("id IN (#{id_list})")|,
        ~S|User.where("created_at > '#{date}'")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches joins with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.joins("LEFT JOIN posts ON posts.user_id = #{user_id}")|,
        ~S|Post.joins("INNER JOIN users ON users.id = #{user_id}")|,
        ~S|Model.joins("JOIN table2 ON table2.name = '#{name}'")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches order clause with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.order("#{params[:sort_column]} #{params[:direction]}")|,
        ~S|Post.order("created_at #{direction}")|,
        ~S|Model.order("#{column} DESC")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches group clause with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.group("#{column}")|,
        ~S|Post.group("DATE(created_at) #{grouping}")|,
        ~S|Model.group("category_#{type}")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches having clause with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.having("COUNT(*) > #{min_count}")|,
        ~S|Post.having("SUM(views) = #{total}")|,
        ~S|Model.having("AVG(score) > #{threshold}")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe ActiveRecord patterns", %{pattern: pattern} do
      safe_code = [
        ~S|User.where(name: params[:name])|,
        ~S|User.where("name = ?", params[:name])|,
        ~S|User.find_by(name: params[:name])|,
        ~S|User.where(id: [1, 2, 3])|,
        ~S|User.joins(:posts)|,
        ~S|User.order(:created_at)|,
        ~S|User.group(:category)|,
        ~S|User.having("COUNT(*) > ?", 5)|,
        ~S|puts "Searching for #{params[:name]}"|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert metadata.description =~ "SQL injection"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes real-world incident references" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "CVE-2023-22794" || impact =~ "Rails" || impact =~ "ActiveRecord"
    end
    
    test "includes proper references" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
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
    
    test "includes SQL-specific AST rules" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "where" in enhancement.ast_rules.method_names
    end
    
    test "has proper context detection" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert is_map(enhancement.context_rules)
      assert is_list(enhancement.context_rules.exclude_paths)
      assert is_list(enhancement.context_rules.safe_patterns)
    end
  end
end