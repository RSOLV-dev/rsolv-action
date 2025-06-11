defmodule RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-interpolation"
      assert pattern.name == "SQL Injection via String Interpolation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
    end
    
    test "pattern detects vulnerable template literal SQL queries" do
      pattern = SqlInjectionInterpolation.pattern()
      
      vulnerable_cases = [
        ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|,
        ~S|db.query(`DELETE FROM posts WHERE id = ${postId}`)|,
        ~S|const sql = `UPDATE users SET email = '${email}' WHERE id = ${id}`|,
        ~S|`INSERT INTO logs (message, user) VALUES ('${msg}', '${user}')`|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe parameterized queries" do
      pattern = SqlInjectionInterpolation.pattern()
      
      safe_cases = [
        ~S|db.query("SELECT * FROM users WHERE name = ?", [userName])|,
        ~S|const query = db.prepare("DELETE FROM posts WHERE id = ?")|,
        ~S|await db.execute("UPDATE users SET email = ? WHERE id = ?", [email, id])|,
        ~S|const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId])|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code), 
          "Incorrectly matched safe code: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.cve_examples)
      
      # Check references include important sources
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
    end
    
    test "metadata includes template literal specific information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()
      
      # Should specifically mention template literals
      assert metadata.description =~ "template literal"
      
      # Should have attack vectors specific to template literals
      attack_vector_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_vector_text =~ "template" || attack_vector_text =~ "${" 
    end
  end
  
  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert SqlInjectionInterpolation.applies_to_file?("app.js")
      assert SqlInjectionInterpolation.applies_to_file?("index.ts")
      assert SqlInjectionInterpolation.applies_to_file?("src/database.jsx")
      assert SqlInjectionInterpolation.applies_to_file?("components/User.tsx")
    end
    
    test "does not apply to non-JavaScript files" do
      refute SqlInjectionInterpolation.applies_to_file?("app.py")
      refute SqlInjectionInterpolation.applies_to_file?("index.rb")
      refute SqlInjectionInterpolation.applies_to_file?("config.json")
    end
  end
end