defmodule RSOLVWeb.PatternMigrationE2ETest do
  use RSOLVWeb.ConnCase
  
  @moduledoc """
  End-to-end test to verify the pattern migration approach is working as designed.
  
  Tests the complete flow for migrated patterns:
  1. Pattern detection via API
  2. Metadata retrieval
  3. Pattern module integration
  4. API response formatting
  """
  
  describe "End-to-End Pattern Migration Verification" do
    test "all migrated patterns are accessible via API", %{conn: conn} do
      # Get all JavaScript patterns to verify our migrated ones are included
      conn = get(conn, "/api/v1/patterns/javascript")
      assert json = json_response(conn, 200)
      
      pattern_ids = Enum.map(json["patterns"], & &1["id"])
      
      # Verify all 5 migrated patterns are present
      assert "js-sql-injection-concat" in pattern_ids
      assert "js-sql-injection-interpolation" in pattern_ids
      assert "js-xss-innerhtml" in pattern_ids
      assert "js-xss-document-write" in pattern_ids
      assert "js-command-injection-exec" in pattern_ids
    end
    
    test "migrated patterns have correct structure and fields", %{conn: conn} do
      # Test each migrated pattern
      migrated_patterns = [
        "js-sql-injection-concat",
        "js-sql-injection-interpolation", 
        "js-xss-innerhtml",
        "js-xss-document-write",
        "js-command-injection-exec"
      ]
      
      conn = get(conn, "/api/v1/patterns/javascript")
      json = json_response(conn, 200)
      patterns = json["patterns"]
      
      for pattern_id <- migrated_patterns do
        pattern = Enum.find(patterns, & &1["id"] == pattern_id)
        assert pattern, "Pattern #{pattern_id} not found"
        
        # Verify required fields
        assert pattern["name"]
        assert pattern["description"]
        assert pattern["type"]
        assert pattern["severity"]
        assert pattern["languages"]
        assert pattern["patterns"], "Pattern #{pattern_id} missing regex patterns"
        assert pattern["cwe_id"]
        assert pattern["owasp_category"]
        assert pattern["recommendation"]
      end
    end
    
    test "metadata endpoint works for all migrated patterns", %{conn: conn} do
      migrated_patterns = [
        {"js-sql-injection-concat", "SQL injection"},
        {"js-sql-injection-interpolation", "template literal"},
        {"js-xss-innerhtml", "innerHTML"},
        {"js-xss-document-write", "document.write"},
        {"js-command-injection-exec", "command injection"}
      ]
      
      for {pattern_id, expected_text} <- migrated_patterns do
        conn = get(conn, "/api/v1/patterns/#{pattern_id}/metadata")
        
        assert json = json_response(conn, 200)
        assert json["pattern_id"] == pattern_id
        assert json["description"] =~ expected_text
        
        # Verify metadata structure
        assert is_list(json["references"])
        assert length(json["references"]) > 0
        assert is_list(json["attack_vectors"])
        assert length(json["attack_vectors"]) > 0
        
        # Check CVE examples exist
        assert is_list(json["cve_examples"])
        assert Enum.all?(json["cve_examples"], fn cve ->
          cve["id"] && cve["description"] && cve["severity"]
        end)
      end
    end
    
    test "pattern detection works correctly with test cases", %{conn: conn} do
      # Get patterns to test regex functionality
      conn = get(conn, "/api/v1/patterns/javascript")
      patterns = json_response(conn, 200)["patterns"]
      
      test_cases = [
        {"js-sql-injection-concat", ~s(const query = "SELECT * FROM users WHERE id = " + userId), true},
        {"js-sql-injection-interpolation", ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|, true},
        {"js-xss-innerhtml", ~s(element.innerHTML = userInput), true},
        {"js-xss-document-write", ~S|document.write(userInput)|, true},
        {"js-command-injection-exec", ~S|exec("ls " + userInput)|, true}
      ]
      
      for {pattern_id, code, should_match} <- test_cases do
        pattern = Enum.find(patterns, & &1["id"] == pattern_id)
        assert pattern, "Pattern #{pattern_id} not found"
        
        # Get the regex pattern (it's in the "patterns" array)
        regex_strings = pattern["patterns"]
        assert is_list(regex_strings) && length(regex_strings) > 0
        
        # Convert the string back to regex and test
        regex_string = List.first(regex_strings)
        {:ok, regex} = Regex.compile(regex_string, "i")
        
        if should_match do
          assert Regex.match?(regex, code), 
            "Pattern #{pattern_id} failed to match: #{code}"
        else
          refute Regex.match?(regex, code),
            "Pattern #{pattern_id} incorrectly matched: #{code}"
        end
      end
    end
    
    test "metadata includes comprehensive vulnerability information", %{conn: conn} do
      # Test command injection metadata as example of comprehensive data
      conn = get(conn, "/api/v1/patterns/js-command-injection-exec/metadata")
      json = json_response(conn, 200)
      
      # Check description quality
      assert String.length(json["description"]) > 100
      assert json["description"] =~ "shell"
      assert json["description"] =~ "metacharacter"
      
      # Check references include multiple types
      ref_types = Enum.map(json["references"], & &1["type"])
      assert "cwe" in ref_types
      assert "owasp" in ref_types
      
      # Check attack vectors are detailed
      assert length(json["attack_vectors"]) >= 5
      attack_text = Enum.join(json["attack_vectors"], " ")
      assert attack_text =~ ";"  # Command separator
      assert attack_text =~ "|"  # Pipe
      assert attack_text =~ "$"  # Variable expansion
      
      # Check real world impact
      assert length(json["real_world_impact"]) >= 5
      impact_text = Enum.join(json["real_world_impact"], " ")
      assert impact_text =~ "remote code execution"
      
      # Check CVE examples have good data
      assert length(json["cve_examples"]) >= 3
      for cve <- json["cve_examples"] do
        assert cve["cvss"], "CVE #{cve["id"]} missing CVSS score"
        assert cve["note"] || cve["description"], "CVE #{cve["id"]} missing context"
      end
      
      # Check additional context exists
      assert json["additional_context"]
      assert json["additional_context"]["shell_differences"]
      assert json["additional_context"]["common_mistakes"]
    end
    
    test "pattern API supports include_metadata parameter", %{conn: conn} do
      # Test without metadata
      conn = get(conn, "/api/v1/patterns/javascript")
      json = json_response(conn, 200)
      pattern = Enum.find(json["patterns"], & &1["id"] == "js-command-injection-exec")
      refute Map.has_key?(pattern, "vulnerability_metadata")
      
      # Test with metadata
      conn = get(conn, "/api/v1/patterns/javascript?include_metadata=true")
      json = json_response(conn, 200)
      pattern = Enum.find(json["patterns"], & &1["id"] == "js-command-injection-exec")
      assert Map.has_key?(pattern, "vulnerability_metadata")
      assert pattern["vulnerability_metadata"]["pattern_id"] == "js-command-injection-exec"
    end
    
    test "non-migrated patterns return 404 for metadata", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/js-weak-crypto-md5/metadata")
      assert json_response(conn, 404)
    end
    
    test "pattern module file organization is correct" do
      # Verify files exist in expected locations
      base_path = "lib/rsolv_api/security/patterns/javascript"
      
      files = [
        "sql_injection_concat.ex",
        "sql_injection_interpolation.ex",
        "xss_innerhtml.ex",
        "xss_document_write.ex",
        "command_injection_exec.ex"
      ]
      
      for file <- files do
        path = Path.join(base_path, file)
        assert File.exists?(path), "Pattern file missing: #{path}"
      end
    end
  end
  
  describe "Pattern Quality Verification" do
    test "migrated patterns follow consistent structure", %{conn: conn} do
      modules = [
        RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat,
        RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation,
        RsolvApi.Security.Patterns.Javascript.XssInnerhtml,
        RsolvApi.Security.Patterns.Javascript.XssDocumentWrite,
        RsolvApi.Security.Patterns.Javascript.CommandInjectionExec
      ]
      
      for module <- modules do
        # Check required functions exist
        assert function_exported?(module, :pattern, 0)
        assert function_exported?(module, :vulnerability_metadata, 0)
        assert function_exported?(module, :applies_to_file?, 1)
        assert function_exported?(module, :applies_to_file?, 2)
        
        # Check pattern structure
        pattern = module.pattern()
        assert %RsolvApi.Security.Pattern{} = pattern
        assert pattern.id
        assert pattern.test_cases.vulnerable
        assert pattern.test_cases.safe
        
        # Check metadata structure
        metadata = module.vulnerability_metadata()
        assert metadata.description
        assert metadata.references
        assert metadata.attack_vectors
        assert metadata.safe_alternatives
      end
    end
  end
end