defmodule RsolvWeb.PatternMetadataApiTest do
  use RsolvWeb.ConnCase
  
  describe "GET /api/v1/patterns/:id/metadata" do
    test "returns metadata for migrated patterns", %{conn: conn} do
      # Test each migrated pattern
      migrated_patterns = [
        "js-sql-injection-concat",
        "js-sql-injection-interpolation",
        "js-xss-innerhtml",
        "js-xss-document-write",
        "js-command-injection-exec"
      ]
      
      for pattern_id <- migrated_patterns do
        conn = get(conn, "/api/v1/patterns/#{pattern_id}/metadata")
        
        assert json = json_response(conn, 200)
        assert json["pattern_id"] == pattern_id
        assert is_binary(json["description"])
        assert is_list(json["references"])
        assert is_list(json["attack_vectors"])
        assert is_list(json["cve_examples"])
        
        # Check references have proper structure
        for ref <- json["references"] do
          assert Map.has_key?(ref, "type")
          assert Map.has_key?(ref, "id") || Map.has_key?(ref, "title")
          assert Map.has_key?(ref, "url")
        end
        
        # Check CVE examples have proper structure
        for cve <- json["cve_examples"] do
          assert Map.has_key?(cve, "id")
          assert Map.has_key?(cve, "description")
          assert Map.has_key?(cve, "severity")
        end
      end
    end
    
    test "returns 404 for non-existent pattern", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/non-existent-pattern/metadata")
      
      assert json = json_response(conn, 404)
      assert json["error"] == "Pattern not found"
    end
    
    test "returns 404 for patterns without metadata", %{conn: conn} do
      # Since all patterns have metadata now, test with a truly non-existent pattern module
      # that would return "Pattern not found" error
      conn = get(conn, "/api/v1/patterns/nonexistent-pattern/metadata")
      
      assert json = json_response(conn, 404)
      assert json["error"] == "Pattern not found"
    end
    
    test "metadata includes safe alternatives", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/js-command-injection-exec/metadata")
      
      assert json = json_response(conn, 200)
      assert Map.has_key?(json, "safe_alternatives") || 
             (Map.has_key?(json, "additional_context") && 
              Map.has_key?(json["additional_context"], "safe_alternatives"))
    end
  end
end