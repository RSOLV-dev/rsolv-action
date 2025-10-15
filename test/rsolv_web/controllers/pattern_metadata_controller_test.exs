defmodule RsolvWeb.PatternMetadataControllerTest do
  use RsolvWeb.ConnCase

  describe "GET /api/v1/patterns/:id/metadata" do
    test "returns vulnerability metadata for a specific pattern", %{conn: conn} do
      # Test with our SQL injection pattern
      conn = get(conn, "/api/v1/patterns/js-sql-injection-concat/metadata")

      assert json = json_response(conn, 200)
      assert json["pattern_id"] == "js-sql-injection-concat"
      assert json["description"] =~ "SQL injection"

      # Check references structure
      assert is_list(json["references"])
      assert length(json["references"]) > 0
      [first_ref | _] = json["references"]
      assert first_ref["type"] == "cwe"
      assert first_ref["id"] == "CWE-89"
      assert first_ref["url"] =~ "cwe.mitre.org"

      # Check attack vectors
      assert is_list(json["attack_vectors"])
      assert "Direct concatenation of user input into SQL queries" in json["attack_vectors"]

      # Check CVE examples
      assert is_list(json["cve_examples"])
    end

    test "returns 404 for non-existent pattern", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/non-existent-pattern/metadata")
      assert json_response(conn, 404)
    end

    test "metadata endpoint returns 404 for non-migrated patterns", %{conn: conn} do
      # Patterns that haven't been migrated to the new structure should return 404
      # Once we add authentication requirements, we can update this test
      conn = get(conn, "/api/v1/patterns/js-xss-dom/metadata")
      assert json_response(conn, 404) == %{"error" => "Pattern not found"}
    end
  end

  describe "GET /api/v1/patterns with include_metadata query param" do
    test "excludes metadata by default", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/by-language/javascript")
      json = json_response(conn, 200)

      # Should have patterns but no metadata
      assert json["count"] > 0
      [first_pattern | _] = json["patterns"]
      refute Map.has_key?(first_pattern, "vulnerability_metadata")
    end

    test "includes metadata when requested", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/by-language/javascript?include_metadata=true")
      json = json_response(conn, 200)

      # Should have patterns with metadata
      assert json["count"] > 0
      [first_pattern | _] = json["patterns"]
      assert Map.has_key?(first_pattern, "vulnerability_metadata")
      assert first_pattern["vulnerability_metadata"]["description"] != nil
    end
  end
end
