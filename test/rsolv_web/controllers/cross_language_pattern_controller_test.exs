defmodule RSOLVWeb.CrossLanguagePatternControllerTest do
  use RSOLVWeb.ConnCase, async: true

  describe "Cross-language pattern endpoints" do
    test "GET /api/v1/patterns/public returns all public patterns", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/public")
      
      assert %{
        "patterns" => patterns,
        "tier" => "public",
        "language" => "all",
        "count" => count
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      assert count > 0
      assert is_integer(count)
      assert length(patterns) == count
      
      # Should contain CVE patterns and other cross-language patterns
      pattern_types = Enum.map(patterns, & &1["type"])
      assert "cve" in pattern_types
    end

    test "GET /api/v1/patterns returns all patterns based on access level (public by default)", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns")
      
      # This endpoint uses legacy behavior when no parameters provided
      assert %{
        "patterns" => patterns,
        "metadata" => metadata
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      assert metadata["count"] > 0
      assert metadata["language"] == "javascript"  # Default language
      assert metadata["tier"] == "public"           # Default tier
      assert metadata["format"] == "standard"      # Default format
      
      # All patterns should have valid structure
      for pattern <- patterns do
        assert pattern["id"]
        assert pattern["name"]
        assert pattern["type"]
        assert pattern["severity"]
      end
    end

    test "GET /api/v1/patterns/protected returns error without auth", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/protected")
      
      assert %{"error" => "API key required"} = json_response(conn, 401)
    end

    test "GET /api/v1/patterns/ai returns error without auth", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/ai")
      
      assert %{"error" => "API key required"} = json_response(conn, 401)
    end

    test "GET /api/v1/patterns/enterprise returns error without auth", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/enterprise")
      
      assert %{"error" => "API key required"} = json_response(conn, 401)
    end

    test "cross-language patterns should include CVE patterns", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/public")
      response = json_response(conn, 200)
      
      cve_patterns = Enum.filter(response["patterns"], & &1["type"] == "cve")
      assert length(cve_patterns) > 0
      
      # Check for specific CVE patterns we know exist
      cve_ids = Enum.map(cve_patterns, & &1["id"])
      assert "log4shell-detection" in cve_ids
      assert "spring4shell-detection" in cve_ids
    end

    test "cross-language patterns should not duplicate patterns from language-specific endpoints", %{conn: conn} do
      # Get all patterns
      conn_all = get(conn, ~p"/api/v1/patterns/public")
      all_response = json_response(conn_all, 200)
      
      # Get JavaScript patterns
      conn_js = get(conn, ~p"/api/v1/patterns/public/javascript")
      js_response = json_response(conn_js, 200)
      
      # Count total patterns and JavaScript patterns
      all_count = all_response["count"]
      js_count = js_response["count"]
      
      # All patterns should include JavaScript patterns but have additional ones
      assert all_count > js_count
      
      # JavaScript patterns should be a subset of all patterns
      js_pattern_ids = MapSet.new(js_response["patterns"], & &1["id"])
      all_pattern_ids = MapSet.new(all_response["patterns"], & &1["id"])
      
      assert MapSet.subset?(js_pattern_ids, all_pattern_ids)
    end

    test "patterns should have consistent structure across endpoints", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/public")
      response = json_response(conn, 200)
      
      for pattern <- response["patterns"] do
        # Required fields
        assert pattern["id"]
        assert pattern["name"]
        assert pattern["description"]
        assert pattern["type"]
        assert pattern["severity"]
        assert pattern["recommendation"]
        
        # Optional but expected fields
        assert is_list(pattern["languages"])
        assert is_list(pattern["frameworks"])
        assert is_map(pattern["patterns"])
        assert is_list(pattern["patterns"]["regex"])
        assert is_map(pattern["testCases"])
        
        # Test cases should have vulnerable and safe examples
        assert is_list(pattern["testCases"]["vulnerable"])
        assert is_list(pattern["testCases"]["safe"])
      end
    end
  end
end