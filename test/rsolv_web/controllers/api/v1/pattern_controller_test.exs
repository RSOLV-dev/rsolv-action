defmodule RSOLVWeb.Api.V1.PatternControllerTest do
  use RSOLVWeb.ConnCase
  
  describe "GET /api/v1/patterns" do
    test "returns standard patterns by default", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns?language=javascript&tier=public")
      
      assert %{
        "patterns" => patterns,
        "metadata" => %{
          "language" => "javascript",
          "tier" => "public",
          "format" => "standard",
          "enhanced" => false
        }
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      assert length(patterns) > 0
    end
    
    test "returns enhanced patterns when format=enhanced", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns?language=javascript&tier=public&format=enhanced")
      
      assert %{
        "patterns" => patterns,
        "metadata" => %{
          "language" => "javascript",
          "tier" => "public",
          "format" => "enhanced",
          "enhanced" => true
        }
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      assert length(patterns) > 0
      
      # Check that patterns have AST enhancement fields
      first_pattern = List.first(patterns)
      assert Map.has_key?(first_pattern, "ast_rules")
      assert Map.has_key?(first_pattern, "context_rules")
      assert Map.has_key?(first_pattern, "min_confidence")
    end
    
    test "defaults to javascript and public tier", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns")
      
      assert %{
        "metadata" => %{
          "language" => "javascript",
          "tier" => "public",
          "format" => "standard"
        }
      } = json_response(conn, 200)
    end
    
    test "includes x-pattern-version header", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns")
      
      assert get_resp_header(conn, "x-pattern-version") == ["2.0"]
    end
    
    test "handles different languages", %{conn: conn} do
      for language <- ["javascript", "python", "ruby", "java", "elixir", "php"] do
        conn = get(conn, "/api/v1/patterns?language=#{language}")
        
        assert %{
          "patterns" => patterns,
          "metadata" => %{"language" => ^language}
        } = json_response(conn, 200)
        
        assert is_list(patterns)
      end
    end
    
    test "handles different tiers", %{conn: conn} do
      for tier <- ["public", "protected", "ai", "enterprise"] do
        conn = get(conn, "/api/v1/patterns?tier=#{tier}")
        
        assert %{
          "patterns" => patterns,
          "metadata" => %{"tier" => ^tier}
        } = json_response(conn, 200)
        
        assert is_list(patterns)
      end
    end
    
    test "public tier returns fewer patterns than enterprise", %{conn: conn} do
      conn_public = get(conn, "/api/v1/patterns?tier=public")
      %{"patterns" => public_patterns} = json_response(conn_public, 200)
      
      conn_enterprise = get(conn, "/api/v1/patterns?tier=enterprise")
      %{"patterns" => enterprise_patterns} = json_response(conn_enterprise, 200)
      
      assert length(public_patterns) < length(enterprise_patterns)
    end
  end
end