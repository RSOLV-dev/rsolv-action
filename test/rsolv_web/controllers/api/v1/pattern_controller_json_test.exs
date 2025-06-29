defmodule RSOLVWeb.Api.V1.PatternControllerJsonTest do
  use RSOLVWeb.ConnCase
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  describe "Pattern API with native JSON" do
    test "standard format works with native JSON", %{conn: conn} do
      # This test should work because standard format doesn't have regex
      conn = get(conn, "/api/v1/patterns?language=javascript&format=standard")
      
      assert %{
        "patterns" => patterns,
        "metadata" => metadata
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      assert metadata["format"] == "standard"
    end
    
    test "enhanced format needs JSONSerializer for regex handling", %{conn: conn} do
      # Currently this will fail because enhanced format has regex objects
      # We need to integrate JSONSerializer into the pattern formatting
      
      # This test demonstrates the current failure
      assert_raise RuntimeError, fn ->
        get(conn, "/api/v1/patterns?language=javascript&format=enhanced")
      end
    end
    
    test "JSONSerializer can handle pattern with regex", %{conn: _conn} do
      # Test that our JSONSerializer works for patterns
      pattern = %{
        id: "test",
        pattern: ~r/SELECT.*FROM/i,
        ast_rules: [
          %{type: "call", pattern: ~r/query|execute/}
        ]
      }
      
      # Should be able to encode
      json = JSONSerializer.encode!(pattern)
      assert is_binary(json)
      
      # Should be able to decode
      {:ok, decoded} = JSON.decode(json)
      assert decoded["pattern"]["__type__"] == "regex"
      assert decoded["pattern"]["source"] == "SELECT.*FROM"
      assert decoded["pattern"]["flags"] == ["i"]
    end
  end
end