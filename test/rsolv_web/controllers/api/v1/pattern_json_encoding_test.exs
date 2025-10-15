defmodule RsolvWeb.Api.V1.PatternJsonEncodingTest do
  use RsolvWeb.ConnCase

  describe "JSON encoding for patterns with regex" do
    test "fails to encode patterns with regex using Jason (current behavior)", %{conn: conn} do
      # This test demonstrates the current failure when trying to encode
      # patterns that contain Elixir regex objects

      # Create a pattern with a regex
      pattern_with_regex = %{
        id: "sql_injection_concat",
        type: :sql_injection,
        description: "SQL injection via string concatenation",
        pattern: ~r/\.(query|execute|exec|run|all|get)/,
        severity: :high,
        confidence: 90
      }

      # Attempt to encode with JSON should fail
      assert_raise Protocol.UndefinedError, fn ->
        JSON.encode!(pattern_with_regex)
      end
    end

    test "demonstrates regex cannot be encoded by JSON", %{conn: _conn} do
      # Simple test showing regex encoding failure
      regex = ~r/test_pattern/

      # This should raise an error
      assert_raise Protocol.UndefinedError, fn ->
        JSON.encode!(%{pattern: regex})
      end
    end

    test "shows current enhanced format succeeds with JSONSerializer", %{conn: conn} do
      # When requesting enhanced format, the API uses JSONSerializer
      # which properly handles regex objects

      conn = get(conn, "/api/v1/patterns?language=elixir&format=enhanced")

      # Should return 200 with properly serialized patterns
      response = json_response(conn, 200)
      assert response["metadata"]["format"] == "enhanced"
      assert response["metadata"]["enhanced"] == true
      assert is_list(response["patterns"])
    end
  end

  describe "Proposed JSON encoding solution" do
    test "prepare_for_json/1 should convert regex to serializable format" do
      # This test will initially fail until we implement prepare_for_json/1

      pattern_with_regex = %{
        id: "sql_injection_concat",
        pattern: ~r/\.(query|execute|exec|run|all|get)/,
        flags: [:unicode]
      }

      # This function doesn't exist yet - TDD red phase
      prepared = Rsolv.Security.Patterns.JSONSerializer.prepare_for_json(pattern_with_regex)

      # Should convert regex to a map representation
      assert prepared == %{
               id: "sql_injection_concat",
               pattern: %{
                 "__type__" => "regex",
                 "source" => "\\.(query|execute|exec|run|all|get)",
                 # The regex itself doesn't have unicode flag
                 "flags" => []
               },
               # This is a separate field
               flags: [:unicode]
             }
    end

    test "native JSON.encode! should work with prepared patterns" do
      # This test demonstrates the desired behavior after migration

      prepared_pattern = %{
        id: "sql_injection_concat",
        pattern: %{
          "__type__" => "regex",
          "source" => "\\.(query|execute|exec|run|all|get)",
          "flags" => []
        }
      }

      # Native JSON encoding should work
      json = JSON.encode!(prepared_pattern)
      assert is_binary(json)

      # Should be able to decode back
      decoded = JSON.decode!(json)
      assert decoded["pattern"]["__type__"] == "regex"
      assert decoded["pattern"]["source"] == "\\.(query|execute|exec|run|all|get)"
    end
  end

  describe "End-to-end enhanced format with JSON" do
    test "enhanced format should return successfully after JSON migration", %{conn: conn} do
      # This is our target behavior - currently will fail

      conn = get(conn, "/api/v1/patterns?language=elixir&format=enhanced")

      # Should return 200 with properly encoded patterns
      assert %{
               "patterns" => patterns,
               "metadata" => %{
                 "format" => "enhanced",
                 "enhanced" => true
               }
             } = json_response(conn, 200)

      # Patterns should have regex objects properly serialized
      first_pattern = List.first(patterns)

      # If pattern has a regex, it should be serialized as a map
      if Map.has_key?(first_pattern, "pattern") && is_map(first_pattern["pattern"]) do
        assert first_pattern["pattern"]["__type__"] == "regex"
        assert is_binary(first_pattern["pattern"]["source"])
      end
    end
  end
end
