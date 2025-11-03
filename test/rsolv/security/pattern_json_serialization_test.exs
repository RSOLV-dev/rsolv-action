defmodule Rsolv.Security.PatternJsonSerializationTest do
  use ExUnit.Case

  describe "JSON encoding with regex - TDD Red Phase" do
    test "Jason fails to encode regex objects" do
      # This test demonstrates the current failure
      regex = ~r/test_pattern/

      assert_raise Protocol.UndefinedError, ~r/Jason.Encoder not implemented for/, fn ->
        JSON.encode!(regex)
      end
    end

    test "Jason fails to encode pattern maps with regex" do
      pattern = %{
        id: "sql_injection",
        pattern: ~r/SELECT.*FROM.*WHERE/i,
        severity: :high
      }

      assert_raise Protocol.UndefinedError, fn ->
        JSON.encode!(pattern)
      end
    end

    test "real pattern example that currently fails" do
      # This is based on the actual sql_injection_concat pattern
      pattern = %{
        id: "sql_injection_concat",
        type: :sql_injection,
        pattern: ~r/\.(query|execute|exec|run|all|get)/,
        flags: [],
        severity: :high
      }

      assert_raise Protocol.UndefinedError, fn ->
        JSON.encode!(pattern)
      end
    end
  end

  describe "Proposed solution - prepare_for_json/1" do
    test "prepare_for_json/1 should convert regex to serializable map" do
      # This will fail until we implement the function
      regex = ~r/test_pattern/i

      # The function we need to implement
      result = Rsolv.Security.Patterns.JSONSerializer.prepare_for_json(regex)

      assert result == %{
               "__type__" => "regex",
               "source" => "test_pattern",
               "flags" => ["i"]
             }
    end

    test "prepare_for_json/1 should handle nested structures" do
      pattern = %{
        id: "sql_injection",
        pattern: ~r/SELECT.*FROM/i,
        ast_rules: [
          %{type: "call", pattern: ~r/execute|query/}
        ]
      }

      result = Rsolv.Security.Patterns.JSONSerializer.prepare_for_json(pattern)

      assert result == %{
               id: "sql_injection",
               pattern: %{
                 "__type__" => "regex",
                 "source" => "SELECT.*FROM",
                 "flags" => ["i"]
               },
               ast_rules: [
                 %{
                   type: "call",
                   pattern: %{
                     "__type__" => "regex",
                     "source" => "execute|query",
                     "flags" => []
                   }
                 }
               ]
             }
    end
  end

  describe "Native JSON encoding" do
    test "native JSON.encode should work with prepared patterns" do
      # This test shows the target behavior with Elixir 1.18's JSON
      prepared = %{
        id: "test",
        pattern: %{
          "__type__" => "regex",
          "source" => "test",
          "flags" => []
        }
      }

      # Using native JSON encoder (available in Elixir 1.18+)
      json = JSON.encode!(prepared)
      assert is_binary(json)

      # Should decode properly
      decoded = JSON.decode!(json)
      assert decoded["pattern"]["__type__"] == "regex"
    end
  end
end
