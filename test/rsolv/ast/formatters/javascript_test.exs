defmodule Rsolv.AST.Formatters.JavaScriptTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false
  alias Rsolv.AST.Formatters.JavaScript

  describe "format_tests/2" do
    test "formats tests with describe block wrapper" do
      red_tests = [
        %{
          "testName" => "prevents SQL injection",
          "testCode" => "expect(result).toBeNull();",
          "attackVector" => "'; DROP TABLE users;--"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = JavaScript.format_tests(red_tests, insertion_point)

      assert result =~ "describe('security'"
      assert result =~ "prevents SQL injection"
      assert result =~ "expect(result).toBeNull();"
      assert result =~ "Attack vector: '; DROP TABLE users;--"
    end

    test "handles complete test blocks without wrapping" do
      red_tests = [
        %{
          "testName" => "complete test",
          "testCode" => "it('works', () => { expect(true).toBe(true); });",
          "attackVector" => "n/a"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = JavaScript.format_tests(red_tests, insertion_point)

      assert result =~ "it('works', () => { expect(true).toBe(true); });"
      refute result =~ "Attack vector"
    end

    test "formats multiple tests" do
      red_tests = [
        %{
          "testName" => "test 1",
          "testCode" => "expect(1).toBe(1);",
          "attackVector" => "vector1"
        },
        %{
          "testName" => "test 2",
          "testCode" => "expect(2).toBe(2);",
          "attackVector" => "vector2"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = JavaScript.format_tests(red_tests, insertion_point)

      assert result =~ "test 1"
      assert result =~ "test 2"
      assert result =~ "vector1"
      assert result =~ "vector2"
    end

    test "properly indents test code" do
      red_tests = [
        %{
          "testName" => "test",
          "testCode" => "const x = 1;\nexpect(x).toBe(1);",
          "attackVector" => "test"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = JavaScript.format_tests(red_tests, insertion_point)

      assert result =~ "  const x = 1;"
      assert result =~ "  expect(x).toBe(1);"
    end
  end
end
