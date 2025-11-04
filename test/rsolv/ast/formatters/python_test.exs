defmodule Rsolv.AST.Formatters.PythonTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false
  alias Rsolv.AST.Formatters.Python

  describe "format_tests/2" do
    test "formats tests with TestSecurity class wrapper when parent is module" do
      red_tests = [
        %{
          "testName" => "prevents SQL injection",
          "testCode" => "assert result is None",
          "attackVector" => "'; DROP TABLE users;--"
        }
      ]

      insertion_point = %{parent: "module"}
      result = Python.format_tests(red_tests, insertion_point)

      assert result =~ "class TestSecurity:"
      assert result =~ "def test_prevents_sql_injection(self):"
      assert result =~ "assert result is None"
      assert result =~ "Attack vector: '; DROP TABLE users;--"
    end

    test "does not wrap in class when parent is test_class" do
      red_tests = [
        %{
          "testName" => "prevents XSS",
          "testCode" => "assert '<script>' not in result",
          "attackVector" => "<script>alert('XSS')</script>"
        }
      ]

      insertion_point = %{parent: "test_class"}
      result = Python.format_tests(red_tests, insertion_point)

      refute result =~ "class TestSecurity:"
      assert result =~ "def test_prevents_xss(self):"
      assert result =~ "assert '<script>' not in result"
    end

    test "handles complete function definitions without wrapping" do
      red_tests = [
        %{
          "testName" => "complete test",
          "testCode" => "def test_something(self):\n    assert True",
          "attackVector" => "n/a"
        }
      ]

      insertion_point = %{parent: "test_class"}
      result = Python.format_tests(red_tests, insertion_point)

      assert result =~ "def test_something(self):"
      assert result =~ "Attack vector: n/a"
    end

    test "formats multiple tests" do
      red_tests = [
        %{
          "testName" => "test 1",
          "testCode" => "assert 1 == 1",
          "attackVector" => "vector1"
        },
        %{
          "testName" => "test 2",
          "testCode" => "assert 2 == 2",
          "attackVector" => "vector2"
        }
      ]

      insertion_point = %{parent: "test_class"}
      result = Python.format_tests(red_tests, insertion_point)

      assert result =~ "test_1"
      assert result =~ "test_2"
      assert result =~ "vector1"
      assert result =~ "vector2"
    end

    test "sanitizes function names properly" do
      red_tests = [
        %{
          "testName" => "Test With Spaces & Special!!! Chars",
          "testCode" => "assert True",
          "attackVector" => "test"
        }
      ]

      insertion_point = %{parent: "test_class"}
      result = Python.format_tests(red_tests, insertion_point)

      assert result =~ "def test_test_with_spaces_special_chars(self):"
    end

    test "properly indents test code with 4 spaces" do
      red_tests = [
        %{
          "testName" => "test",
          "testCode" => "x = 1\nassert x == 1",
          "attackVector" => "test"
        }
      ]

      insertion_point = %{parent: "test_class"}
      result = Python.format_tests(red_tests, insertion_point)

      assert result =~ "    x = 1"
      assert result =~ "    assert x == 1"
    end
  end
end
