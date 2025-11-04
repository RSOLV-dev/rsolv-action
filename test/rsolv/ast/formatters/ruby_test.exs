defmodule Rsolv.AST.Formatters.RubyTest do
  use ExUnit.Case, async: false  # Changed: parser pool is singleton, must run sequentially
  alias Rsolv.AST.Formatters.Ruby

  describe "format_tests/2" do
    test "formats tests with describe block wrapper" do
      red_tests = [
        %{
          "testName" => "prevents SQL injection",
          "testCode" => "expect(result).to be_nil",
          "attackVector" => "'; DROP TABLE users;--"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = Ruby.format_tests(red_tests, insertion_point)

      assert result =~ "describe 'security'"
      assert result =~ "prevents SQL injection"
      assert result =~ "expect(result).to be_nil"
      assert result =~ "Attack vector: '; DROP TABLE users;--"
    end

    test "handles complete test blocks without wrapping" do
      red_tests = [
        %{
          "testName" => "complete test",
          "testCode" => "it 'works' do\n  expect(true).to be true\nend",
          "attackVector" => "n/a"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = Ruby.format_tests(red_tests, insertion_point)

      assert result =~ "it 'works' do"
      refute result =~ "Attack vector"
    end

    test "formats multiple tests" do
      red_tests = [
        %{
          "testName" => "test 1",
          "testCode" => "expect(1).to eq(1)",
          "attackVector" => "vector1"
        },
        %{
          "testName" => "test 2",
          "testCode" => "expect(2).to eq(2)",
          "attackVector" => "vector2"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = Ruby.format_tests(red_tests, insertion_point)

      assert result =~ "test 1"
      assert result =~ "test 2"
      assert result =~ "vector1"
      assert result =~ "vector2"
    end

    test "properly indents test code" do
      red_tests = [
        %{
          "testName" => "test",
          "testCode" => "x = 1\nexpect(x).to eq(1)",
          "attackVector" => "test"
        }
      ]

      insertion_point = %{parent: "describe_block"}
      result = Ruby.format_tests(red_tests, insertion_point)

      assert result =~ "  x = 1"
      assert result =~ "  expect(x).to eq(1)"
    end
  end
end
