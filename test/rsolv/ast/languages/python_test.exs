defmodule Rsolv.AST.Languages.PythonTest do
  use ExUnit.Case, async: true
  alias Rsolv.AST.Languages.Python

  describe "find_insertion_point/1" do
    test "finds insertion point after last test in test class" do
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "ClassDef",
            "name" => "TestFoo",
            "body" => [
              %{
                "type" => "FunctionDef",
                "name" => "test_bar",
                "_end_lineno" => 5
              }
            ]
          }
        ]
      }

      assert {:ok, %{line: 6, strategy: "after_last_test_function", parent: "test_class"}} =
               Python.find_insertion_point(ast)
    end

    test "finds insertion point for module-level test functions" do
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "FunctionDef",
            "name" => "test_something",
            "_end_lineno" => 3
          }
        ]
      }

      assert {:ok, %{line: 4, strategy: "after_last_test_function", parent: "module"}} =
               Python.find_insertion_point(ast)
    end

    test "returns error when no test class or function found" do
      ast = %{
        "type" => "Module",
        "body" => []
      }

      assert {:error, :no_test_container} = Python.find_insertion_point(ast)
    end

    test "handles test class with no tests yet" do
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "ClassDef",
            "name" => "TestEmpty",
            "body" => [],
            "_end_lineno" => 2
          }
        ]
      }

      assert {:ok, %{line: 1, strategy: "after_last_test_function", parent: "test_class"}} =
               Python.find_insertion_point(ast)
    end

    test "supports async test functions" do
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "AsyncFunctionDef",
            "name" => "test_async",
            "_end_lineno" => 5
          }
        ]
      }

      assert {:ok, %{line: 6, strategy: "after_last_test_function", parent: "module"}} =
               Python.find_insertion_point(ast)
    end
  end
end
