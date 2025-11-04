defmodule Rsolv.AST.Languages.JavaScriptTest do
  use ExUnit.Case, async: false  # Changed: parser pool is singleton, must run sequentially
  alias Rsolv.AST.Languages.JavaScript

  describe "find_insertion_point/2" do
    test "finds insertion point after last test in describe block" do
      ast = %{
        "type" => "File",
        "program" => %{
          "type" => "Program",
          "body" => [
            %{
              "type" => "ExpressionStatement",
              "expression" => %{
                "type" => "CallExpression",
                "callee" => %{"type" => "Identifier", "name" => "describe"},
                "arguments" => [
                  %{"type" => "Literal", "value" => "Test Suite"},
                  %{
                    "type" => "ArrowFunctionExpression",
                    "body" => %{
                      "type" => "BlockStatement",
                      "body" => [
                        %{
                          "type" => "ExpressionStatement",
                          "expression" => %{
                            "type" => "CallExpression",
                            "callee" => %{"type" => "Identifier", "name" => "it"},
                            "loc" => %{"end" => %{"line" => 5}}
                          }
                        }
                      ]
                    }
                  }
                ]
              }
            }
          ]
        }
      }

      assert {:ok, %{line: 6, strategy: "after_last_it_block", parent: "describe_block"}} =
               JavaScript.find_insertion_point(ast, "vitest")
    end

    test "returns error when no describe block found" do
      ast = %{
        "type" => "File",
        "program" => %{
          "type" => "Program",
          "body" => []
        }
      }

      assert {:error, :no_describe_block} = JavaScript.find_insertion_point(ast, "jest")
    end

    test "handles describe block with no tests" do
      ast = %{
        "type" => "File",
        "program" => %{
          "type" => "Program",
          "body" => [
            %{
              "type" => "ExpressionStatement",
              "expression" => %{
                "type" => "CallExpression",
                "callee" => %{"type" => "Identifier", "name" => "describe"},
                "arguments" => [
                  %{"type" => "Literal", "value" => "Empty Suite"},
                  %{
                    "type" => "ArrowFunctionExpression",
                    "body" => %{
                      "type" => "BlockStatement",
                      "body" => [],
                      "loc" => %{"end" => %{"line" => 10}}
                    }
                  }
                ],
                "loc" => %{"end" => %{"line" => 10}}
              }
            }
          ]
        }
      }

      assert {:ok, %{line: 9, strategy: "inside_describe_block", parent: "describe_block"}} =
               JavaScript.find_insertion_point(ast, "mocha")
    end

    test "supports all JS frameworks" do
      simple_ast = %{
        "type" => "File",
        "program" => %{"type" => "Program", "body" => []}
      }

      for framework <- ["vitest", "jest", "mocha"] do
        assert {:error, :no_describe_block} =
                 JavaScript.find_insertion_point(simple_ast, framework)
      end
    end
  end
end
