defmodule Rsolv.AST.Languages.RubyTest do
  use ExUnit.Case, async: true
  alias Rsolv.AST.Languages.Ruby

  describe "find_insertion_point/1" do
    test "finds insertion point after last test in Prism describe block" do
      ast = %{
        "type" => "program",
        "children" => [
          %{
            "type" => "statements",
            "children" => [
              %{
                "type" => "call",
                "children" => [
                  %{"type" => "constant_read"},
                  %{"type" => "arguments"},
                  %{
                    "type" => "block",
                    "children" => [
                      %{
                        "type" => "statements",
                        "children" => [
                          %{
                            "type" => "call",
                            "children" => [
                              %{"type" => "arguments"},
                              %{
                                "type" => "block",
                                "_end_lineno" => 5
                              }
                            ],
                            "_end_lineno" => 5
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            ]
          }
        ]
      }

      assert {:ok, %{line: 6, strategy: "after_last_it_block", parent: "describe_block"}} =
               Ruby.find_insertion_point(ast)
    end

    test "returns error when no describe block found" do
      ast = %{
        "type" => "program",
        "children" => [
          %{"type" => "statements", "children" => []}
        ]
      }

      assert {:error, :no_describe_block} = Ruby.find_insertion_point(ast)
    end

    test "handles describe block with no tests (inside_describe_block strategy)" do
      ast = %{
        "type" => "program",
        "children" => [
          %{
            "type" => "statements",
            "children" => [
              %{
                "type" => "call",
                "children" => [
                  %{"type" => "constant_read"},
                  %{"type" => "arguments"},
                  %{
                    "type" => "block",
                    "children" => [
                      %{
                        "type" => "statements",
                        "children" => []
                      }
                    ],
                    "_end_lineno" => 10
                  }
                ],
                "_end_lineno" => 10
              }
            ]
          }
        ]
      }

      assert {:ok, %{line: 9, strategy: "inside_describe_block", parent: "describe_block"}} =
               Ruby.find_insertion_point(ast)
    end

    test "handles old parser-prism format with block nodes" do
      ast = %{
        "type" => "begin",
        "children" => [
          %{
            "type" => "block",
            "children" => [
              %{
                "type" => "send",
                "children" => [nil, "describe", %{"type" => "str"}]
              },
              %{"type" => "args"},
              %{
                "type" => "begin",
                "children" => [
                  %{
                    "type" => "block",
                    "children" => [
                      %{
                        "type" => "send",
                        "children" => [nil, "it", %{"type" => "str"}]
                      },
                      %{"type" => "args"},
                      %{"type" => "send", "_end_lineno" => 8}
                    ],
                    "_end_lineno" => 8
                  }
                ]
              }
            ]
          }
        ]
      }

      assert {:ok, %{line: 9, strategy: "after_last_it_block", parent: "describe_block"}} =
               Ruby.find_insertion_point(ast)
    end
  end
end
