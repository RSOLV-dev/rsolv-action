defmodule Rsolv.AST.MockParsers do
  @moduledoc """
  Mock parsers for testing without external dependencies.
  Returns pre-defined AST structures for known test cases.
  """
  
  def python_ast(:simple) do
    %{
      "_type" => "Module",
      "_fields" => %{
        "body" => [
          %{
            "_type" => "FunctionDef",
            "_fields" => %{
              "name" => "hello",
              "args" => %{
                "_type" => "arguments",
                "_fields" => %{
                  "args" => []
                }
              },
              "body" => [
                %{
                  "_type" => "Return",
                  "_fields" => %{
                    "value" => %{
                      "_type" => "Constant",
                      "_fields" => %{
                        "value" => "Hello, World!"
                      }
                    }
                  }
                }
              ]
            },
            "_lineno" => 1,
            "_col_offset" => 0
          }
        ]
      }
    }
  end
  
  def python_ast(:sql_injection_vulnerable) do
    %{
      "_type" => "Module",
      "_fields" => %{
        "body" => [
          %{
            "_type" => "Import",
            "_fields" => %{
              "names" => [%{"_type" => "alias", "_fields" => %{"name" => "sqlite3"}}]
            }
          },
          %{
            "_type" => "FunctionDef",
            "_fields" => %{
              "name" => "get_user",
              "body" => [
                %{
                  "_type" => "Assign",
                  "_fields" => %{
                    "targets" => [%{"_type" => "Name", "_fields" => %{"id" => "query"}}],
                    "value" => %{
                      "_type" => "JoinedStr",
                      "_lineno" => 6,
                      "_fields" => %{
                        "values" => [
                          %{"_type" => "Constant", "_fields" => %{"value" => "SELECT * FROM users WHERE id = "}},
                          %{"_type" => "FormattedValue", "_fields" => %{
                            "value" => %{"_type" => "Name", "_fields" => %{"id" => "user_id"}}
                          }}
                        ]
                      }
                    }
                  }
                },
                %{
                  "_type" => "Expr",
                  "_fields" => %{
                    "value" => %{
                      "_type" => "Call",
                      "_fields" => %{
                        "func" => %{
                          "_type" => "Attribute",
                          "_fields" => %{
                            "value" => %{"_type" => "Name", "_fields" => %{"id" => "conn"}},
                            "attr" => "execute"
                          }
                        },
                        "args" => [%{"_type" => "Name", "_fields" => %{"id" => "query"}}]
                      }
                    }
                  }
                }
              ]
            }
          }
        ]
      }
    }
  end
  
  def python_ast(:command_injection_vulnerable) do
    %{
      "_type" => "Module",
      "_fields" => %{
        "body" => [
          %{
            "_type" => "Import",
            "_fields" => %{
              "names" => [%{"_type" => "alias", "_fields" => %{"name" => "os"}}]
            }
          },
          %{
            "_type" => "FunctionDef",
            "_fields" => %{
              "name" => "process_file",
              "body" => [
                %{
                  "_type" => "Expr",
                  "_lineno" => 5,
                  "_fields" => %{
                    "value" => %{
                      "_type" => "Call",
                      "_fields" => %{
                        "func" => %{
                          "_type" => "Attribute",
                          "_fields" => %{
                            "value" => %{"_type" => "Name", "_fields" => %{"id" => "os"}},
                            "attr" => "system"
                          }
                        },
                        "args" => [
                          %{
                            "_type" => "JoinedStr",
                            "_fields" => %{
                              "values" => [
                                %{"_type" => "Constant", "_fields" => %{"value" => "cat "}},
                                %{"_type" => "FormattedValue", "_fields" => %{
                                  "value" => %{"_type" => "Name", "_fields" => %{"id" => "filename"}}
                                }}
                              ]
                            }
                          }
                        ]
                      }
                    }
                  }
                }
              ]
            }
          }
        ]
      }
    }
  end
  
  def javascript_ast(:simple) do
    %{
      "type" => "Program",
      "body" => [
        %{
          "type" => "FunctionDeclaration",
          "id" => %{
            "type" => "Identifier",
            "name" => "hello"
          },
          "params" => [],
          "body" => %{
            "type" => "BlockStatement",
            "body" => [
              %{
                "type" => "ReturnStatement",
                "argument" => %{
                  "type" => "Literal",
                  "value" => "Hello, World!"
                }
              }
            ]
          }
        }
      ]
    }
  end
  
  def javascript_ast(:sql_injection_vulnerable) do
    %{
      "type" => "Program",
      "body" => [
        %{
          "type" => "VariableDeclaration",
          "declarations" => [
            %{
              "type" => "VariableDeclarator",
              "id" => %{"type" => "Identifier", "name" => "mysql"},
              "init" => %{
                "type" => "CallExpression",
                "callee" => %{"type" => "Identifier", "name" => "require"},
                "arguments" => [%{"type" => "Literal", "value" => "mysql"}]
              }
            }
          ]
        },
        %{
          "type" => "FunctionDeclaration",
          "id" => %{"type" => "Identifier", "name" => "getUser"},
          "body" => %{
            "type" => "BlockStatement",
            "body" => [
              %{
                "type" => "VariableDeclaration",
                "declarations" => [
                  %{
                    "type" => "VariableDeclarator",
                    "id" => %{"type" => "Identifier", "name" => "query"},
                    "init" => %{
                      "type" => "TemplateLiteral",
                      "expressions" => [
                        %{"type" => "Identifier", "name" => "userId"}
                      ],
                      "quasis" => [
                        %{"value" => %{"raw" => "SELECT * FROM users WHERE id = "}},
                        %{"value" => %{"raw" => ""}}
                      ]
                    }
                  }
                ]
              },
              %{
                "type" => "ReturnStatement",
                "argument" => %{
                  "type" => "CallExpression",
                  "callee" => %{
                    "type" => "MemberExpression",
                    "object" => %{"type" => "Identifier", "name" => "connection"},
                    "property" => %{"type" => "Identifier", "name" => "query"}
                  },
                  "arguments" => [%{"type" => "Identifier", "name" => "query"}]
                }
              }
            ]
          }
        }
      ]
    }
  end
  
  def ruby_ast(:simple) do
    %{
      type: :def,
      children: [
        :hello,
        %{type: :args, children: []},
        %{type: :str, children: ["Hello, World!"]}
      ]
    }
  end
  
  def php_ast(:simple) do
    %{
      "nodeType" => "Stmt_Function",
      "name" => %{"name" => "hello"},
      "stmts" => [
        %{
          "nodeType" => "Stmt_Return",
          "expr" => %{
            "nodeType" => "Scalar_String",
            "value" => "Hello, World!"
          }
        }
      ]
    }
  end
  
  def java_ast(:simple) do
    %{
      "type" => "CompilationUnit",
      "types" => [
        %{
          "type" => "ClassDeclaration",
          "name" => "Hello",
          "members" => [
            %{
              "type" => "MethodDeclaration",
              "name" => "hello",
              "modifiers" => ["public", "static"],
              "returnType" => "String",
              "body" => %{
                "type" => "BlockStmt",
                "statements" => [
                  %{
                    "type" => "ReturnStmt",
                    "expression" => %{
                      "type" => "StringLiteralExpr",
                      "value" => "Hello, World!"
                    }
                  }
                ]
              }
            }
          ]
        }
      ]
    }
  end
  
  def elixir_ast(:simple) do
    {:defmodule, [line: 1],
     [
       {:__aliases__, [line: 1], [:Hello]},
       [
         do: {:def, [line: 2],
          [
            {:hello, [line: 2], nil},
            [do: "Hello, World!"]
          ]}
       ]
     ]}
  end
end