defmodule Rsolv.AST.ASTPatternMatcherTest do
  use ExUnit.Case, async: true

  alias Rsolv.AST.ASTPatternMatcher

  describe "match/3" do
    test "detects SQL injection in Python string interpolation" do
      # Python AST for: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "Expr",
            "value" => %{
              "type" => "Call",
              "func" => %{
                "type" => "Attribute",
                "value" => %{"type" => "Name", "id" => "cursor"},
                "attr" => "execute"
              },
              "args" => [
                %{
                  "type" => "JoinedStr",
                  "values" => [
                    %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
                    %{
                      "type" => "FormattedValue",
                      "value" => %{"type" => "Name", "id" => "user_id"}
                    }
                  ]
                }
              ]
            }
          }
        ]
      }

      pattern = %{
        id: "python-sql-injection",
        name: "SQL Injection via String Interpolation",
        ast_pattern: %{
          type: "Call",
          func: %{
            type: "Attribute",
            attr: ~r/^(execute|executemany|executescript)$/
          },
          args: [
            %{
              type: "JoinedStr",
              values: {:contains, %{type: "FormattedValue"}}
            }
          ]
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "python")

      assert length(matches) == 1
      assert hd(matches).pattern_id == "python-sql-injection"
      assert hd(matches).confidence > 0.8
    end

    test "does NOT detect SQL injection when using parameterized queries" do
      # Python AST for: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "Expr",
            "value" => %{
              "type" => "Call",
              "func" => %{
                "type" => "Attribute",
                "value" => %{"type" => "Name", "id" => "cursor"},
                "attr" => "execute"
              },
              "args" => [
                %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = ?"},
                %{
                  "type" => "Tuple",
                  "elts" => [%{"type" => "Name", "id" => "user_id"}]
                }
              ]
            }
          }
        ]
      }

      pattern = %{
        id: "python-sql-injection",
        name: "SQL Injection via String Interpolation",
        ast_pattern: %{
          type: "Call",
          func: %{
            type: "Attribute",
            attr: ~r/^(execute|executemany|executescript)$/
          },
          args: [
            %{
              type: "JoinedStr",
              values: {:contains, %{type: "FormattedValue"}}
            }
          ]
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "python")

      assert length(matches) == 0
    end

    test "detects XSS in Ruby ERB template" do
      # Ruby AST for: <%= user_input %>
      ast = %{
        "type" => "erb",
        "children" => [
          %{
            "type" => "output",
            "escape" => false,
            "value" => %{
              "type" => "send",
              "receiver" => nil,
              "method" => "user_input",
              "arguments" => []
            }
          }
        ]
      }

      pattern = %{
        id: "ruby-xss-erb",
        name: "XSS via Unescaped ERB Output",
        ast_pattern: %{
          type: "output",
          escape: false,
          value: %{
            type: "send",
            method: ~r/^(params|user_|input|request)/
          }
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "ruby")

      assert length(matches) == 1
      assert hd(matches).pattern_id == "ruby-xss-erb"
    end

    test "detects hardcoded secrets in JavaScript" do
      # JavaScript AST for: const apiKey = "sk-1234567890abcdef"
      ast = %{
        "type" => "Program",
        "body" => [
          %{
            "type" => "VariableDeclaration",
            "declarations" => [
              %{
                "type" => "VariableDeclarator",
                "id" => %{"type" => "Identifier", "name" => "apiKey"},
                "init" => %{
                  "type" => "Literal",
                  "value" => "sk-1234567890abcdef",
                  "raw" => "\"sk-1234567890abcdef\""
                }
              }
            ]
          }
        ]
      }

      pattern = %{
        id: "js-hardcoded-secret",
        name: "Hardcoded Secret Key",
        ast_pattern: %{
          type: "VariableDeclarator",
          id: %{
            type: "Identifier",
            name: ~r/(api_?key|secret|token|password)/i
          },
          init: %{
            type: "Literal",
            value: ~r/^(sk-|pk-|Bearer |[A-Za-z0-9]{32,})/
          }
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "javascript")

      assert length(matches) == 1
      assert hd(matches).pattern_id == "js-hardcoded-secret"
      assert hd(matches).severity == "high"
    end

    test "handles nested AST traversal" do
      # Deeply nested AST structure
      ast = %{
        "type" => "Program",
        "body" => [
          %{
            "type" => "FunctionDeclaration",
            "body" => %{
              "type" => "BlockStatement",
              "body" => [
                %{
                  "type" => "IfStatement",
                  "consequent" => %{
                    "type" => "BlockStatement",
                    "body" => [
                      %{
                        "type" => "ExpressionStatement",
                        "expression" => %{
                          "type" => "CallExpression",
                          "callee" => %{"type" => "Identifier", "name" => "eval"},
                          "arguments" => [
                            %{"type" => "Identifier", "name" => "userInput"}
                          ]
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

      pattern = %{
        id: "js-eval-injection",
        name: "Eval Injection",
        ast_pattern: %{
          type: "CallExpression",
          callee: %{
            type: "Identifier",
            name: "eval"
          },
          arguments: {:contains, %{type: "Identifier"}}
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "javascript")

      assert length(matches) == 1
      # Nested 6 levels deep (CallExpression is at 6)
      assert hd(matches).location.depth == 6
    end

    test "supports wildcard matching with :any" do
      ast = %{
        "type" => "CallExpression",
        "callee" => %{"type" => "Identifier", "name" => "dangerousFunction"},
        "arguments" => [
          %{"type" => "Literal", "value" => "safe"},
          %{"type" => "Identifier", "name" => "userInput"},
          %{"type" => "Literal", "value" => 123}
        ]
      }

      pattern = %{
        id: "dangerous-call",
        name: "Dangerous Function Call",
        ast_pattern: %{
          type: "CallExpression",
          callee: %{name: "dangerousFunction"},
          arguments: {:includes, %{type: "Identifier"}}
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "javascript")

      assert length(matches) == 1
      # The CallExpression itself isn't in an argument position - it's the root node
      # The pattern matches because the arguments contain an Identifier
      assert hd(matches).context.node_type == "CallExpression"
    end

    test "returns empty list when no patterns match" do
      ast = %{
        "type" => "Program",
        "body" => [
          %{
            "type" => "VariableDeclaration",
            "declarations" => [
              %{
                "type" => "VariableDeclarator",
                "id" => %{"type" => "Identifier", "name" => "safeVar"},
                "init" => %{"type" => "Literal", "value" => 42}
              }
            ]
          }
        ]
      }

      pattern = %{
        id: "never-matches",
        name: "Never Matches",
        ast_pattern: %{
          type: "NonExistentNodeType"
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "javascript")

      assert matches == []
    end

    test "provides match context and location" do
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "FunctionDef",
            "name" => "process_user",
            "lineno" => 10,
            "col_offset" => 0,
            "body" => [
              %{
                "type" => "Expr",
                "lineno" => 11,
                "col_offset" => 4,
                "value" => %{
                  "type" => "Call",
                  "func" => %{"type" => "Name", "id" => "eval"},
                  "args" => [%{"type" => "Name", "id" => "user_data"}],
                  "lineno" => 11,
                  "col_offset" => 4
                }
              }
            ]
          }
        ]
      }

      pattern = %{
        id: "python-eval",
        name: "Eval Usage",
        ast_pattern: %{
          type: "Call",
          func: %{type: "Name", id: "eval"}
        }
      }

      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "python")

      assert length(matches) == 1
      match = hd(matches)

      assert match.location.start_line == 11
      assert match.location.start_column == 4
      assert match.context.in_function == "process_user"
      assert match.context.parent_type == "Expr"
    end
  end

  describe "match_multiple/3" do
    test "matches multiple patterns against AST" do
      ast = %{
        "type" => "Program",
        "body" => [
          %{
            "type" => "CallExpression",
            "callee" => %{"type" => "Identifier", "name" => "eval"},
            "arguments" => [%{"type" => "Identifier", "name" => "code"}]
          },
          %{
            "type" => "VariableDeclaration",
            "declarations" => [
              %{
                "type" => "VariableDeclarator",
                "id" => %{"type" => "Identifier", "name" => "apiKey"},
                "init" => %{"type" => "Literal", "value" => "sk-secret123"}
              }
            ]
          }
        ]
      }

      patterns = [
        %{
          id: "eval-usage",
          name: "Eval Usage",
          ast_pattern: %{
            type: "CallExpression",
            callee: %{name: "eval"}
          }
        },
        %{
          id: "hardcoded-secret",
          name: "Hardcoded Secret",
          ast_pattern: %{
            type: "VariableDeclarator",
            id: %{name: ~r/api_?key/i},
            init: %{type: "Literal"}
          }
        }
      ]

      {:ok, matches} = ASTPatternMatcher.match_multiple(ast, patterns, "javascript")

      assert length(matches) == 2
      assert Enum.any?(matches, &(&1.pattern_id == "eval-usage"))
      assert Enum.any?(matches, &(&1.pattern_id == "hardcoded-secret"))
    end
  end
end
