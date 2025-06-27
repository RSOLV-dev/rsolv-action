defmodule RsolvApi.AST.ASTNormalizerTest do
  @moduledoc """
  Tests for AST normalization across different languages.
  
  The normalizer should convert language-specific AST formats into a unified format
  that enables consistent pattern matching across all supported languages.
  """
  
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.ASTNormalizer
  
  describe "normalize_ast/2" do
    test "normalizes JavaScript/TypeScript AST from tree-sitter format" do
      # Red phase: Test the expected unified format for JavaScript
      javascript_ast = %{
        "type" => "Program",
        "_loc" => %{
          "start" => %{"line" => 1, "column" => 0},
          "end" => %{"line" => 1, "column" => 10}
        },
        "_start" => 0,
        "_end" => 10,
        "body" => [
          %{
            "type" => "VariableDeclaration",
            "_loc" => %{
              "start" => %{"line" => 1, "column" => 0},
              "end" => %{"line" => 1, "column" => 10}
            },
            "_start" => 0,
            "_end" => 10,
            "declarations" => [
              %{
                "type" => "VariableDeclarator",
                "id" => %{"type" => "Identifier", "name" => "x"},
                "init" => %{"type" => "NumericLiteral", "value" => 1}
              }
            ],
            "kind" => "var"
          }
        ]
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(javascript_ast, "javascript")
      
      # Should have unified format
      assert normalized.type == :program
      assert normalized.loc.start.line == 1
      assert normalized.loc.start.column == 0
      assert normalized.loc.end.line == 1
      assert normalized.loc.end.column == 10
      assert normalized.range == [0, 10]
      assert normalized.language == "javascript"
      
      # Should have children with semantic names
      assert Map.has_key?(normalized.children, :body)
      assert is_list(normalized.children.body)
      
      # First statement should be normalized variable declaration
      [first_stmt] = normalized.children.body
      assert first_stmt.type == :variable_declaration
      assert first_stmt.children.kind == "var"
      assert is_list(first_stmt.children.declarations)
      
      # Preserve original type in metadata
      assert normalized.metadata.original_type == "Program"
    end
    
    test "normalizes Python AST from ast module format" do
      # Red phase: Test Python AST normalization
      python_ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "Assign",
            "targets" => [
              %{"type" => "Name", "id" => "x", "ctx" => %{"type" => "Store"}}
            ],
            "value" => %{"type" => "Constant", "value" => 1},
            "_lineno" => 1,
            "_col_offset" => 0,
            "_end_lineno" => 1,
            "_end_col_offset" => 5
          }
        ]
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(python_ast, "python")
      
      # Should convert Python location format to unified format
      assert normalized.type == :module
      assert normalized.language == "python"
      
      # Should convert Python location fields
      [first_stmt] = normalized.children.body
      assert first_stmt.type == :assignment
      assert first_stmt.loc.start.line == 1
      assert first_stmt.loc.start.column == 0
      assert first_stmt.loc.end.line == 1
      assert first_stmt.loc.end.column == 5
      assert first_stmt.range == [0, 5]
      
      # Should normalize Python-specific fields
      assert is_list(first_stmt.children.targets)
      assert Map.has_key?(first_stmt.children, :value)
      
      # Preserve original type
      assert first_stmt.metadata.original_type == "Assign"
    end
    
    test "normalizes Ruby AST from parser gem format" do
      # Red phase: Test Ruby AST normalization  
      ruby_ast = %{
        "type" => "lvasgn",
        "_loc" => %{
          "start" => %{"line" => 1, "column" => 0},
          "end" => %{"line" => 1, "column" => 5}
        },
        "_start" => 0,
        "_end" => 5,
        "children" => [
          "x",
          %{
            "type" => "int",
            "children" => [1]
          }
        ]
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(ruby_ast, "ruby")
      
      # Should convert Ruby array-based children to semantic structure
      assert normalized.type == :assignment
      assert normalized.language == "ruby"
      assert normalized.metadata.original_type == "lvasgn"
      
      # Should convert children array to semantic structure
      assert Map.has_key?(normalized.children, :variable)
      assert Map.has_key?(normalized.children, :value)
      assert normalized.children.variable == "x"
      assert normalized.children.value.type == :integer
    end
    
    test "normalizes PHP AST from nikic/php-parser format" do
      # Red phase: Test PHP AST normalization
      php_ast = %{
        "type" => "Stmt_Expression",
        "_loc" => %{
          "start" => %{"line" => 1, "column" => 0},
          "end" => %{"line" => 1, "column" => 10}
        },
        "children" => %{
          "expr" => %{
            "type" => "Expr_Assign",
            "children" => %{
              "var" => %{"type" => "Expr_Variable", "children" => %{"name" => "x"}},
              "expr" => %{"type" => "Scalar_LNumber", "children" => %{"value" => 1}}
            }
          }
        }
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(php_ast, "php")
      
      # Should normalize PHP verbose type names
      assert normalized.type == :expression_statement
      assert normalized.language == "php"
      assert normalized.metadata.original_type == "Stmt_Expression"
      
      # Should preserve nested structure with semantic names
      assert Map.has_key?(normalized.children, :expression)
      expr = normalized.children.expression
      assert expr.type == :assignment
      assert Map.has_key?(expr.children, :left)
      assert Map.has_key?(expr.children, :right)
    end
    
    test "handles missing location information gracefully" do
      # Red phase: Test handling of ASTs without location info
      ast_without_location = %{
        "type" => "Program",
        "body" => []
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(ast_without_location, "javascript")
      
      # Should provide default location
      assert normalized.loc.start.line == 0
      assert normalized.loc.start.column == 0
      assert normalized.loc.end.line == 0
      assert normalized.loc.end.column == 0
      assert normalized.range == [0, 0]
    end
    
    test "preserves metadata for debugging and analysis" do
      # Red phase: Test metadata preservation
      javascript_ast = %{
        "type" => "Program",
        "body" => [],
        "extra" => %{"some" => "data"}
      }
      
      {:ok, normalized} = ASTNormalizer.normalize_ast(javascript_ast, "javascript")
      
      # Should preserve original metadata
      assert normalized.metadata.original_type == "Program"
      assert normalized.metadata.language == "javascript"
      assert Map.has_key?(normalized.metadata, :original_extra)
      assert normalized.metadata.original_extra == %{"some" => "data"}
    end
    
    test "returns error for unsupported language" do
      # Red phase: Test error handling for unknown languages
      ast = %{"type" => "Unknown"}
      
      assert {:error, :unsupported_language} = ASTNormalizer.normalize_ast(ast, "unknown_lang")
    end
    
    test "returns error for malformed AST" do
      # Red phase: Test error handling for invalid AST structures
      malformed_ast = %{"invalid" => "structure"}
      
      assert {:error, :malformed_ast} = ASTNormalizer.normalize_ast(malformed_ast, "javascript")
    end
  end
  
  describe "normalize_location/2" do
    test "converts JavaScript/Ruby location format" do
      # Red phase: Test location conversion
      js_location = %{
        "_loc" => %{
          "start" => %{"line" => 5, "column" => 10},
          "end" => %{"line" => 5, "column" => 20}
        },
        "_start" => 100,
        "_end" => 110
      }
      
      location = ASTNormalizer.normalize_location(js_location, "javascript")
      
      assert location.start.line == 5
      assert location.start.column == 10
      assert location.end.line == 5
      assert location.end.column == 20
      assert location.range == [100, 110]
    end
    
    test "converts Python location format" do
      # Red phase: Test Python location conversion
      python_location = %{
        "_lineno" => 3,
        "_col_offset" => 5,
        "_end_lineno" => 3,
        "_end_col_offset" => 15
      }
      
      location = ASTNormalizer.normalize_location(python_location, "python")
      
      assert location.start.line == 3
      assert location.start.column == 5
      assert location.end.line == 3
      assert location.end.column == 15
      assert location.range == [5, 15]  # Approximation when character positions not available
    end
  end
  
  describe "normalize_type/2" do
    test "normalizes JavaScript types to unified names" do
      # Red phase: Test type name normalization
      assert ASTNormalizer.normalize_type("Program", "javascript") == :program
      assert ASTNormalizer.normalize_type("VariableDeclaration", "javascript") == :variable_declaration
      assert ASTNormalizer.normalize_type("FunctionDeclaration", "javascript") == :function_declaration
      assert ASTNormalizer.normalize_type("Identifier", "javascript") == :identifier
      assert ASTNormalizer.normalize_type("NumericLiteral", "javascript") == :number_literal
    end
    
    test "normalizes Python types to unified names" do
      # Red phase: Test Python type normalization
      assert ASTNormalizer.normalize_type("Module", "python") == :module
      assert ASTNormalizer.normalize_type("Assign", "python") == :assignment
      assert ASTNormalizer.normalize_type("FunctionDef", "python") == :function_declaration
      assert ASTNormalizer.normalize_type("Name", "python") == :identifier
      assert ASTNormalizer.normalize_type("Constant", "python") == :literal
    end
    
    test "normalizes Ruby types to unified names" do
      # Red phase: Test Ruby type normalization
      assert ASTNormalizer.normalize_type("lvasgn", "ruby") == :assignment
      assert ASTNormalizer.normalize_type("def", "ruby") == :function_declaration
      assert ASTNormalizer.normalize_type("send", "ruby") == :method_call
      assert ASTNormalizer.normalize_type("int", "ruby") == :integer
      assert ASTNormalizer.normalize_type("str", "ruby") == :string_literal
    end
    
    test "normalizes PHP types to unified names" do
      # Red phase: Test PHP type normalization
      assert ASTNormalizer.normalize_type("Stmt_Expression", "php") == :expression_statement
      assert ASTNormalizer.normalize_type("Expr_Assign", "php") == :assignment
      assert ASTNormalizer.normalize_type("Expr_Variable", "php") == :variable
      assert ASTNormalizer.normalize_type("Scalar_LNumber", "php") == :number_literal
    end
    
    test "handles unknown types with fallback" do
      # Red phase: Test unknown type handling
      assert ASTNormalizer.normalize_type("UnknownType", "javascript") == :unknown
      assert ASTNormalizer.normalize_type("CustomNode", "python") == :unknown
    end
  end
end