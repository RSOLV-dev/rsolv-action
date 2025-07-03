defmodule Rsolv.AST.ASTNormalizer do
  @moduledoc """
  Normalizes AST formats from different language parsers into a unified format.
  
  This module converts language-specific AST structures into a standardized format
  that enables consistent pattern matching across all supported languages.
  
  ## Unified AST Format
  
  ```elixir
  %{
    type: :program | :assignment | :function_declaration | etc,
    loc: %{
      start: %{line: integer, column: integer},
      end: %{line: integer, column: integer}
    },
    range: [start_char, end_char],
    children: %{semantic_field_name: value},
    metadata: %{
      original_type: "LanguageSpecificType",
      language: "javascript" | "python" | etc
    }
  }
  ```
  """
  
  @supported_languages ~w(javascript typescript python ruby php java go)
  
  @doc """
  Normalizes an AST from a language-specific format to the unified format.
  
  ## Examples
  
      iex> js_ast = %{"type" => "Program", "body" => []}
      iex> ASTNormalizer.normalize_ast(js_ast, "javascript")
      {:ok, %{type: :program, children: %{body: []}, ...}}
      
      iex> ASTNormalizer.normalize_ast(%{}, "unknown")
      {:error, :unsupported_language}
  """
  def normalize_ast(ast, language) when language in @supported_languages do
    try do
      case validate_ast_structure(ast) do
        :ok ->
          normalized = do_normalize_ast(ast, language)
          {:ok, normalized}
        {:error, reason} ->
          {:error, reason}
      end
    rescue
      _ -> {:error, :normalization_failed}
    end
  end
  
  def normalize_ast(_ast, _language) do
    {:error, :unsupported_language}
  end
  
  @doc """
  Normalizes location information from different parser formats.
  """
  def normalize_location(node, language) do
    case language do
      lang when lang in ~w(javascript typescript ruby) ->
        normalize_js_location(node)
      "python" ->
        normalize_python_location(node)
      lang when lang in ~w(php java go) ->
        normalize_generic_location(node)
    end
  end
  
  @doc """
  Normalizes type names from language-specific to unified naming.
  """
  def normalize_type(type, language) do
    type_mappings = get_type_mappings(language)
    
    # Convert to lowercase with underscores for consistent lookup
    lookup_key = type
    |> String.replace(~r/([a-z])([A-Z])/, "\\1_\\2")
    |> String.downcase()
    |> String.replace(~r/^(stmt|expr)_/, "")
    
    Map.get(type_mappings, type, Map.get(type_mappings, lookup_key, :unknown))
  end
  
  # Private functions
  
  defp validate_ast_structure(ast) when is_map(ast) do
    if Map.has_key?(ast, "type") or Map.has_key?(ast, :type) do
      :ok
    else
      {:error, :malformed_ast}
    end
  end
  
  defp validate_ast_structure(_), do: {:error, :malformed_ast}
  
  defp do_normalize_ast(ast, language) do
    type = get_ast_type(ast)
    normalized_type = normalize_type(type, language)
    location = normalize_location(ast, language)
    children = normalize_children(ast, language)
    metadata = build_metadata(ast, language)
    
    %{
      type: normalized_type,
      loc: location,
      range: location.range,
      children: children,
      language: language,
      metadata: metadata
    }
  end
  
  defp get_ast_type(ast) do
    Map.get(ast, "type") || Map.get(ast, :type) || "Unknown"
  end
  
  defp normalize_js_location(node) do
    loc = Map.get(node, "_loc", %{})
    start_pos = Map.get(loc, "start", %{"line" => 0, "column" => 0})
    end_pos = Map.get(loc, "end", %{"line" => 0, "column" => 0})
    start_char = Map.get(node, "_start", 0)
    end_char = Map.get(node, "_end", 0)
    
    %{
      start: %{
        line: start_pos["line"] || 0,
        column: start_pos["column"] || 0
      },
      end: %{
        line: end_pos["line"] || 0,
        column: end_pos["column"] || 0
      },
      range: [start_char, end_char]
    }
  end
  
  defp normalize_python_location(node) do
    start_line = Map.get(node, "_lineno", 0)
    start_col = Map.get(node, "_col_offset", 0)
    end_line = Map.get(node, "_end_lineno", start_line)
    end_col = Map.get(node, "_end_col_offset", start_col)
    
    %{
      start: %{line: start_line, column: start_col},
      end: %{line: end_line, column: end_col},
      range: [start_col, end_col]  # Approximation when char positions not available
    }
  end
  
  defp normalize_generic_location(node) do
    # Fallback for other languages - try to extract any location info
    loc = Map.get(node, "_loc", %{})
    
    case loc do
      %{"start" => start, "end" => end_pos} ->
        %{
          start: %{line: start["line"] || 0, column: start["column"] || 0},
          end: %{line: end_pos["line"] || 0, column: end_pos["column"] || 0},
          range: [Map.get(node, "_start", 0), Map.get(node, "_end", 0)]
        }
      _ ->
        # Default location when no info available
        %{
          start: %{line: 0, column: 0},
          end: %{line: 0, column: 0},
          range: [0, 0]
        }
    end
  end
  
  defp normalize_children(ast, language) do
    case language do
      lang when lang in ~w(javascript typescript) ->
        normalize_js_children(ast)
      "python" ->
        normalize_python_children(ast)
      "ruby" ->
        normalize_ruby_children(ast)
      "php" ->
        normalize_php_children(ast)
      _ ->
        normalize_generic_children(ast)
    end
  end
  
  defp normalize_js_children(ast) do
    ast
    |> Map.drop(["type", "_loc", "_start", "_end"])
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      normalized_key = String.to_atom(key)
      normalized_value = normalize_child_value(value, "javascript")
      Map.put(acc, normalized_key, normalized_value)
    end)
  end
  
  defp normalize_python_children(ast) do
    ast
    |> Map.drop(["type", "_lineno", "_col_offset", "_end_lineno", "_end_col_offset"])
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      normalized_key = String.to_atom(key)
      normalized_value = normalize_child_value(value, "python")
      Map.put(acc, normalized_key, normalized_value)
    end)
  end
  
  defp normalize_ruby_children(ast) do
    children = Map.get(ast, "children", [])
    type = get_ast_type(ast)
    
    case {type, children} do
      {"lvasgn", [var_name, value]} ->
        %{
          variable: var_name,
          value: normalize_child_value(value, "ruby")
        }
      {"def", [method_name | rest]} ->
        %{
          name: method_name,
          body: normalize_child_value(rest, "ruby")
        }
      _ ->
        %{children: normalize_child_value(children, "ruby")}
    end
  end
  
  defp normalize_php_children(ast) do
    children = Map.get(ast, "children", %{})
    
    # Special handling for PHP assignment expressions
    type = get_ast_type(ast)
    
    case type do
      "Expr_Assign" ->
        # For assignments, we want left and right semantic fields
        var_node = get_in(children, ["var"])
        expr_node = get_in(children, ["expr"])
        
        %{
          left: normalize_child_value(var_node, "php"),
          right: normalize_child_value(expr_node, "php")
        }
      _ ->
        # General PHP children normalization
        children
        |> Enum.reduce(%{}, fn {key, value}, acc ->
          semantic_key = case key do
            "expr" -> :expression
            "var" -> :variable
            "name" -> :name
            "value" -> :value
            _ -> String.to_atom(key)
          end
          
          normalized_value = normalize_child_value(value, "php")
          Map.put(acc, semantic_key, normalized_value)
        end)
    end
  end
  
  defp normalize_generic_children(ast) do
    ast
    |> Map.drop(["type", "_loc", "_start", "_end"])
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      normalized_key = String.to_atom(key)
      normalized_value = normalize_child_value(value, "generic")
      Map.put(acc, normalized_key, normalized_value)
    end)
  end
  
  defp normalize_child_value(value, language) when is_map(value) do
    case Map.has_key?(value, "type") or Map.has_key?(value, :type) do
      true -> 
        # Recursively normalize nested AST nodes
        {:ok, normalized} = normalize_ast(value, language)
        normalized
      false ->
        # Keep as-is if not an AST node
        value
    end
  end
  
  defp normalize_child_value(value, language) when is_list(value) do
    Enum.map(value, &normalize_child_value(&1, language))
  end
  
  defp normalize_child_value(value, _language), do: value
  
  defp build_metadata(ast, language) do
    original_type = get_ast_type(ast)
    original_extra = Map.get(ast, "extra", %{})
    
    %{
      original_type: original_type,
      language: language,
      original_extra: original_extra
    }
  end
  
  defp get_type_mappings("javascript") do
    %{
      "Program" => :program,
      "VariableDeclaration" => :variable_declaration,
      "FunctionDeclaration" => :function_declaration,
      "Identifier" => :identifier,
      "NumericLiteral" => :number_literal,
      "StringLiteral" => :string_literal,
      "BinaryExpression" => :binary_expression,
      "CallExpression" => :call_expression,
      "MemberExpression" => :member_expression,
      "ExpressionStatement" => :expression_statement,
      "BlockStatement" => :block_statement,
      "IfStatement" => :if_statement,
      "WhileStatement" => :while_statement,
      "ForStatement" => :for_statement,
      "ReturnStatement" => :return_statement
    }
  end
  
  defp get_type_mappings("typescript") do
    # TypeScript uses same ESTree format as JavaScript
    get_type_mappings("javascript")
  end
  
  defp get_type_mappings("python") do
    %{
      "Module" => :module,
      "Assign" => :assignment,
      "FunctionDef" => :function_declaration,
      "Name" => :identifier,
      "Constant" => :literal,
      "Num" => :number_literal,
      "Str" => :string_literal,
      "BinOp" => :binary_expression,
      "Call" => :call_expression,
      "Attribute" => :member_expression,
      "Expr" => :expression_statement,
      "If" => :if_statement,
      "While" => :while_statement,
      "For" => :for_statement,
      "Return" => :return_statement
    }
  end
  
  defp get_type_mappings("ruby") do
    %{
      "lvasgn" => :assignment,
      "def" => :function_declaration,
      "send" => :method_call,
      "int" => :integer,
      "str" => :string_literal,
      "sym" => :symbol_literal,
      "if" => :if_statement,
      "while" => :while_statement,
      "for" => :for_statement,
      "return" => :return_statement,
      "begin" => :block_statement
    }
  end
  
  defp get_type_mappings("php") do
    %{
      "Stmt_Expression" => :expression_statement,
      "expression_statement" => :expression_statement,
      "Expr_Assign" => :assignment,
      "assign" => :assignment,
      "Expr_Variable" => :variable,
      "variable" => :variable,
      "Scalar_LNumber" => :number_literal,
      "lnumber" => :number_literal,
      "Scalar_String" => :string_literal,
      "string" => :string_literal,
      "Expr_FuncCall" => :call_expression,
      "funccall" => :call_expression,
      "Stmt_Function" => :function_declaration,
      "function" => :function_declaration,
      "Stmt_If" => :if_statement,
      "if" => :if_statement
    }
  end
  
  defp get_type_mappings("java") do
    %{
      "CompilationUnit" => :compilation_unit,
      "ClassOrInterfaceDeclaration" => :class_declaration,
      "MethodDeclaration" => :function_declaration,
      "VariableDeclarationExpr" => :variable_declaration,
      "AssignExpr" => :assignment,
      "NameExpr" => :identifier,
      "IntegerLiteralExpr" => :number_literal,
      "StringLiteralExpr" => :string_literal
    }
  end
  
  defp get_type_mappings("go") do
    %{
      "File" => :file,
      "GenDecl" => :declaration,
      "FuncDecl" => :function_declaration,
      "AssignStmt" => :assignment,
      "Ident" => :identifier,
      "BasicLit" => :literal,
      "CallExpr" => :call_expression,
      "SelectorExpr" => :member_expression,
      "IfStmt" => :if_statement,
      "ForStmt" => :for_statement,
      "ReturnStmt" => :return_statement
    }
  end
  
  defp get_type_mappings(_), do: %{}
end