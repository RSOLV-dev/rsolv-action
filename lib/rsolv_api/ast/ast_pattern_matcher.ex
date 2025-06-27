defmodule RsolvApi.AST.ASTPatternMatcher do
  @moduledoc """
  Matches security patterns against parsed AST structures.
  
  This module provides the core AST-based pattern matching functionality,
  replacing regex-based pattern detection with proper AST traversal.
  
  Features:
  - Deep AST traversal
  - Pattern matching with wildcards and regex
  - Context-aware matching
  - Location tracking
  - Confidence scoring
  """
  
  require Logger
  
  @doc """
  Matches a single pattern against an AST.
  
  Returns {:ok, matches} where matches is a list of findings.
  """
  def match(ast, pattern, language) do
    # Skip patterns without AST rules
    if pattern.ast_pattern == nil do
      {:ok, []}
    else
      matches = traverse_and_match(ast, pattern.ast_pattern, pattern, language, [], %{depth: 0})
      {:ok, matches}
    end
  end
  
  @doc """
  Matches multiple patterns against an AST.
  
  Returns {:ok, matches} where matches is a list of all findings.
  """
  def match_multiple(ast, patterns, language) do
    matches = Enum.flat_map(patterns, fn pattern ->
      {:ok, pattern_matches} = match(ast, pattern, language)
      pattern_matches
    end)
    
    {:ok, matches}
  end
  
  # Private functions
  
  defp traverse_and_match(ast, pattern, full_pattern, language, path, context) when is_map(ast) do
    # Check if current node matches the pattern AND context requirements
    pattern_matches = matches_pattern?(ast, pattern)
    context_passes = if pattern_matches do
      passes_context_requirements?(ast, pattern, full_pattern, context)
    else
      false
    end
    
    
    node_matches = if pattern_matches && context_passes do
      [build_match(ast, full_pattern, path, context)]
    else
      []
    end
    
    # Continue traversing child nodes
    child_matches = Enum.flat_map(ast, fn {key, value} ->
      new_path = path ++ [key]
      new_context = update_context(context, ast, key)
      traverse_and_match(value, pattern, full_pattern, language, new_path, new_context)
    end)
    
    node_matches ++ child_matches
  end
  
  defp traverse_and_match(ast, pattern, full_pattern, language, path, context) when is_list(ast) do
    ast
    |> Enum.with_index()
    |> Enum.flat_map(fn {item, index} ->
      new_path = path ++ [index]
      new_context = context
        |> Map.put(:list_index, index)
        # Don't increment depth for list traversal
      traverse_and_match(item, pattern, full_pattern, language, new_path, new_context)
    end)
  end
  
  defp traverse_and_match(_ast, _pattern, _full_pattern, _language, _path, _context) do
    []
  end
  
  # Made public for debugging
  def matches_pattern?(node, pattern) when is_map(node) and is_map(pattern) do
    result = Enum.all?(pattern, fn {key, expected} ->
      # Skip special context keys (prefixed with _)
      if String.starts_with?(to_string(key), "_") do
        true
      else
        # Try both string and atom keys to handle different AST formats
        string_key = to_string(key)
        actual = Map.get(node, string_key)
        actual = if actual == nil, do: Map.get(node, key), else: actual
        matches_value?(actual, expected)
      end
    end)
    
    
    result
  end
  
  def matches_pattern?(_node, _pattern), do: false
  
  # Check additional context requirements from the pattern
  defp passes_context_requirements?(node, pattern, _full_pattern, context) do
    # Check parent requirements
    parent_ok = if parent_req = pattern["_parent_requirements"] do
      check_parent_requirements(context, parent_req)
    else
      true
    end
    
    # Check SQL keywords requirement (from context_analysis)
    sql_ok = if pattern["_contains_sql_keywords"] || pattern["_contains_sql"] do
      contains_sql_keywords?(node, context)
    else
      true
    end
    
    # Check user input requirement (from context_analysis)
    user_input_ok = if pattern["_has_user_input_in_concatenation"] || pattern["_has_user_input"] do
      has_user_input?(node, context)
    else
      true
    end
    
    # Check if within database call (from context_analysis)
    # For SQL patterns, we're more lenient - if it contains SQL and user input, that's risky
    db_call_ok = if pattern["_within_db_call"] do
      # If we already found SQL keywords and user input, consider this potentially dangerous
      # even if not directly in a db call (could be assigned to a variable first)
      if sql_ok && user_input_ok do
        true
      else
        Map.get(context, :in_database_call, false) || 
        check_ancestor_for_db_call(pattern["_ancestor_requirements"], context)
      end
    else
      true
    end
    
    # Check method name requirements
    method_ok = if methods = pattern["_method_names"] do
      check_method_names(node, methods)
    else
      true
    end
    
    # Check callee name requirements (similar to method names but for direct function calls)
    callee_ok = if callee_names = pattern["_callee_names"] do
      check_callee_names(node, callee_names)
    else
      true
    end
    
    # Check left side requirements (for assignments like innerHTML)
    left_side_ok = if left_req = pattern["_left_side"] do
      check_left_side_requirements(node, left_req)
    else
      true
    end
    
    # Check argument analysis requirements (for eval patterns)
    arg_analysis_ok = if arg_req = pattern["_argument_analysis"] do
      check_argument_analysis(node, arg_req, context)
    else
      true
    end
    
    # Check contains_sql_pattern (Python patterns)
    sql_pattern_ok = if pattern["_contains_sql_pattern"] do
      contains_sql_keywords?(node, context)
    else
      true
    end
    
    # Check left_or_right_is_string (Python patterns)
    string_ok = if pattern["_left_or_right_is_string"] do
      check_if_string_in_binop(node)
    else
      true
    end
    
    
    parent_ok && sql_ok && user_input_ok && db_call_ok && method_ok && callee_ok && left_side_ok && arg_analysis_ok && sql_pattern_ok && string_ok
  end
  
  defp check_ancestor_for_db_call(nil, _context), do: false
  defp check_ancestor_for_db_call(ancestor_req, context) do
    # Check if we have a DB method call in ancestors
    if ancestor_req["has_db_method_call"] || ancestor_req[:has_db_method_call] do
      # For now, use the context flag
      Map.get(context, :in_database_call, false)
    else
      false
    end
  end
  
  defp check_parent_requirements(context, parent_req) do
    parent_type = Map.get(context, :parent_type)
    
    # Check parent type
    type_ok = if req_type = parent_req["type"] || parent_req[:type] do
      parent_type == req_type
    else
      true
    end
    
    # Check callee matches (for method calls)
    callee_ok = if parent_req["callee_matches"] || parent_req[:callee_matches] do
      # This would need access to parent node details
      # For now, just check if we're in a database context
      Map.get(context, :in_database_call, false)
    else
      true
    end
    
    type_ok && callee_ok
  end
  
  defp contains_sql_keywords?(node, _context) do
    # Check if node or its children contain SQL keywords
    node_str = inspect(node)
    sql_keywords = ~r/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|DROP|CREATE)\b/i
    Regex.match?(sql_keywords, node_str)
  end
  
  defp has_user_input?(node, _context) do
    # Check for common user input patterns
    node_str = inspect(node)
    user_input_patterns = [
      ~r/req\.(body|params|query)/,
      ~r/request\.(body|params|query)/,
      ~r/\$_(POST|GET|REQUEST)/,
      ~r/user(Id|Input|Data|Name)/i,
      # Python patterns
      ~r/user_id/,
      ~r/username/,
      ~r/user_input/,
      # Generic input patterns - match on word boundaries
      ~r/\binput\b/i,
      ~r/\bdata\b/i,
      ~r/\bparams\b/i,
      ~r/\bargs\b/i
    ]
    
    # Check if eval(input) pattern - simple variable named "input"
    has_input = Enum.any?(user_input_patterns, &Regex.match?(&1, node_str))
    
    # Also check for simple cases like eval(input) where "input" is the variable name
    if not has_input and is_map(node) do
      case node do
        %{"name" => name} when is_binary(name) ->
          String.downcase(name) in ["input", "data", "userdata", "userinput", "params", "args"]
        _ ->
          false
      end
    else
      has_input
    end
  end
  
  defp check_if_string_in_binop(node) do
    # For BinOp nodes, check if left or right is a string
    case node do
      %{"type" => "BinOp", "left" => left, "right" => right} ->
        is_string_node?(left) || is_string_node?(right)
      _ ->
        false
    end
  end
  
  defp is_string_node?(%{"type" => "Constant", "value" => value}) when is_binary(value), do: true
  defp is_string_node?(%{"type" => "Str", "s" => _}), do: true  # Older Python AST format
  defp is_string_node?(_), do: false
  
  defp check_method_names(node, expected_methods) do
    # Check if this is a call to one of the expected methods
    case node do
      %{"type" => "CallExpression", "callee" => callee} ->
        method_name = extract_method_name(callee)
        method_name in expected_methods
      _ ->
        false
    end
  end
  
  defp extract_method_name(%{"type" => "MemberExpression", "property" => %{"name" => name}}), do: name
  defp extract_method_name(%{"name" => name}), do: name
  defp extract_method_name(_), do: nil
  
  defp check_callee_names(node, expected_names) do
    # For CallExpression, check if the callee matches one of the expected names
    case node do
      %{"type" => "CallExpression", "callee" => callee} ->
        callee_name = extract_callee_name(callee)
        callee_name in expected_names
      _ ->
        false
    end
  end
  
  defp extract_callee_name(%{"name" => name}), do: name
  defp extract_callee_name(%{"type" => "MemberExpression", "property" => %{"name" => name}}), do: name
  defp extract_callee_name(_), do: nil
  
  defp check_left_side_requirements(node, left_req) do
    # For AssignmentExpression, check the left side
    left = Map.get(node, "left")
    
    if left == nil do
      false
    else
      # Check if it's the right type (e.g., MemberExpression)
      type_ok = if req_type = left_req["object_type"] || left_req[:object_type] do
        Map.get(left, "type") == req_type
      else
        true
      end
      
      # Check the property name (e.g., innerHTML vs textContent)
      property_ok = if req_prop = left_req["property"] || left_req[:property] do
        case left do
          %{"type" => "MemberExpression", "property" => %{"name" => prop_name}} ->
            prop_name == req_prop
          _ ->
            false
        end
      else
        true
      end
      
      type_ok && property_ok
    end
  end
  
  defp check_argument_analysis(node, arg_req, context) do
    # For CallExpression, check the arguments
    args = Map.get(node, "arguments", [])
    
    # Check first argument contains user input
    first_arg_ok = if arg_req["first_arg_contains_user_input"] || arg_req[:first_arg_contains_user_input] do
      case Enum.at(args, 0) do
        nil -> false
        arg -> 
          has_user_input?(arg, context)
      end
    else
      true
    end
    
    # Check if it's a string type (not a function)
    string_type_ok = if arg_req["is_string_type"] || arg_req[:is_string_type] do
      case Enum.at(args, 0) do
        %{"type" => type} when type in ["Literal", "StringLiteral", "TemplateLiteral", "Identifier"] -> true
        _ -> false
      end
    else
      true
    end
    
    # Check it's not a static string
    not_static_ok = if arg_req["not_static_string"] || arg_req[:not_static_string] do
      case Enum.at(args, 0) do
        %{"type" => "Literal"} -> false  # Static string literal
        %{"type" => "StringLiteral"} -> false  # Static string literal
        _ -> true
      end
    else
      true
    end
    
    first_arg_ok && string_type_ok && not_static_ok
  end
  
  # Order matters! Regex matching must come before map matching
  defp matches_value?(actual, %Regex{} = regex) do
    is_binary(actual) && Regex.match?(regex, actual)
  end
  
  defp matches_value?(actual, expected) when is_map(expected) do
    matches_pattern?(actual, expected)
  end
  
  defp matches_value?(actual, {:contains, pattern}) when is_list(actual) do
    Enum.any?(actual, fn item ->
      matches_pattern?(item, pattern)
    end)
  end
  
  defp matches_value?(actual, {:includes, pattern}) when is_list(actual) do
    Enum.any?(actual, fn item ->
      matches_pattern?(item, pattern)
    end)
  end
  
  # Handle matching list patterns
  defp matches_value?(actual, expected) when is_list(actual) and is_list(expected) do
    # For now, check if all expected patterns exist in actual
    length(actual) == length(expected) &&
    Enum.zip(actual, expected)
    |> Enum.all?(fn {actual_item, expected_item} ->
      matches_value?(actual_item, expected_item)
    end)
  end
  
  defp matches_value?(actual, expected) do
    # Handle special case for Python operators which are maps like %{"type" => "Add"}
    case {actual, expected} do
      {%{"type" => op_type}, expected_op} when is_binary(expected_op) ->
        op_type == expected_op
      _ ->
        actual == expected
    end
  end
  
  defp build_match(node, pattern, _path, context) do
    %{
      pattern_id: pattern.id,
      pattern_name: pattern.name,
      type: pattern.id,
      pattern_type: Map.get(pattern, :pattern_type, :unknown),  # Get pattern_type from the converted format
      severity: determine_severity(pattern),
      location: extract_location(node, context),
      confidence: calculate_confidence(node, pattern, context),
      context: build_context(node, context),
      recommendation: Map.get(pattern, :recommendation, "Review this code for potential security issues")
    }
  end
  
  defp determine_severity(pattern) do
    cond do
      String.contains?(pattern.id, "injection") -> "high"
      String.contains?(pattern.id, "xss") -> "high"
      String.contains?(pattern.id, "secret") -> "high"
      String.contains?(pattern.id, "eval") -> "critical"
      true -> "medium"
    end
  end
  
  defp extract_location(node, context) do
    # Handle different AST formats
    cond do
      # JavaScript/TypeScript format with _loc
      Map.has_key?(node, "_loc") ->
        loc = Map.get(node, "_loc")
        %{
          start_line: get_in(loc, ["start", "line"]) || 1,
          start_column: get_in(loc, ["start", "column"]) || 0,
          end_line: get_in(loc, ["end", "line"]) || 1,
          end_column: get_in(loc, ["end", "column"]) || 0,
          depth: Map.get(context, :depth, 0)
        }
      
      # Python format with lineno/col_offset
      Map.has_key?(node, "lineno") ->
        %{
          start_line: Map.get(node, "lineno", 1),
          start_column: Map.get(node, "col_offset", 0),
          end_line: Map.get(node, "end_lineno", Map.get(node, "lineno", 1)),
          end_column: Map.get(node, "end_col_offset", Map.get(node, "col_offset", 0)),
          depth: Map.get(context, :depth, 0)
        }
      
      # Default
      true ->
        %{
          start_line: 1,
          start_column: 0,
          end_line: 1,
          end_column: 0,
          depth: Map.get(context, :depth, 0)
        }
    end
  end
  
  defp calculate_confidence(_node, pattern, _context) do
    # Base confidence on pattern type
    cond do
      String.contains?(pattern.id, "injection") -> 0.85
      String.contains?(pattern.id, "xss") -> 0.85
      String.contains?(pattern.id, "secret") -> 0.9
      String.contains?(pattern.id, "eval") -> 0.95
      true -> 0.7
    end
  end
  
  defp build_context(node, context) do
    base = %{
      node_type: Map.get(node, "type"),
      parent_type: Map.get(context, :parent_type),
      depth: Map.get(context, :depth, 0)
    }
    
    # Add function context if available
    base = if function_name = Map.get(context, :in_function) do
      Map.put(base, :in_function, function_name)
    else
      base
    end
    
    # Add argument position if in arguments list
    if Map.has_key?(context, :list_index) && 
       (Map.get(context, :parent_key) == "arguments" || Map.get(context, :parent_key) == "args") do
      Map.put(base, :argument_position, Map.get(context, :list_index))
    else
      base
    end
  end
  
  defp update_context(context, node, key) do
    new_context = context
    |> Map.put(:parent_type, Map.get(node, "type"))
    |> Map.put(:parent_key, to_string(key))
    
    # Only increment depth when traversing into AST nodes (maps with "type")
    new_context = if is_map(node) && Map.has_key?(node, "type") do
      Map.update(new_context, :depth, 1, & &1 + 1)
    else
      new_context
    end
    
    new_context
    |> maybe_add_function_context(node)
    |> maybe_add_database_context(node)
  end
  
  defp maybe_add_function_context(context, %{"type" => "FunctionDef", "name" => name}) do
    Map.put(context, :in_function, name)
  end
  
  defp maybe_add_function_context(context, %{"type" => "FunctionDeclaration", "id" => %{"name" => name}}) do
    Map.put(context, :in_function, name)
  end
  
  defp maybe_add_function_context(context, _node), do: context
  
  defp maybe_add_database_context(context, %{"type" => "CallExpression", "callee" => callee}) do
    method_name = extract_method_name(callee)
    if method_name in ["query", "execute", "exec", "run", "all", "get"] do
      Map.put(context, :in_database_call, true)
    else
      context
    end
  end
  
  defp maybe_add_database_context(context, _node), do: context
end