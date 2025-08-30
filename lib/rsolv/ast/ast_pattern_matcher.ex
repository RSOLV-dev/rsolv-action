defmodule Rsolv.AST.ASTPatternMatcher do
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
    
    # Check callee pattern (e.g., Math.random)
    callee_pattern_ok = if callee_pattern = pattern["_callee_pattern"] do
      check_callee_pattern(node, callee_pattern)
    else
      true
    end
    
    # Check callee object.property pattern (e.g., crypto.createHash)
    callee_object_property_ok = if pattern["_callee_object"] && pattern["_callee_property"] do
      check_callee_object_property(node, pattern["_callee_object"], pattern["_callee_property"])
    else
      true
    end
    
    # Check usage analysis for context-based validation
    usage_ok = if usage_analysis = pattern["_usage_analysis"] do
      check_usage_analysis(node, usage_analysis, context)
    else
      true
    end
    
    # Check identifier requirements for hardcoded secrets
    identifier_ok = if identifier_check = pattern["_identifier_check"] do
      check_identifier(node, identifier_check)
    else
      true
    end
    
    # Check value analysis for hardcoded secrets
    value_ok = if value_analysis = pattern["_value_analysis"] do
      check_value_analysis(node, value_analysis)
    else
      true
    end
    
    # Check value type restrictions
    value_type_ok = if value_types = pattern["_value_types"] do
      check_value_types(node, value_types)
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
    
    
    parent_ok && sql_ok && user_input_ok && db_call_ok && method_ok && callee_ok && 
    callee_pattern_ok && callee_object_property_ok && usage_ok && identifier_ok && value_ok && value_type_ok && 
    left_side_ok && arg_analysis_ok && sql_pattern_ok && string_ok
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
  
  @doc """
  Checks if a node's arguments match the specified analysis requirements.
  
  Supports checking argument position, value patterns, and various other constraints
  to reduce false positives in pattern matching.
  
  ## Examples
  
      iex> alias Rsolv.AST.ASTPatternMatcher
      iex> # Test MD5 detection - should match
      iex> node = %{"type" => "CallExpression", "arguments" => [%{"type" => "Literal", "value" => "md5"}]}
      iex> arg_req = %{"position" => 0, "value_pattern" => ~r/^md5$/i}
      iex> ASTPatternMatcher.check_argument_analysis(node, arg_req, %{})
      true
      
      iex> alias Rsolv.AST.ASTPatternMatcher
      iex> # Test SHA256 detection - should NOT match MD5 pattern
      iex> node = %{"type" => "CallExpression", "arguments" => [%{"type" => "Literal", "value" => "sha256"}]}
      iex> arg_req = %{"position" => 0, "value_pattern" => ~r/^md5$/i}
      iex> ASTPatternMatcher.check_argument_analysis(node, arg_req, %{})
      false
      
      iex> alias Rsolv.AST.ASTPatternMatcher
      iex> # Test SHA1 detection with hyphen - should match
      iex> node = %{"type" => "CallExpression", "arguments" => [%{"type" => "Literal", "value" => "sha-1"}]}
      iex> arg_req = %{"position" => 0, "value_pattern" => ~r/^sha-?1$/i}
      iex> ASTPatternMatcher.check_argument_analysis(node, arg_req, %{})
      true
      
      iex> alias Rsolv.AST.ASTPatternMatcher
      iex> # Test when no arguments at position - should fail
      iex> node = %{"type" => "CallExpression", "arguments" => []}
      iex> arg_req = %{"position" => 0, "value_pattern" => ~r/^md5$/i}
      iex> ASTPatternMatcher.check_argument_analysis(node, arg_req, %{})
      false
  """
  @doc false  # Internal function, but needs to be public for doctests
  def check_argument_analysis(node, arg_req, context \\ %{}) do
    # For CallExpression, check the arguments
    args = Map.get(node, "arguments", [])
    
    # Check specific argument position and value pattern (for weak crypto patterns)
    position_value_ok = if position = arg_req["position"] || arg_req[:position] do
      value_pattern = arg_req["value_pattern"] || arg_req[:value_pattern]
      
      case Enum.at(args, position) do
        nil -> 
          false  # No argument at this position
          
        %{"type" => type, "value" => value} when type in ["Literal", "StringLiteral"] and is_binary(value) ->
          # Check if the value matches the pattern
          if value_pattern do
            case value_pattern do
              %Regex{} = regex -> Regex.match?(regex, value)
              pattern when is_binary(pattern) -> value == pattern
              _ -> true
            end
          else
            true
          end
          
        %{"type" => "TemplateLiteral", "quasis" => [%{"value" => %{"raw" => raw}} | _]} when is_binary(raw) ->
          # Check template literal value
          if value_pattern do
            case value_pattern do
              %Regex{} = regex -> Regex.match?(regex, raw)
              pattern when is_binary(pattern) -> raw == pattern
              _ -> true
            end
          else
            true
          end
          
        _ -> 
          false  # Argument exists but isn't a string literal we can check
      end
    else
      true  # No position requirement
    end
    
    # Early return if position/value check failed
    if not position_value_ok do
      false
    else
      # Check if arguments contain sensitive keywords
      sensitive_keywords_ok = if arg_req["contains_sensitive_keywords"] || arg_req[:contains_sensitive_keywords] do
        # Look for sensitive keywords in argument values
        sensitive_patterns = ~r/password|secret|token|key|credential|auth|api[_-]?key/i
        
        Enum.any?(args, fn arg ->
          case arg do
            # Check identifiers for sensitive variable names
            %{"type" => "Identifier", "name" => name} ->
              Regex.match?(sensitive_patterns, name)
              
            # Check string literals for sensitive content
            %{"type" => type, "value" => value} when type in ["Literal", "StringLiteral"] and is_binary(value) ->
              Regex.match?(sensitive_patterns, value)
              
            # Check template literals
            %{"type" => "TemplateLiteral", "quasis" => quasis} ->
              Enum.any?(quasis, fn 
                %{"value" => %{"raw" => raw}} when is_binary(raw) ->
                  Regex.match?(sensitive_patterns, raw)
                _ -> false
              end)
              
            # Check object expressions for sensitive property names
            %{"type" => "ObjectExpression", "properties" => props} ->
              Enum.any?(props, fn
                %{"key" => %{"name" => name}} when is_binary(name) ->
                  Regex.match?(sensitive_patterns, name)
                %{"key" => %{"value" => value}} when is_binary(value) ->
                  Regex.match?(sensitive_patterns, value)
                _ -> false
              end)
              
            _ -> false
          end
        end)
      else
        true
      end
      
      # For patterns that require sensitive keywords, only match if found
      # For other patterns, continue with additional checks
      if arg_req["contains_sensitive_keywords"] || arg_req[:contains_sensitive_keywords] do
        sensitive_keywords_ok
      else
        # Check first argument contains user input
        first_arg_ok = if arg_req["first_arg_contains_user_input"] || arg_req[:first_arg_contains_user_input] do
          case Enum.at(args, 0) do
            nil -> false
            arg -> 
              # Simple check for identifiers that might be user input
              case arg do
                %{"type" => "Identifier"} -> true
                %{"type" => "MemberExpression"} -> true
                %{"type" => "CallExpression"} -> true
                _ -> false
              end
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
        
        first_arg_ok && string_type_ok && not_static_ok && sensitive_keywords_ok && position_value_ok
      end
    end
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
      min_confidence: Map.get(pattern, :min_confidence, 0.7),  # Pass through min_confidence
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
  
  defp calculate_confidence(node, pattern, context) do
    # Check if pattern has confidence rules
    confidence_rules = Map.get(pattern, :confidence_rules, %{})
    
    # Check if we have the actual pattern object for more checks
    ast_pattern = Map.get(pattern, :ast_pattern, %{})
    
    if map_size(confidence_rules) > 0 do
      # Use the ConfidenceCalculator with pattern-specific rules
      Rsolv.AST.ConfidenceCalculator.calculate_confidence(
        ast_pattern,
        node,
        context,
        confidence_rules
      )
    else
      # Fallback to simple confidence based on pattern type
      cond do
        String.contains?(pattern.id, "injection") -> 0.85
        String.contains?(pattern.id, "xss") -> 0.85
        String.contains?(pattern.id, "secret") -> 0.9
        String.contains?(pattern.id, "eval") -> 0.95
        String.contains?(pattern.id, "crypto") -> 0.7  # Better default for crypto patterns
        true -> 0.7
      end
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
  
  # Validates identifier names for hardcoded secret patterns
  defp check_identifier(node, identifier_check) do
    with identifier_name when is_binary(identifier_name) <- extract_identifier_name(node),
         true <- matches_required_pattern?(identifier_name, identifier_check),
         true <- not_excluded_pattern?(identifier_name, identifier_check) do
      true
    else
      _ -> false
    end
  end
  
  defp extract_identifier_name(%{"id" => %{"name" => name}}), do: name
  defp extract_identifier_name(%{"name" => name}), do: name
  defp extract_identifier_name(_), do: nil
  
  defp matches_required_pattern?(name, check) do
    case get_option(check, :pattern) do
      %Regex{} = pattern -> Regex.match?(pattern, name)
      nil -> true
    end
  end
  
  defp not_excluded_pattern?(name, check) do
    case get_option(check, :exclude_pattern) do
      %Regex{} = pattern -> not Regex.match?(pattern, name)
      nil -> true
    end
  end
  
  # Analyzes value characteristics for hardcoded secret detection
  defp check_value_analysis(node, value_analysis) do
    with value_node when not is_nil(value_node) <- extract_value_node(node),
         string_value when is_binary(string_value) <- extract_string_value(value_node),
         true <- valid_secret_length?(string_value, value_analysis) do
      true
    else
      _ -> false
    end
  end
  
  defp extract_value_node(%{"init" => init}), do: init
  defp extract_value_node(%{"value" => value}), do: value
  defp extract_value_node(_), do: nil
  
  defp extract_string_value(%{"type" => "Literal", "value" => v}) when is_binary(v), do: v
  defp extract_string_value(%{"type" => "TemplateLiteral", "quasis" => [%{"value" => %{"raw" => v}} | _]}), do: v
  defp extract_string_value(_), do: nil
  
  defp valid_secret_length?(string, analysis) do
    min_length = get_option(analysis, :min_length, 16)
    max_length = get_option(analysis, :max_length, 200)
    string_length = String.length(string)
    
    # Quick rejection for obviously non-secret values
    cond do
      string_length < 10 -> false  # Too short to be a real secret
      string_length < min_length -> false
      string_length > max_length -> false
      true -> true
    end
  end
  
  # Validates that the value node type matches allowed types for secrets
  defp check_value_types(node, allowed_types) do
    with value_node when not is_nil(value_node) <- extract_value_node(node),
         node_type when is_binary(node_type) <- value_node["type"] do
      node_type in allowed_types
    else
      _ -> false
    end
  end
  
  # Helper to get option from either atom or string key
  defp get_option(map, key, default \\ nil) do
    map[key] || map[to_string(key)] || default
  end
  
  # Checks if the callee matches a specific pattern (e.g., Math.random)
  defp check_callee_pattern(node, pattern_string) do
    callee = node["callee"]
    
    case {callee, pattern_string} do
      # Handle member expressions like Math.random
      {%{"type" => "MemberExpression", "object" => %{"name" => obj}, "property" => %{"name" => prop}}, pattern} ->
        actual = "#{obj}.#{prop}"
        actual == pattern || String.downcase(actual) == String.downcase(pattern)
        
      # Handle simple function names
      {%{"type" => "Identifier", "name" => name}, pattern} ->
        name == pattern || String.downcase(name) == String.downcase(pattern)
        
      _ ->
        false
    end
  end
  
  # Checks if the callee matches object.property pattern (e.g., crypto.createHash)
  defp check_callee_object_property(node, expected_object, expected_property) do
    callee = node["callee"]
    
    case callee do
      %{"type" => "MemberExpression", "object" => %{"name" => obj}, "property" => %{"name" => prop}} ->
        obj == expected_object && prop == expected_property
        
      %{"type" => "MemberExpression", "object" => %{"type" => "Identifier", "name" => obj}, "property" => %{"type" => "Identifier", "name" => prop}} ->
        obj == expected_object && prop == expected_property
        
      _ ->
        false
    end
  end
  
  # Performs usage analysis to check context-specific requirements
  defp check_usage_analysis(_node, analysis, context) do
    checks = []
    
    # Check variable name if required
    checks = if get_option(analysis, :check_variable_name) do
      parent = Map.get(context, :parent_node)
      var_check = case parent do
        %{"type" => "VariableDeclarator", "id" => %{"name" => name}} ->
          # Check if variable name suggests security usage
          security_patterns = ~r/token|key|secret|password|auth|session|nonce|salt|iv|uuid|guid/i
          Regex.match?(security_patterns, name)
        _ ->
          false
      end
      [var_check | checks]
    else
      checks
    end
    
    # Check context if required
    checks = if get_option(analysis, :check_context) do
      # Check if we're in a security-related context
      in_security_context = Map.get(context, :in_security_function, false) ||
                           Map.get(context, :near_crypto_usage, false)
      [in_security_context | checks]
    else
      checks
    end
    
    # Check transformations if required (e.g., toString(36))
    checks = if get_option(analysis, :check_transformations) do
      parent = Map.get(context, :parent_node)
      has_transform = case parent do
        %{"type" => "CallExpression", "callee" => %{"property" => %{"name" => method}}} ->
          method in ["toString", "substring", "substr", "slice"]
        _ ->
          false
      end
      [has_transform | checks]
    else
      checks
    end
    
    # If no specific checks were enabled, pass by default
    if Enum.empty?(checks) do
      true
    else
      # Require at least one check to pass for Math.random to be flagged
      Enum.any?(checks)
    end
  end
  
end