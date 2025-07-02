defmodule RsolvApi.AST.PatternAdapter do
  @moduledoc """
  Adapts security patterns for use with the AST PatternMatcher.
  
  This module bridges between the existing pattern system (PatternRegistry)
  and the new AST-based pattern matching. It loads patterns, enhances them
  with AST rules from ast_pattern.ex, and converts them to the format
  expected by PatternMatcher.
  """
  
  alias RsolvApi.Security.{Pattern, ASTPattern, PatternRegistry, PatternServer}
  require Logger
  
  @cache_table :pattern_adapter_cache
  @cache_ttl :timer.hours(1)  # Patterns don't change often
  
  # Initialize cache on first use
  defp ensure_cache_exists do
    case :ets.whereis(@cache_table) do
      :undefined ->
        try do
          :ets.new(@cache_table, [:set, :public, :named_table, {:read_concurrency, true}])
        rescue
          ArgumentError ->
            # Table was created by another process
            :ok
        end
      _ ->
        :ok
    end
  end
  
  @doc """
  Loads patterns for a specific language with AST enhancements.
  Results are cached for performance.
  """
  def load_patterns_for_language(language) do
    # Ensure cache is initialized
    ensure_cache_exists()
    
    cache_key = {:patterns, language}
    
    case lookup_cache(cache_key) do
      {:ok, patterns} -> 
        patterns
        
      :miss ->
        patterns = do_load_patterns(language)
        cache_patterns(cache_key, patterns)
        patterns
    end
  end
  
  @doc """
  Converts an AST-enhanced pattern to the format expected by PatternMatcher.
  """
  def convert_to_matcher_format(%ASTPattern{} = pattern) do
    # Convert AST rules to the ast_pattern format expected by matcher
    ast_pattern = if pattern.ast_rules do
      # Convert AST rules to a simple pattern format the matcher expects
      convert_ast_rules_to_pattern(pattern.ast_rules)
    else
      # Fallback: try to extract pattern from regex
      nil
    end
    
    %{
      id: pattern.id,
      name: pattern.name,
      pattern_type: pattern.type,
      severity: pattern.severity,
      ast_pattern: ast_pattern,
      context_rules: pattern.context_rules,
      confidence_rules: pattern.confidence_rules,
      min_confidence: pattern.min_confidence || 0.7,
      languages: pattern.languages || [],
      regex: pattern.regex
    }
  end
  
  # Handle regular Pattern struct
  def convert_to_matcher_format(%Pattern{} = pattern) do
    # First enhance it, then convert
    pattern
    |> enhance_pattern()
    |> convert_to_matcher_format()
  end
  
  # Convert the complex ast_rules structure to pattern for matching
  defp convert_ast_rules_to_pattern(%{node_type: node_type} = rules) do
    base_pattern = %{
      "type" => to_string(node_type)
    }
    
    
    # Add operator if present
    base_pattern = if operator = rules[:operator] do
      Map.put(base_pattern, "operator", operator)
    else
      base_pattern
    end
    
    # Special handling for Python BinOp patterns
    base_pattern = if node_type == "BinOp" && rules[:op] do
      Map.put(base_pattern, "op", rules[:op])
    else
      base_pattern
    end
    
    # Add parent node requirements
    base_pattern = if parent = rules[:parent_node] do
      Map.put(base_pattern, "_parent_requirements", parent)
    else
      base_pattern
    end
    
    # Add context analysis requirements
    base_pattern = if context = rules[:context_analysis] do
      base_pattern
      |> maybe_add_context_rule(:contains_sql_keywords, context)
      |> maybe_add_context_rule(:has_user_input_in_concatenation, context)
      |> maybe_add_context_rule(:within_db_call, context)
    else
      base_pattern
    end
    
    # Add SQL context requirements (Python patterns use this)
    base_pattern = if sql_context = rules[:sql_context] do
      base_pattern
      |> maybe_add_context_rule(:left_or_right_is_string, sql_context)
      |> maybe_add_context_rule(:contains_sql_pattern, sql_context)
      |> maybe_add_context_rule(:followed_by_db_call, sql_context)
    else
      base_pattern
    end
    
    # Add ancestor requirements
    base_pattern = if ancestors = rules[:ancestor_requirements] do
      Map.put(base_pattern, "_ancestor_requirements", ancestors)
    else
      base_pattern
    end
    
    # Add left side requirements (for assignments)
    base_pattern = if left_side = rules[:left_side] do
      Map.put(base_pattern, "_left_side", left_side)
    else
      base_pattern
    end
    
    # Add right side analysis
    base_pattern = if right_side = rules[:right_side_analysis] do
      Map.put(base_pattern, "_right_side_analysis", right_side)
    else
      base_pattern
    end
    
    # Add other direct requirements
    base_pattern = base_pattern
    |> maybe_add_rule(:contains_sql, rules)
    |> maybe_add_rule(:has_user_input, rules)
    |> maybe_add_rule(:callee_matches, rules)
    |> maybe_add_rule(:method_names, rules)
    |> maybe_add_rule(:callee, rules)  # For eval pattern with alternatives
    |> maybe_add_rule(:callee_names, rules)  # For command injection patterns
    |> maybe_add_rule(:argument_contains, rules)
    |> maybe_add_rule(:argument_analysis, rules)  # For argument checking
    
    
    base_pattern
  end
  
  defp convert_ast_rules_to_pattern(_), do: nil
  
  defp maybe_add_rule(pattern, key, rules) do
    value = rules[key]
    
    case {key, value} do
      {:callee, %{name: name, alternatives: alts}} ->
        # Special handling for callee with alternatives
        Map.put(pattern, "_callee_names", [name | alts])
        
      {:callee, %{name: name}} ->
        # Special handling for callee with just name
        Map.put(pattern, "_callee_names", [name])
        
      {_, nil} ->
        # No value, return pattern unchanged
        pattern
        
      {_, value} ->
        # Default case - add with underscore prefix
        Map.put(pattern, "_#{key}", value)
    end
  end
  
  defp maybe_add_context_rule(pattern, key, context) do
    if value = context[key] do
      Map.put(pattern, "_#{key}", value)
    else
      pattern
    end
  end
  
  @doc """
  Enhances a regular pattern with AST rules using the logic from ast_pattern.ex
  """
  def enhance_pattern(%Pattern{} = pattern) do
    # Try to find the module that generated this pattern based on its ID
    enhanced = try do
      # Convert pattern ID to module name
      # e.g., "python-sql-injection-concat" -> RsolvApi.Security.Patterns.Python.SqlInjectionConcat
      module_name = pattern_id_to_module_name(pattern.id)
      module = String.to_existing_atom("Elixir.#{module_name}")
      
      if function_exported?(module, :ast_enhancement, 0) do
        enhancement = apply(module, :ast_enhancement, [])
        
        # Convert to ASTPattern with ast_enhancement data
        pattern
        |> Map.from_struct()
        |> Map.merge(enhancement)
        |> then(&struct(ASTPattern, &1))
      else
        nil
      end
    rescue
      _error ->
        nil
    end
    
    # If no custom enhancement or it failed, use ASTPattern.enhance/1
    enhanced || case ASTPattern.enhance(pattern) do
      %ASTPattern{} = enhanced ->
        enhanced
        
      _ ->
        # If enhancement fails, convert to basic ASTPattern without rules
        pattern
        |> Map.from_struct()
        |> Map.put(:ast_rules, nil)
        |> Map.put(:context_rules, nil)
        |> Map.put(:confidence_rules, nil)
        |> Map.put(:min_confidence, 0.7)
        |> then(&struct(ASTPattern, &1))
    end
  end
  
  # Private functions
  
  defp do_load_patterns(language) do
    # PatternServer is the production interface - try it first
    language_patterns = case Process.whereis(PatternServer) do
      nil ->
        # PatternServer not running, use PatternRegistry directly
        Logger.debug("PatternServer not running, using PatternRegistry")
        PatternRegistry.get_patterns_for_language(language)
      _pid ->
        # PatternServer is running, use it
        case PatternServer.get_patterns(language) do
          {:ok, patterns} -> patterns
          _ -> 
            # Fallback to PatternRegistry if server has issues
            PatternRegistry.get_patterns_for_language(language)
        end
    end
    
    Logger.info("PatternAdapter loading patterns for #{language}: found #{length(language_patterns)} patterns")
    
    # Enhance each pattern and convert to matcher format
    enhanced_patterns = language_patterns
    |> Enum.map(fn pattern ->
      try do
        enhanced = enhance_pattern(pattern)
        enhanced
      rescue
        error ->
          Logger.warning("Failed to enhance pattern #{pattern.id}: #{Exception.message(error)}")
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&convert_to_matcher_format/1)
    |> Enum.reject(&is_nil/1)
    
    enhanced_patterns
  rescue
    error ->
      Logger.error("Failed to load patterns for #{language}: #{inspect(error)}")
      []
  end
  
  defp lookup_cache(key) do
    case :ets.lookup(@cache_table, key) do
      [{^key, {patterns, expiry}}] ->
        if expiry > System.monotonic_time(:millisecond) do
          {:ok, patterns}
        else
          :ets.delete(@cache_table, key)
          :miss
        end
      _ ->
        :miss
    end
  end
  
  defp cache_patterns(key, patterns) do
    ensure_cache_exists()
    expiry = System.monotonic_time(:millisecond) + @cache_ttl
    :ets.insert(@cache_table, {key, {patterns, expiry}})
    :ok
  end
  
  defp pattern_id_to_module_name(pattern_id) do
    # Convert pattern ID to module name
    # "python-sql-injection-concat" -> RsolvApi.Security.Patterns.Python.SqlInjectionConcat
    parts = String.split(pattern_id, "-")
    
    # First part is the language - handle special cases
    language = case Enum.at(parts, 0) do
      "js" -> "Javascript"
      "ts" -> "Typescript"
      lang -> Macro.camelize(lang)
    end
    
    # Rest is the pattern name
    pattern_name = parts
    |> Enum.drop(1)
    |> Enum.map(&Macro.camelize/1)
    |> Enum.join("")
    
    "RsolvApi.Security.Patterns.#{language}.#{pattern_name}"
  end
end