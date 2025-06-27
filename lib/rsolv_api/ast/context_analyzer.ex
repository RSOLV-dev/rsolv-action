defmodule RsolvApi.AST.ContextAnalyzer do
  @moduledoc """
  Analyzes code context to improve pattern matching accuracy.
  
  This module provides context-aware analysis for:
  - Path exclusion rules (test files, vendor code, etc.)
  - Framework detection (Rails, Django, Express, etc.)
  - Security pattern evaluation
  - Dynamic confidence scoring based on context
  """
  
  @cache_table :context_analyzer_cache
  @cache_ttl :timer.minutes(5)
  
  # Initialize cache on module load
  def __after_compile__(_env, _bytecode) do
    init_cache()
  end
  
  defp init_cache do
    if :ets.whereis(@cache_table) == :undefined do
      :ets.new(@cache_table, [:set, :public, :named_table, {:read_concurrency, true}])
    end
  end
  
  # Path context struct
  defmodule PathContext do
    defstruct [
      :path,
      :is_test_file,
      :is_example_file,
      :is_vendor_file,
      :should_skip,
      :confidence_multiplier,
      :file_type
    ]
  end
  
  # Code context struct
  defmodule CodeContext do
    defstruct [
      :language,
      :framework,
      :uses_orm,
      :orm_type,
      :uses_prepared_statements,
      :sql_safety_score,
      :has_imports,
      :imported_modules
    ]
  end
  
  # Security context struct
  defmodule SecurityContext do
    defstruct [
      :pattern_type,
      :has_input_validation,
      :uses_safe_patterns,
      :has_dangerous_operations,
      :user_input_handling,
      :overall_safety_score,
      :location_confidence_multiplier,
      :context_factors
    ]
  end
  
  @doc """
  Analyzes a file path to determine its context and whether it should be analyzed.
  """
  def analyze_path(path, options \\ %{}) do
    # Ensure cache is initialized
    init_cache()
    
    # Check cache
    cache_key = {:path, path, :erlang.phash2(options)}
    
    case lookup_cache(cache_key) do
      {:ok, result} -> result
      :miss ->
        result = do_analyze_path(path, options)
        cache_result(cache_key, result)
        result
    end
  end
  
  @doc """
  Analyzes code content to detect framework usage and patterns.
  """
  def analyze_code(code, language, metadata) do
    path = metadata[:path] || ""
    
    # Get path context first (not used in code analysis, but could be in future)
    _path_context = analyze_path(path)
    
    # Analyze code patterns
    framework = detect_framework(code, language)
    orm_info = detect_orm_usage(code, language, framework)
    safety_info = analyze_sql_safety(code, language)
    
    %CodeContext{
      language: language,
      framework: framework,
      uses_orm: orm_info.uses_orm,
      orm_type: orm_info.orm_type,
      uses_prepared_statements: safety_info.uses_prepared_statements,
      sql_safety_score: calculate_sql_safety_score(safety_info, orm_info),
      has_imports: detect_imports(code, language),
      imported_modules: extract_imports(code, language)
    }
  end
  
  @doc """
  Evaluates security context for a given code snippet and pattern type.
  """
  def evaluate_security_context(code, language, metadata) do
    pattern_type = metadata[:pattern_type]
    path = metadata[:path] || ""
    
    # Get path context
    path_context = analyze_path(path)
    
    # Analyze security patterns
    input_validation = has_input_validation?(code, language)
    safe_patterns = uses_safe_patterns?(code, language, pattern_type)
    dangerous_ops = has_dangerous_operations?(code, language, pattern_type)
    input_handling = analyze_user_input_handling(code, language)
    
    # Calculate safety score
    safety_score = calculate_safety_score(%{
      has_validation: input_validation,
      uses_safe_patterns: safe_patterns,
      has_dangerous_ops: dangerous_ops,
      input_handling: input_handling,
      path_context: path_context
    })
    
    %SecurityContext{
      pattern_type: pattern_type,
      has_input_validation: input_validation,
      uses_safe_patterns: safe_patterns,
      has_dangerous_operations: dangerous_ops,
      user_input_handling: input_handling,
      overall_safety_score: safety_score,
      location_confidence_multiplier: path_context.confidence_multiplier,
      context_factors: %{
        path_type: determine_path_type(path),
        language: language
      }
    }
  end
  
  # Private functions
  
  defp do_analyze_path(path, options) do
    is_test = is_test_file?(path)
    is_example = is_example_file?(path)
    is_vendor = is_vendor_file?(path)
    
    # Apply strict mode if requested
    strict_mode = Map.get(options, :strict_mode, false)
    
    confidence_multiplier = cond do
      is_test && strict_mode -> 0.1  # Even lower in strict mode
      is_test -> 0.3
      is_example && strict_mode -> 0.3  # Lower in strict mode
      is_example -> 0.5
      is_vendor -> 0.0
      true -> 1.0
    end
    
    %PathContext{
      path: path,
      is_test_file: is_test,
      is_example_file: is_example,
      is_vendor_file: is_vendor,
      should_skip: is_vendor || (strict_mode && (is_test || is_example)),
      confidence_multiplier: confidence_multiplier,
      file_type: determine_file_type(path)
    }
  end
  
  defp is_test_file?(path) do
    test_patterns = [
      ~r/test\//,
      ~r/spec\//,
      ~r/__tests__\//,
      ~r/_test\./,
      ~r/\.test\./,
      ~r/\.spec\./,
      ~r/test_.*\./
    ]
    
    Enum.any?(test_patterns, &Regex.match?(&1, path))
  end
  
  defp is_example_file?(path) do
    example_patterns = [
      ~r/examples?\//,
      ~r/demos?\//,
      ~r/samples?\//,
      ~r/tutorial\//,
      ~r/sample_/
    ]
    
    Enum.any?(example_patterns, &Regex.match?(&1, path))
  end
  
  defp is_vendor_file?(path) do
    vendor_patterns = [
      ~r/vendor\//,
      ~r/node_modules\//,
      ~r/third_party\//,
      ~r/bower_components\//,
      ~r/packages\//,
      ~r/\.bundle\//
    ]
    
    Enum.any?(vendor_patterns, &Regex.match?(&1, path))
  end
  
  defp determine_file_type(path) do
    cond do
      is_test_file?(path) -> :test
      is_example_file?(path) -> :example
      is_vendor_file?(path) -> :vendor
      true -> :production
    end
  end
  
  defp determine_path_type(path) do
    case determine_file_type(path) do
      :test -> :test
      :example -> :example
      :vendor -> :vendor
      _ -> :production
    end
  end
  
  defp detect_framework(code, language) do
    case language do
      "ruby" ->
        cond do
          code =~ ~r/class\s+\w+\s*<\s*ApplicationRecord/ -> "rails"
          code =~ ~r/class\s+\w+\s*<\s*ActiveRecord::Base/ -> "rails"
          code =~ ~r/require\s+['"]sinatra/ -> "sinatra"
          true -> nil
        end
        
      "python" ->
        cond do
          code =~ ~r/from\s+django/ || code =~ ~r/import\s+django/ -> "django"
          code =~ ~r/from\s+flask/ || code =~ ~r/import\s+flask/ -> "flask"
          code =~ ~r/from\s+fastapi/ || code =~ ~r/import\s+fastapi/ -> "fastapi"
          true -> nil
        end
        
      "javascript" ->
        cond do
          code =~ ~r/require\s*\(\s*['"]express['"]/ || code =~ ~r/from\s+['"]express['"]/ -> "express"
          code =~ ~r/require\s*\(\s*['"]koa['"]/ || code =~ ~r/from\s+['"]koa['"]/ -> "koa"
          code =~ ~r/require\s*\(\s*['"]fastify['"]/ || code =~ ~r/from\s+['"]fastify['"]/ -> "fastify"
          true -> nil
        end
        
      _ -> nil
    end
  end
  
  defp detect_orm_usage(code, language, framework) do
    case {language, framework} do
      {"ruby", "rails"} ->
        %{uses_orm: true, orm_type: "activerecord"}
        
      {"python", "django"} ->
        if code =~ ~r/models\.Model/ do
          %{uses_orm: true, orm_type: "django_orm"}
        else
          %{uses_orm: false, orm_type: nil}
        end
        
      _ ->
        %{uses_orm: false, orm_type: nil}
    end
  end
  
  defp analyze_sql_safety(code, language) do
    prepared_statements = case language do
      "java" ->
        code =~ ~r/PreparedStatement/ || code =~ ~r/\.prepare\(/
        
      "python" ->
        code =~ ~r/execute\s*\([^,]+,\s*[(\[]/ || code =~ ~r/executemany/
        
      "php" ->
        code =~ ~r/prepare\s*\(/ || code =~ ~r/bind_param/
        
      _ ->
        false
    end
    
    %{
      uses_prepared_statements: prepared_statements,
      has_string_concatenation: code =~ ~r/['"]\s*\+\s*\w+/ || code =~ ~r/\$\{/,
      has_parameterized_queries: code =~ ~r/\?\s*[,)]/ || code =~ ~r/%s/
    }
  end
  
  defp calculate_sql_safety_score(safety_info, orm_info) do
    base_score = 0.5
    
    score = base_score
    score = if safety_info.uses_prepared_statements, do: score + 0.35, else: score
    score = if orm_info.uses_orm, do: score + 0.2, else: score
    score = if safety_info.has_string_concatenation, do: score - 0.3, else: score
    score = if safety_info.has_parameterized_queries, do: score + 0.2, else: score
    
    max(0.0, min(1.0, score))
  end
  
  defp detect_imports(code, _language) do
    code =~ ~r/import\s+/ || code =~ ~r/require\s*\(/ || code =~ ~r/from\s+\w+\s+import/
  end
  
  defp extract_imports(code, language) do
    case language do
      "python" ->
        import_regex = ~r/(?:from\s+([\w.]+)\s+)?import\s+([\w.,\s*]+)/
        Regex.scan(import_regex, code)
        |> Enum.map(fn
          [_, "", modules] -> String.split(modules, ~r/,\s*/)
          [_, from_module, _] -> [from_module]
        end)
        |> List.flatten()
        
      "javascript" ->
        import_regex = ~r/(?:import|require)\s*\(?\s*['"]([^'"]+)['"]/
        Regex.scan(import_regex, code, capture: :all_but_first)
        |> List.flatten()
        
      _ ->
        []
    end
  end
  
  defp has_input_validation?(code, _language) do
    validation_patterns = [
      ~r/\.match\?\s*\(/,          # Ruby match?
      ~r/\.test\s*\(/,            # JavaScript test
      ~r/re\.match\s*\(/,         # Python regex
      ~r/preg_match\s*\(/,        # PHP
      ~r/Pattern\.matches\s*\(/,   # Java
      ~r/regexp\.MatchString\s*\(/ # Go
    ]
    
    Enum.any?(validation_patterns, &Regex.match?(&1, code))
  end
  
  defp uses_safe_patterns?(code, _language, pattern_type) do
    case pattern_type do
      :sql_injection ->
        # Check for parameterized queries
        code =~ ~r/where\s*\(\s*\w+:\s*\w+/ ||  # Rails style
        code =~ ~r/\?\s*[,)]/ ||                 # Placeholder style
        code =~ ~r/%s/ ||                        # Python style
        code =~ ~r/:\w+/                         # Named parameters
        
      :command_injection ->
        # Check for safe subprocess usage
        code =~ ~r/shell\s*=\s*False/ ||         # Python
        code =~ ~r/\[\s*['"]/ ||                 # Array style commands
        !String.contains?(code, "+")              # No concatenation
        
      :code_injection ->
        # Check if eval is not used with user input
        !(code =~ ~r/eval\s*\(/ && code =~ ~r/user_input/)
        
      _ ->
        false
    end
  end
  
  defp has_dangerous_operations?(code, _language, pattern_type) do
    case pattern_type do
      :command_injection ->
        code =~ ~r/exec\s*\(/ || code =~ ~r/system\s*\(/ || code =~ ~r/spawn/
        
      :code_injection ->
        code =~ ~r/eval\s*\(/
        
      :sql_injection ->
        code =~ ~r/execute\s*\(.*\+/ || code =~ ~r/query\s*\(.*\+/
        
      _ ->
        false
    end
  end
  
  defp analyze_user_input_handling(code, _language) do
    cond do
      code =~ ~r/\+\s*user_input/ || code =~ ~r/user_input\s*\+/ ->
        :direct_concatenation
        
      code =~ ~r/\$\{.*user/ ->
        :template_interpolation
        
      code =~ ~r/sanitize|escape|clean/ ->
        :sanitized
        
      true ->
        :unknown
    end
  end
  
  defp calculate_safety_score(factors) do
    base_score = 0.5
    
    score = base_score
    score = if factors.has_validation, do: score + 0.2, else: score
    score = if factors.uses_safe_patterns, do: score + 0.3, else: score
    score = if factors.has_dangerous_ops, do: score - 0.4, else: score
    
    score = case factors.input_handling do
      :direct_concatenation -> score - 0.3
      :template_interpolation -> score - 0.2
      :sanitized -> score + 0.2
      _ -> score
    end
    
    # Apply path context multiplier
    score = score * factors.path_context.confidence_multiplier
    
    max(0.0, min(1.0, score))
  end
  
  # Cache helpers
  
  defp lookup_cache(key) do
    case :ets.lookup(@cache_table, key) do
      [{^key, {result, expiry}}] ->
        if expiry > System.monotonic_time(:millisecond) do
          {:ok, result}
        else
          :ets.delete(@cache_table, key)
          :miss
        end
      _ ->
        :miss
    end
  end
  
  defp cache_result(key, result) do
    expiry = System.monotonic_time(:millisecond) + @cache_ttl
    :ets.insert(@cache_table, {key, {result, expiry}})
    :ok
  end
end