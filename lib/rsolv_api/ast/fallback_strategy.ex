defmodule RsolvApi.AST.FallbackStrategy do
  @moduledoc """
  Provides fallback analysis when AST parsing fails.
  
  This module implements a robust fallback strategy for code analysis
  when AST parsing is unavailable due to syntax errors, timeouts, or
  parser crashes. It uses pattern matching and heuristics to provide
  security analysis with reduced confidence levels.
  """
  
  alias RsolvApi.AST.{ParserRegistry, ASTNormalizer}
  
  @cache_table :fallback_analysis_cache
  @cache_ttl :timer.minutes(15)
  
  # Initialize cache on module load
  def __after_compile__(_env, _bytecode) do
    init_cache()
  end
  
  defp init_cache do
    if :ets.whereis(@cache_table) == :undefined do
      :ets.new(@cache_table, [:set, :public, :named_table, {:read_concurrency, true}])
    end
  end
  
  # Result struct for fallback analysis
  defmodule AnalysisResult do
    @enforce_keys [:strategy, :ast_available]
    defstruct [
      :strategy,           # :ast or :fallback
      :ast_available,      # boolean
      :ast,               # normalized AST if available
      :error,             # standardized error if AST failed
      :fallback_analysis, # fallback analysis results
      :timing            # performance metrics
    ]
  end
  
  # Fallback analysis structure
  defmodule FallbackAnalysis do
    @enforce_keys [:structure, :metrics, :patterns_detected, :confidence]
    defstruct [
      :structure,           # code structure analysis
      :metrics,            # code metrics
      :patterns_detected,  # security patterns found
      :confidence,         # overall confidence score
      :partial_ast_available, # whether partial AST was recovered
      :parsed_sections,    # number of sections parsed
      :recommendations,    # security recommendations
      :analysis_warnings   # warnings during analysis
    ]
  end
  
  # Pattern detection result
  defmodule Pattern do
    @enforce_keys [:type, :confidence]
    defstruct [
      :type,
      :confidence,
      :line,
      :description,
      :metadata
    ]
  end
  
  # Code structure information
  defmodule Structure do
    defstruct [
      has_functions: false,
      has_variables: false,
      has_classes: false,
      has_imports: false,
      has_exports: false,
      complexity_estimate: 0
    ]
  end
  
  # Code metrics
  defmodule Metrics do
    defstruct [
      line_count: 0,
      char_count: 0,
      token_count: 0,
      comment_lines: 0,
      blank_lines: 0
    ]
  end
  
  @doc """
  Analyzes code with automatic fallback to pattern-based analysis
  when AST parsing fails.
  """
  def analyze_with_fallback(session_id, customer_id, language, code, options \\ %{}) do
    # Ensure cache is initialized
    init_cache()
    
    start_time = System.monotonic_time(:millisecond)
    
    # Check cache first if code is not nil
    cache_key = if code, do: {:fallback, language, :erlang.phash2(code)}, else: nil
    
    case check_cache(cache_key) do
      {:ok, cached_result} ->
        # Return cached result with updated timing
        total_time = System.monotonic_time(:millisecond) - start_time
        updated_timing = Map.merge(cached_result.timing, %{
          cache_hit: true,
          total_ms: total_time
        })
        {:ok, %{cached_result | timing: updated_timing}}
        
      :miss ->
        # Continue with normal analysis
        analyze_without_cache(session_id, customer_id, language, code, options, start_time, cache_key)
    end
  end
  
  defp check_cache(nil), do: :miss
  defp check_cache(cache_key) do
    case :ets.lookup(@cache_table, cache_key) do
      [{^cache_key, {result, expiry}}] ->
        if expiry > System.monotonic_time(:millisecond) do
          {:ok, result}
        else
          # Expired, remove from cache
          :ets.delete(@cache_table, cache_key)
          :miss
        end
      _ ->
        :miss
    end
  end
  
  defp analyze_without_cache(session_id, customer_id, language, code, options, start_time, cache_key) do
    
    # Check if fallback is disabled
    if options[:fallback_enabled] == false do
      case ParserRegistry.parse_code(session_id, customer_id, language, code) do
        {:ok, result} when result.error != nil ->
          {:error, result.error}
        {:ok, result} ->
          {:ok, build_ast_result(result, start_time)}
        {:error, error} ->
          {:error, error}
      end
    else
      # Try AST parsing first
      ast_start = System.monotonic_time(:millisecond)
      
      case try_ast_parsing(session_id, customer_id, language, code, options) do
        {:ok, ast_result} ->
          # AST parsing succeeded
          {:ok, build_ast_result(ast_result, start_time)}
          
        {:error, error} ->
          # Check if this is an error that should bypass fallback
          if should_bypass_fallback?(error) do
            {:error, error}
          else
            # AST parsing failed, use fallback
            ast_attempt_time = System.monotonic_time(:millisecond) - ast_start
            
            fallback_start = System.monotonic_time(:millisecond)
            fallback_analysis = perform_fallback_analysis(language, code, error, options)
            fallback_time = System.monotonic_time(:millisecond) - fallback_start
            
            total_time = System.monotonic_time(:millisecond) - start_time
            
            result = %AnalysisResult{
              strategy: :fallback,
              ast_available: false,
              ast: nil,
              error: error,
              fallback_analysis: fallback_analysis,
              timing: %{
                ast_attempt_ms: ast_attempt_time,
                fallback_analysis_ms: fallback_time,
                total_ms: total_time,
                cache_hit: false
              }
            }
            
            # Cache the result if we have a cache key
            if cache_key do
              expiry = System.monotonic_time(:millisecond) + @cache_ttl
              :ets.insert(@cache_table, {cache_key, {result, expiry}})
            end
            
            {:ok, result}
          end
      end
    end
  end
  
  # Private functions
  
  defp try_ast_parsing(session_id, customer_id, language, code, _options) do
    # Handle nil/empty code
    if is_nil(code) or code == "" do
      {:error, %{
        type: :empty_input,
        message: "Empty or nil code provided",
        language: language,
        severity: :low,
        recoverable: true
      }}
    else
      case ParserRegistry.parse_code(session_id, customer_id, language, code) do
        {:ok, result} when result.error != nil ->
          # Parsing failed with error
          {:error, result.error}
          
        {:ok, result} when result.ast != nil ->
          # Parsing succeeded
          case ASTNormalizer.normalize_ast(result.ast, language) do
            {:ok, normalized_ast} ->
              {:ok, Map.put(result, :ast, normalized_ast)}
            {:error, _} ->
              # Normalization failed, treat as parse error
              {:error, %{
                type: :normalization_failed,
                message: "Failed to normalize AST",
                language: language,
                severity: :medium,
                recoverable: true
              }}
          end
          
        {:ok, _result} ->
          # Parser returned success but no AST (empty or unparseable code)
          {:error, %{
            type: :empty_ast,
            message: "Parser returned no AST",
            language: language,
            severity: :low,
            recoverable: true
          }}
          
        {:error, error} when is_atom(error) ->
          # Handle atom errors from ParserRegistry
          {:error, %{
            type: error,
            message: "Parser error: #{error}",
            language: language,
            severity: :medium,
            recoverable: true
          }}
          
        {:error, error} ->
          {:error, error}
      end
    end
  end
  
  defp build_ast_result(ast_result, start_time) do
    total_time = System.monotonic_time(:millisecond) - start_time
    
    %AnalysisResult{
      strategy: :ast,
      ast_available: true,
      ast: ast_result.ast,
      error: nil,
      fallback_analysis: nil,
      timing: %{
        ast_attempt_ms: ast_result.timing.parse_time_ms,
        fallback_analysis_ms: 0,
        total_ms: total_time,
        cache_hit: false
      }
    }
  end
  
  defp perform_fallback_analysis(language, code, error, options) do
    # Handle nil/empty code
    if is_nil(code) or code == "" do
      %FallbackAnalysis{
        structure: %Structure{},
        metrics: %Metrics{},
        patterns_detected: [],
        confidence: 0.0,
        partial_ast_available: false,
        parsed_sections: 0,
        recommendations: [],
        analysis_warnings: ["Empty code provided"]
      }
    else
      # Analyze code structure
      structure = analyze_structure(code, language)
      
      # Calculate metrics
      metrics = calculate_metrics(code)
      
      # Detect security patterns
      depth = options[:analysis_depth] || :standard
      patterns = detect_patterns(code, language, depth)
      
      # Generate recommendations
      recommendations = generate_recommendations(patterns, language)
      
      # Calculate confidence based on error type and code complexity
      confidence = calculate_confidence(error, metrics, structure)
      
      # Check for partial AST availability
      {partial_ast, parsed_sections} = check_partial_ast(code, language)
      
      # Detect analysis warnings
      warnings = detect_warnings(code, metrics)
      
      %FallbackAnalysis{
        structure: structure,
        metrics: metrics,
        patterns_detected: patterns,
        confidence: confidence,
        partial_ast_available: partial_ast,
        parsed_sections: parsed_sections,
        recommendations: recommendations,
        analysis_warnings: warnings
      }
    end
  end
  
  defp analyze_structure(code, language) do
    %Structure{
      has_functions: has_functions?(code, language),
      has_variables: has_variables?(code, language),
      has_classes: has_classes?(code, language),
      has_imports: has_imports?(code, language),
      has_exports: has_exports?(code, language),
      complexity_estimate: estimate_complexity(code)
    }
  end
  
  defp has_functions?(code, language) do
    case language do
      lang when lang in ["javascript", "typescript"] ->
        code =~ ~r/function\s+\w+|const\s+\w+\s*=\s*\(|=>\s*\{/
      "python" ->
        code =~ ~r/def\s+\w+/
      "ruby" ->
        code =~ ~r/def\s+\w+/
      "php" ->
        code =~ ~r/function\s+\w+/
      "java" ->
        code =~ ~r/(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\(/
      "go" ->
        code =~ ~r/func\s+\w+/
      _ ->
        false
    end
  end
  
  defp has_variables?(code, language) do
    case language do
      lang when lang in ["javascript", "typescript"] ->
        code =~ ~r/const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=/
      "python" ->
        code =~ ~r/\w+\s*=\s*[^=]/
      "ruby" ->
        code =~ ~r/@\w+\s*=|\w+\s*=\s*[^=]/
      "php" ->
        code =~ ~r/\$\w+\s*=/
      "java" ->
        code =~ ~r/(int|String|boolean|double|float|char|long)\s+\w+\s*=/
      "go" ->
        code =~ ~r/var\s+\w+|:=/
      _ ->
        false
    end
  end
  
  defp has_classes?(code, language) do
    case language do
      lang when lang in ["javascript", "typescript"] ->
        code =~ ~r/class\s+\w+/
      "python" ->
        code =~ ~r/class\s+\w+/
      "ruby" ->
        code =~ ~r/class\s+\w+/
      "php" ->
        code =~ ~r/class\s+\w+/
      "java" ->
        code =~ ~r/class\s+\w+/
      "go" ->
        code =~ ~r/type\s+\w+\s+struct/
      _ ->
        false
    end
  end
  
  defp has_imports?(code, language) do
    case language do
      lang when lang in ["javascript", "typescript"] ->
        code =~ ~r/import\s+.+from|require\s*\(/
      "python" ->
        code =~ ~r/import\s+\w+|from\s+\w+\s+import/
      "ruby" ->
        code =~ ~r/require\s+['"]|require_relative\s+['"]|include\s+\w+/
      "php" ->
        code =~ ~r/require\s+['"]|include\s+['"]|use\s+\w+/
      "java" ->
        code =~ ~r/import\s+[\w.]+;/
      "go" ->
        code =~ ~r/import\s+\(|import\s+"/
      _ ->
        false
    end
  end
  
  defp has_exports?(code, language) do
    case language do
      lang when lang in ["javascript", "typescript"] ->
        code =~ ~r/export\s+(default\s+)?|module\.exports\s*=/
      "python" ->
        code =~ ~r/__all__\s*=/
      "ruby" ->
        code =~ ~r/module\s+\w+/
      _ ->
        false
    end
  end
  
  defp estimate_complexity(code) do
    # Simple complexity estimation based on various factors
    factors = [
      {~r/if\s*\(|elif\s+|else\s*{/, 1},      # Conditionals
      {~r/for\s*\(|while\s*\(|\.forEach/, 2}, # Loops
      {~r/try\s*{|catch\s*\(/, 2},            # Error handling
      {~r/function|def\s+|func\s+/, 1},       # Functions
      {~r/class\s+\w+/, 3},                   # Classes
      {~r/\|\||&&/, 1},                       # Logical operators
      {~r/\?.*:/, 1}                          # Ternary operators
    ]
    
    Enum.reduce(factors, 0, fn {pattern, weight}, acc ->
      matches = Regex.scan(pattern, code)
      acc + (length(matches) * weight)
    end)
  end
  
  defp calculate_metrics(code) do
    lines = String.split(code, "\n")
    # Remove empty trailing line if code ends with newline
    lines = if List.last(lines) == "" and length(lines) > 1 do
      List.delete_at(lines, -1)
    else
      lines
    end
    
    %Metrics{
      line_count: length(lines),
      char_count: String.length(code),
      token_count: estimate_token_count(code),
      comment_lines: count_comment_lines(lines),
      blank_lines: count_blank_lines(lines)
    }
  end
  
  defp estimate_token_count(code) do
    # Simple token estimation
    code
    |> String.split(~r/\s+|[;,\(\)\{\}\[\]]/)
    |> Enum.reject(&(&1 == ""))
    |> length()
  end
  
  defp count_comment_lines(lines) do
    Enum.count(lines, fn line ->
      trimmed = String.trim(line)
      String.starts_with?(trimmed, "//") or
      String.starts_with?(trimmed, "#") or
      String.starts_with?(trimmed, "/*") or
      String.starts_with?(trimmed, "*")
    end)
  end
  
  defp count_blank_lines(lines) do
    Enum.count(lines, &(String.trim(&1) == ""))
  end
  
  defp detect_patterns(code, language, depth) do
    patterns = []
    
    # SQL Injection patterns
    patterns = patterns ++ detect_sql_injection(code, language)
    
    # Command Injection patterns
    patterns = patterns ++ detect_command_injection(code, language)
    
    # Eval/Code Injection patterns
    patterns = patterns ++ detect_code_injection(code, language)
    
    # XSS patterns
    patterns = patterns ++ detect_xss(code, language)
    
    # Weak Cryptography patterns
    patterns = patterns ++ detect_weak_crypto(code, language)
    
    # Hard-coded secrets
    patterns = patterns ++ detect_hardcoded_secrets(code, language)
    
    # Deep analysis adds more patterns
    patterns = if depth == :deep do
      patterns ++ detect_advanced_patterns(code, language)
    else
      patterns
    end
    
    # Sort by confidence and deduplicate
    patterns
    |> Enum.sort_by(& &1.confidence, :desc)
    |> Enum.uniq_by(& {&1.type, &1.line})
  end
  
  defp detect_sql_injection(code, _language) do
    patterns = [
      {~r/SELECT.*FROM.*WHERE.*\+\s*\w+/, 0.8, "SQL injection via string concatenation"},
      {~r/SELECT.*FROM.*WHERE.*\$\{/, 0.8, "SQL injection via template literal"},
      {~r/SELECT.*FROM.*WHERE.*\.\s*\$/, 0.8, "SQL injection via PHP concatenation"},
      {~r/query\s*\(\s*["'].*\+.*["']\s*\)/, 0.7, "Potential SQL injection in query"},
      {~r/execute\s*\(\s*["'].*\+.*["']\s*\)/, 0.7, "Potential SQL injection in execute"},
      {~r/mysql_query\s*\(/, 0.7, "Potential SQL injection in mysql_query"}
    ]
    
    find_patterns(code, patterns, "sql_injection")
  end
  
  defp detect_command_injection(code, language) do
    patterns = case language do
      "python" ->
        [
          {~r/os\.system\s*\([^)]*\+/, 0.85, "Command injection via os.system"},
          {~r/subprocess\.\w+\s*\([^)]*shell=True/, 0.8, "Command injection with shell=True"}
        ]
      "ruby" ->
        [
          {~r/system\s*\(.*\+/, 0.85, "Command injection via system"},
          {~r/`[^`]*#\{/, 0.85, "Command injection via backticks"}
        ]
      "javascript" ->
        [
          {~r/exec\s*\([^)]*/, 0.85, "Command injection via exec"},
          {~r/spawn\s*\(/, 0.8, "Command injection via spawn"}
        ]
      _ ->
        [
          {~r/exec\w*\s*\([^)]*\+/, 0.7, "Potential command injection"},
          {~r/system\s*\([^)]*\+/, 0.7, "Potential command injection"}
        ]
    end
    
    find_patterns(code, patterns, "command_injection")
  end
  
  defp detect_code_injection(code, _language) do
    patterns = [
      {~r/eval\s*\(/, 0.9, "Code injection via eval"},
      {~r/new\s+Function\s*\([^)]*\w+/, 0.85, "Code injection via Function constructor"}
    ]
    
    find_patterns(code, patterns, "code_injection")
  end
  
  defp detect_xss(code, _language) do
    patterns = [
      {~r/innerHTML\s*=\s*[^"']/, 0.8, "XSS via innerHTML"},
      {~r/document\.write\s*\(\s*\w+/, 0.8, "XSS via document.write"},
      {~r/\$\(.*\)\.html\s*\(\s*\w+/, 0.75, "XSS via jQuery html()"}
    ]
    
    find_patterns(code, patterns, "xss")
  end
  
  defp detect_weak_crypto(code, _language) do
    patterns = [
      {~r/randomBytes\s*\(\s*(\d+)\s*\)/, 0.0, "Cryptographic key generation"},
      {~r/MD5|SHA1(?!\d)/, 0.8, "Weak hash algorithm"},
      {~r/DES(?!3)|RC4/, 0.8, "Weak encryption algorithm"}
    ]
    
    # Special handling for randomBytes to check key size
    weak_key_results = Regex.scan(~r/randomBytes\s*\(\s*(\d+)\s*\)/, code, capture: :all_but_first)
    |> Enum.flat_map(fn [size_str] ->
      size = String.to_integer(size_str)
      if size < 16 do
        [%Pattern{
          type: "weak_cryptography",
          confidence: 0.8,
          description: "Weak key size: #{size} bytes",
          metadata: %{key_size: size}
        }]
      else
        []
      end
    end)
    
    weak_key_results ++ find_patterns(code, Enum.reject(patterns, fn {p, _, _} -> p == ~r/randomBytes\s*\(\s*(\d+)\s*\)/ end), "weak_cryptography")
  end
  
  defp detect_hardcoded_secrets(code, _language) do
    patterns = [
      {~r/password\s*=\s*["'][^"']+["']/, 0.7, "Hardcoded password"},
      {~r/api[_-]?key\s*=\s*["'][^"']+["']/, 0.8, "Hardcoded API key"},
      {~r/secret\s*=\s*["'][^"']+["']/, 0.7, "Hardcoded secret"}
    ]
    
    find_patterns(code, patterns, "hardcoded_secrets")
  end
  
  defp detect_advanced_patterns(_code, _language) do
    # Additional patterns for deep analysis
    []
  end
  
  defp find_patterns(code, pattern_list, pattern_type) do
    pattern_list
    |> Enum.flat_map(fn {regex, confidence, description} ->
      Regex.scan(regex, code, return: :index)
      |> Enum.map(fn [{start_idx, _length}] ->
        line_number = get_line_number(code, start_idx)
        
        %Pattern{
          type: pattern_type,
          confidence: confidence,
          line: line_number,
          description: description,
          metadata: %{}
        }
      end)
    end)
  end
  
  defp get_line_number(code, char_index) do
    code
    |> String.slice(0, char_index)
    |> String.split("\n")
    |> length()
  end
  
  defp generate_recommendations(patterns, _language) do
    recommendations = []
    
    # Group patterns by type
    grouped = Enum.group_by(patterns, & &1.type)
    
    # SQL Injection recommendations
    recommendations = if grouped["sql_injection"] do
      ["Use parameterized queries or prepared statements instead of string concatenation" | recommendations]
    else
      recommendations
    end
    
    # Command Injection recommendations  
    recommendations = if grouped["command_injection"] do
      ["Sanitize user input and avoid shell execution with user-controlled data" | recommendations]
    else
      recommendations
    end
    
    # Code Injection recommendations
    recommendations = if grouped["code_injection"] do
      ["Avoid using eval() or similar dynamic code execution with user input" | recommendations]
    else
      recommendations
    end
    
    # Check for exec patterns separately
    recommendations = if Enum.any?(patterns, fn p -> 
      p.description =~ "exec" or (p.type == "command_injection" and patterns |> Enum.any?(fn pp -> pp.description =~ "exec" end))
    end) do
      ["Avoid using exec() with user-controlled input" | recommendations]
    else
      recommendations
    end
    
    # XSS recommendations
    recommendations = if grouped["xss"] do
      ["Use proper output encoding and avoid direct HTML injection" | recommendations]
    else
      recommendations
    end
    
    # Weak Crypto recommendations
    recommendations = if grouped["weak_cryptography"] do
      ["Use strong cryptographic algorithms and adequate key sizes (>= 128 bits)" | recommendations]
    else
      recommendations
    end
    
    # Hardcoded Secrets recommendations
    recommendations = if grouped["hardcoded_secrets"] do
      ["Store secrets in environment variables or secure vaults, not in code" | recommendations]
    else
      recommendations
    end
    
    recommendations
  end
  
  defp calculate_confidence(error, metrics, structure) do
    # Base confidence depends on error type
    error_type = Map.get(error, :type)
    
    base_confidence = case error_type do
      :syntax_error -> 0.6
      :timeout -> 0.4  # Lower confidence for timeouts
      :parser_crash -> 0.3
      :empty_input -> 0.0
      _ -> 0.4
    end
    
    # Adjust based on code complexity
    complexity_factor = cond do
      structure.complexity_estimate > 50 -> -0.2
      structure.complexity_estimate > 20 -> -0.1
      structure.complexity_estimate < 5 -> 0.1
      true -> 0.0
    end
    
    # Adjust based on code size
    size_factor = cond do
      metrics.line_count > 1000 -> -0.2
      metrics.line_count > 500 -> -0.1
      metrics.line_count < 50 -> 0.1
      true -> 0.0
    end
    
    # Calculate final confidence
    # For timeout errors, don't add positive adjustments
    confidence = if error_type == :timeout do
      base_confidence + min(0, complexity_factor) + min(0, size_factor)
    else
      base_confidence + complexity_factor + size_factor
    end
    
    # Ensure confidence is between 0 and 1
    max(0.0, min(1.0, confidence))
  end
  
  defp check_partial_ast(code, language) do
    # Try to identify parseable sections
    sections = identify_sections(code, language)
    
    parseable_count = Enum.count(sections, fn section ->
      # Simple heuristic: section is parseable if it has balanced brackets
      balanced_brackets?(section)
    end)
    
    {parseable_count > 0, parseable_count}
  end
  
  defp identify_sections(code, language) do
    # Split code into logical sections (functions, classes, etc.)
    case language do
      lang when lang in ["javascript", "typescript"] ->
        Regex.split(~r/(?=function\s+\w+|class\s+\w+|const\s+\w+\s*=)/, code)
      "python" ->
        Regex.split(~r/(?=def\s+\w+|class\s+\w+)/, code)
      "ruby" ->
        Regex.split(~r/(?=def\s+\w+|class\s+\w+|module\s+\w+)/, code)
      _ ->
        [code]
    end
    |> Enum.reject(&(String.trim(&1) == ""))
  end
  
  defp balanced_brackets?(code) do
    # Simple bracket balance check
    chars = String.graphemes(code)
    
    {_, balanced} = Enum.reduce(chars, {[], true}, fn char, {stack, balanced} ->
      cond do
        not balanced -> {stack, false}
        char in ["(", "[", "{"] -> {[char | stack], true}
        char == ")" -> check_closing(stack, "(", balanced)
        char == "]" -> check_closing(stack, "[", balanced)
        char == "}" -> check_closing(stack, "{", balanced)
        true -> {stack, balanced}
      end
    end)
    
    balanced
  end
  
  defp check_closing([], _expected, _balanced), do: {[], false}
  defp check_closing([expected | rest], expected, balanced), do: {rest, balanced}
  defp check_closing([_other | _rest], _expected, _balanced), do: {[], false}
  
  defp should_bypass_fallback?(error) do
    # Some errors should not use fallback
    case Map.get(error, :type) do
      :unsupported_language -> true
      :invalid_session -> true
      _ -> false
    end
  end
  
  defp detect_warnings(code, metrics) do
    warnings = []
    
    # Check for deeply nested structures
    warnings = if String.contains?(code, String.duplicate("(", 100)) do
      ["Deeply nested structure detected" | warnings]
    else
      warnings
    end
    
    # Check for very long lines
    max_line_length = code
    |> String.split("\n")
    |> Enum.map(&String.length/1)
    |> Enum.max(fn -> 0 end)
    
    warnings = if max_line_length > 1000 do
      ["Very long lines detected (>1000 chars)" | warnings]
    else
      warnings
    end
    
    # Check for suspicious patterns
    warnings = if metrics.line_count > 10000 do
      ["Very large file (>10000 lines)" | warnings]
    else
      warnings
    end
    
    warnings
  end
end