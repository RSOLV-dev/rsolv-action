defmodule RsolvWeb.Api.V1.TaintAnalyzer do
  @moduledoc """
  Analyzes code for taint flow from user input to dangerous sinks.
  Part of RFC-042: AST False Positive Reduction Enhancement.
  
  This module traces data flow from user input sources through variables
  to dangerous operations, providing confidence scores based on taint level.
  
  ## Taint Levels
  
  - Level 1: Direct user input (95% confidence)
  - Level 2: Single-hop tainted variable (85% confidence)
  - Level 3: Suspicious variable name or multi-hop (60-75% confidence)
  - Level 4: Unknown source (40% confidence)
  """
  
  # User input patterns for different languages
  @user_input_patterns [
    # JavaScript/Node.js
    ~r/req\.(body|params|query|headers)/,
    ~r/request\.(body|params|query|headers)/,
    # Python/Flask/Django
    ~r/request\.(form|args|values|json|data)/,
    ~r/request\.GET/,
    ~r/request\.POST/,
    # PHP
    ~r/\$_(GET|POST|REQUEST|COOKIE|SERVER)/,
    # Ruby/Rails
    ~r/params\[/
  ]
  
  # Suspicious variable names that suggest user input
  @suspicious_names [
    ~r/^user(Input|Code|Query|Data|Expression)$/,
    ~r/^input(Data)?$/,
    ~r/^untrusted(Data)?$/,
    ~r/^external(Input|Data)$/,
    ~r/^(user|input|data|code|query|expression)$/i
  ]
  
  # Sanitization function patterns
  @sanitization_patterns [
    ~r/sanitize/i,
    ~r/escape/i,
    ~r/validate/i,
    ~r/clean/i,
    ~r/filter/i,
    ~r/purify/i,
    ~r/strip/i,
    # Validation checks
    ~r/isValid/,
    ~r/check[A-Z]/,
    # Common sanitization libraries
    ~r/DOMPurify/,
    ~r/xss/i,
    ~r/htmlspecialchars/,
    ~r/mysql_real_escape_string/
  ]
  
  @doc """
  Analyzes code for taint flow and returns detailed analysis.
  
  ## Examples
  
      iex> TaintAnalyzer.analyze("eval(req.body.code)", "", 1)
      %{
        direct_input: true,
        tainted_flow: false,
        suspicious_name: false,
        has_sanitization: false,
        confidence: 0.95,
        taint_level: 1
      }
  """
  def analyze(code, file_content, line_number) do
    analysis = %{
      direct_input: has_direct_input?(code),
      tainted_flow: false,
      suspicious_name: has_suspicious_name?(code),
      has_sanitization: has_nearby_sanitization?(file_content, line_number)
    }
    
    # Check for tainted flow if not direct input
    analysis = if not analysis.direct_input do
      var_name = extract_variable_name(code)
      if var_name do
        taint_info = trace_taint_flow(var_name, file_content, line_number)
        analysis
        |> Map.put(:tainted_flow, taint_info.is_tainted)
        |> Map.put(:hops, taint_info.hops)
      else
        analysis
      end
    else
      analysis
    end
    
    # Calculate confidence and taint level
    confidence = calculate_confidence(analysis)
    taint_level = determine_taint_level(analysis)
    
    Map.merge(analysis, %{
      confidence: confidence,
      taint_level: taint_level
    })
  end
  
  @doc """
  Checks if code contains direct user input.
  """
  def has_direct_input?(code) do
    Enum.any?(@user_input_patterns, fn pattern ->
      Regex.match?(pattern, code)
    end)
  end
  
  @doc """
  Checks if code contains suspicious variable names.
  """
  def has_suspicious_name?(code) do
    # Extract the variable name from common patterns
    var_name = extract_variable_name(code)
    
    if var_name do
      Enum.any?(@suspicious_names, fn pattern ->
        Regex.match?(pattern, var_name)
      end)
    else
      false
    end
  end
  
  @doc """
  Traces taint flow from a variable back to its source.
  """
  def trace_taint_flow(var_name, file_content, line_number) do
    lines = String.split(file_content, "\n")
    
    # Look backwards from current line to find variable assignment
    preceding_lines = Enum.take(lines, min(line_number, length(lines)))
    
    # Trace the taint through assignment chains
    result = trace_variable_chain(var_name, preceding_lines, 0)
    
    # Check for function parameter taint if not found
    if not result.is_tainted do
      check_function_parameter_taint(var_name, preceding_lines, result.hops)
    else
      result
    end
  end
  
  defp trace_variable_chain(var_name, lines, hop_count) do
    # Find assignment to this variable
    assignment_pattern = ~r/(?:const|let|var|final)?\s*#{Regex.escape(var_name)}\s*=\s*(.+?)(?:;|$)/
    
    # Search backwards through lines
    assignment_line = Enum.find(Enum.reverse(lines), fn line ->
      Regex.match?(assignment_pattern, line)
    end)
    
    if assignment_line do
      case Regex.run(assignment_pattern, assignment_line) do
        [_, value] ->
          value = String.trim(value)
          
          # Check if the assigned value is user input
          if has_direct_input?(value) do
            %{is_tainted: true, source: extract_input_source(value), hops: hop_count}
          else
            # Check if it's assigned from another variable
            next_var = extract_simple_variable(value)
            if next_var && next_var != var_name do
              # Recursively trace the next variable
              trace_variable_chain(next_var, lines, hop_count + 1)
            else
              # Check if it's a function call result that might be tainted
              if String.contains?(value, "(") do
                %{is_tainted: false, source: nil, hops: hop_count}
              else
                %{is_tainted: false, source: nil, hops: hop_count}
              end
            end
          end
        _ ->
          %{is_tainted: false, source: nil, hops: hop_count}
      end
    else
      %{is_tainted: false, source: nil, hops: hop_count}
    end
  end
  
  defp extract_simple_variable(value) do
    # Extract a simple variable name (not function calls)
    case Regex.run(~r/^([a-zA-Z_]\w*)$/, String.trim(value)) do
      [_, var] -> var
      _ -> 
        # Try to extract from simple operations like "transform(data)"
        case Regex.run(~r/\(([a-zA-Z_]\w*)\)/, value) do
          [_, var] -> var
          _ -> nil
        end
    end
  end
  
  defp check_function_parameter_taint(var_name, lines, hops) do
    # Check if this variable is a function parameter
    function_pattern = ~r/function\s+\w*\s*\(.*#{Regex.escape(var_name)}.*\)/
    
    if Enum.any?(lines, fn line -> Regex.match?(function_pattern, line) end) do
      %{is_tainted: true, source: "function_parameter", hops: hops + 1}
    else
      %{is_tainted: false, source: nil, hops: hops}
    end
  end
  
  @doc """
  Checks for sanitization functions near the vulnerable line.
  """
  def has_nearby_sanitization?(file_content, line_number) do
    lines = String.split(file_content, "\n")
    
    # Check 5 lines before and after
    start_line = max(0, line_number - 5)
    end_line = min(length(lines) - 1, line_number + 5)
    
    # Use explicit step when creating range to avoid negative step warning
    nearby_lines = if start_line <= end_line do
      Enum.slice(lines, start_line..end_line//1)
    else
      []
    end
    
    Enum.any?(nearby_lines, fn line ->
      Enum.any?(@sanitization_patterns, fn pattern ->
        Regex.match?(pattern, line)
      end)
    end)
  end
  
  @doc """
  Calculates confidence score based on analysis results.
  """
  def calculate_confidence(analysis) do
    base_confidence = cond do
      analysis[:direct_input] -> 0.95
      analysis[:tainted_flow] -> 
        # Reduce confidence based on hops if available
        if analysis[:hops] && analysis[:hops] > 1 do
          0.75  # Multi-hop taint
        else
          0.85  # Single-hop taint
        end
      analysis[:suspicious_name] -> 0.60
      true -> 0.40
    end
    
    # Reduce confidence if sanitization is detected
    if analysis[:has_sanitization] do
      base_confidence * 0.5
    else
      base_confidence
    end
  end
  
  # Private helper functions
  
  defp determine_taint_level(analysis) do
    cond do
      analysis.direct_input -> 1
      analysis.tainted_flow -> 
        # Check hop count for multi-level taint
        if analysis[:hops] && analysis[:hops] > 1 do
          3  # Multi-hop is level 3
        else
          2  # Single-hop is level 2
        end
      analysis.suspicious_name -> 3
      true -> 4
    end
  end
  
  defp extract_variable_name(code) do
    patterns = [
      ~r/eval\(([a-zA-Z_]\w*)\)/,
      ~r/exec\(([a-zA-Z_]\w*)\)/,
      ~r/innerHTML\s*=\s*([a-zA-Z_]\w*)/,
      ~r/\$where.*\+\s*([a-zA-Z_]\w*)/,
      ~r/query\([^,]+\+\s*([a-zA-Z_]\w*)/,
      # Generic pattern for function calls
      ~r/\(([a-zA-Z_]\w*)\)/
    ]
    
    Enum.find_value(patterns, fn pattern ->
      case Regex.run(pattern, code) do
        [_, var_name] -> var_name
        _ -> nil
      end
    end)
  end
  
  defp extract_input_source(value) do
    case Regex.run(~r/(req\.\w+\.\w+|request\.\w+|\$_\w+)/, value) do
      [_, source] -> source
      _ -> "user_input"
    end
  end
  
end