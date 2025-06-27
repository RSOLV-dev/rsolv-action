defmodule RsolvApi.AST.ASTErrorHandler do
  @moduledoc """
  Standardizes error handling across all AST parsers.
  
  Provides a unified error format and recovery strategies for different
  types of parsing failures across all supported languages.
  """

  @supported_languages ["javascript", "typescript", "python", "ruby", "php", "java", "go"]

  @doc """
  Standardizes error responses from different language parsers into a unified format.
  """
  def standardize_error(error, language, source_code) do
    # For unsupported language errors, ensure the language is available in the error
    enriched_error = if Map.get(error, :type) == :unsupported_language and not Map.has_key?(error, :language) do
      Map.put(error, :language, language)
    else
      error
    end

    standardized = %{
      type: normalize_error_type(enriched_error),
      message: extract_error_message(enriched_error),
      language: language,
      location: extract_location_info(enriched_error),
      source_snippet: extract_source_snippet(source_code, enriched_error),
      severity: nil,
      suggestions: [],
      recoverable: false,
      timestamp: DateTime.utc_now()
    }

    enhanced = standardized
    |> add_language_specific_fields(error, language)
    |> add_severity()
    |> add_recovery_suggestions()
    |> add_recoverability()

    {:error, enhanced}
  end

  @doc """
  Extracts relevant source code snippet around the error location.
  """
  def extract_source_snippet(source, line, column, opts \\ []) do
    context_lines = Keyword.get(opts, :context_lines, 2)
    
    lines = String.split(source, "\n")
    total_lines = length(lines)

    if line < 1 or line > total_lines do
      nil
    else
      start_line = max(1, line - context_lines)
      end_line = min(total_lines, line + context_lines)
      
      relevant_lines = lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {_line_content, line_num} -> 
          line_num >= start_line and line_num <= end_line 
        end)
      |> Enum.map(fn {line_content, line_num} ->
          if line_num == line do
            "#{line_content}     <-- Error here"
          else
            line_content
          end
        end)
      |> Enum.reject(&(&1 == ""))

      %{
        lines: relevant_lines,
        error_line: line,
        error_column: column
      }
    end
  end

  def extract_source_snippet(source, error) do
    case extract_location_info(error) do
      %{line: line, column: column} when not is_nil(line) ->
        # Ensure line is within source bounds
        source_lines = String.split(source, "\n")
        if line <= length(source_lines) do
          extract_source_snippet(source, line, column)
        else
          # Create a fallback snippet showing the entire source
          %{
            lines: source_lines ++ ["     <-- Error beyond end of file"],
            error_line: line,
            error_column: column
          }
        end
      _ ->
        nil
    end
  end

  @doc """
  Categorizes error severity based on error type and impact.
  """
  def categorize_error_severity(error) do
    case error.type do
      :syntax_error -> :high
      :parser_crash -> :critical
      :timeout -> :medium
      :unsupported_language -> :low
      :unknown_error -> :medium
      _ -> :medium
    end
  end

  @doc """
  Provides recovery suggestions based on error type and context.
  """
  def error_recovery_suggestions(error) do
    case error.type do
      :syntax_error ->
        syntax_error_suggestions(error)
      :timeout ->
        timeout_suggestions(error)
      :parser_crash ->
        crash_suggestions(error)
      :unsupported_language ->
        ["Language '#{error.language}' is not supported. Supported languages: #{Enum.join(@supported_languages, ", ")}"]
      :unknown_error ->
        ["Unknown error occurred. Consider using fallback parsing strategy.", "Check if source code is valid #{error.language} syntax."]
      _ ->
        ["Try using a fallback parsing strategy."]
    end
  end

  @doc """
  Determines if an error is recoverable through fallback strategies.
  """
  def is_recoverable_error?(error) do
    case error.type do
      :syntax_error -> true
      :timeout -> true
      :parser_crash -> false
      :unsupported_language -> false
      :unknown_error -> true
      _ -> false
    end
  end

  # Private helper functions

  defp normalize_error_type(error) do
    case error do
      %{type: :syntax_error} -> :syntax_error
      %{type: :parse_error} -> :syntax_error
      %{type: :scanner_error} -> :syntax_error
      %{type: :timeout} -> :timeout
      %{type: :parser_crash} -> :parser_crash
      %{type: :unsupported_language} -> :unsupported_language
      _ -> :unknown_error
    end
  end

  defp extract_error_message(error) do
    cond do
      Map.has_key?(error, :message) -> error.message
      Map.has_key?(error, :type) and error.type == :timeout -> 
        "Parser timeout after #{Map.get(error, :duration_ms, "unknown")}ms"
      Map.has_key?(error, :type) and error.type == :parser_crash ->
        "Parser crashed: #{Map.get(error, :reason, "unknown")} (exit code: #{Map.get(error, :exit_code, "unknown")})"
      Map.has_key?(error, :type) and error.type == :unsupported_language ->
        error_lang = Map.get(error, :language, "unknown")
        "Language '#{error_lang}' is not supported"
      true -> 
        "Unknown parsing error occurred"
    end
  end

  defp extract_location_info(error) do
    cond do
      # JavaScript/TypeScript tree-sitter format
      Map.has_key?(error, :line) && Map.has_key?(error, :column) ->
        %{
          line: error.line,
          column: error.column,
          offset: Map.get(error, :offset)
        }
      
      # Python format
      Map.has_key?(error, :lineno) && Map.has_key?(error, :offset) ->
        %{
          line: error.lineno,
          column: error.offset,
          offset: error.offset
        }
      
      # Ruby format
      Map.has_key?(error, :location) && is_map(error.location) ->
        %{
          line: error.location.line,
          column: error.location.column,
          offset: Map.get(error.location, :offset)
        }
      
      # Go format
      Map.has_key?(error, :pos) && is_map(error.pos) ->
        %{
          line: error.pos.line,
          column: error.pos.column,
          offset: error.pos.offset
        }
      
      true ->
        nil
    end
  end

  defp add_language_specific_fields(standardized, error, language) do
    error_type = Map.get(error, :type, :unknown_error)
    
    case {error_type, language} do
      {:timeout, _} ->
        Map.put(standardized, :duration_ms, Map.get(error, :duration_ms))
      
      {:parser_crash, _} ->
        standardized
        |> Map.put(:reason, Map.get(error, :reason))
        |> Map.put(:exit_code, Map.get(error, :exit_code))
      
      {:unsupported_language, _} ->
        Map.put(standardized, :supported_languages, @supported_languages)
      
      {:unknown_error, _} ->
        Map.put(standardized, :original_error, error)
      
      _ ->
        standardized
    end
  end

  defp add_severity(standardized) do
    severity = categorize_error_severity(standardized)
    Map.put(standardized, :severity, severity)
  end

  defp add_recovery_suggestions(standardized) do
    suggestions = error_recovery_suggestions(standardized)
    Map.put(standardized, :suggestions, suggestions)
  end

  defp add_recoverability(standardized) do
    recoverable = is_recoverable_error?(standardized)
    Map.put(standardized, :recoverable, recoverable)
  end

  defp syntax_error_suggestions(error) do
    base_suggestions = [
      "Check for missing or extra punctuation (semicolons, commas, brackets)",
      "Verify that all blocks are properly closed",
      "Ensure variable names are valid identifiers"
    ]

    language_specific = case error.language do
      "javascript" ->
        ["Check for missing semicolons or commas", "Verify ES6+ syntax compatibility"]
      "python" ->
        ["Check indentation consistency", "Verify colon placement in control structures"]
      "ruby" ->
        ["Check for missing 'end' keywords", "Verify block syntax (do/end vs {}"]
      "php" ->
        ["Check for missing semicolons", "Verify PHP opening/closing tags"]
      "java" ->
        ["Check for missing semicolons", "Verify class and method declarations"]
      "go" ->
        ["Check for missing package declaration", "Verify brace placement"]
      _ ->
        []
    end

    if String.contains?(error.message || "", "semicolon") do
      ["Check semicolon placement and usage" | base_suggestions] ++ language_specific
    else
      base_suggestions ++ language_specific
    end
  end

  defp timeout_suggestions(error) do
    [
      "Reduce source code complexity or size",
      "Increase parser timeout limit if possible", 
      "Split large files into smaller modules",
      "Consider using a streaming parser for large files"
    ] ++ case error.language do
      "javascript" -> ["Consider using a faster JavaScript parser", "Minimize deeply nested structures"]
      "python" -> ["Reduce deeply nested functions or classes", "Consider breaking into multiple modules"]
      _ -> []
    end
  end

  defp crash_suggestions(_error) do
    [
      "Parser crashed unexpectedly - this indicates a serious issue",
      "Try using a fallback parsing strategy",
      "Report this issue to the development team",
      "Consider preprocessing the source code to identify problematic patterns"
    ]
  end
end