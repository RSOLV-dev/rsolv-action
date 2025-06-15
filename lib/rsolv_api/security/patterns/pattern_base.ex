defmodule RsolvApi.Security.Patterns.PatternBase do
  @moduledoc """
  Base module for all security patterns providing common functionality.
  
  Handles:
  - Cross-language patterns
  - Embedded language detection (SQL in JS, HTML in PHP, etc.)
  - Multi-language vulnerability detection
  """
  
  defmacro __using__(_opts) do
    quote do
      alias RsolvApi.Security.Pattern
      alias RsolvApi.Security.ASTPattern
      
      @doc """
      Returns the base pattern definition.
      Override this in your pattern module.
      """
      def pattern do
        raise "pattern/0 must be implemented"
      end
      
      @doc """
      Returns AST enhancement rules for this pattern.
      Override this to provide pattern-specific AST rules.
      
      Should return a map with:
      - :ast_rules - AST node matching rules
      - :context_rules - Path exclusions, framework checks
      - :confidence_rules - Dynamic confidence scoring
      - :min_confidence - Minimum confidence threshold
      
      Return nil if no AST enhancement is needed.
      """
      def ast_enhancement do
        nil
      end
      
      @doc """
      Returns the pattern with AST enhancements applied.
      Uses pattern-specific AST rules if defined, otherwise
      falls back to centralized AST enhancement.
      """
      def enhanced_pattern do
        base_pattern = pattern()
        enhancement = ast_enhancement()
        
        if is_nil(enhancement) do
          # Fall back to centralized enhancement
          ASTPattern.enhance(base_pattern)
        else
          # Apply pattern-specific enhancement by adding ast_enhancement key
          Map.put(base_pattern, :ast_enhancement, enhancement)
        end
      end
      
      @doc """
      Checks if this pattern applies to a given file based on:
      - File extension
      - Embedded language detection
      - Content analysis
      """
      def applies_to_file?(file_path, content \\ nil) do
        cond do
          # Cross-language patterns apply to all files
          pattern().languages == ["all"] or pattern().languages == ["*"] ->
            true
            
          # Check file extension
          matches_file_extension?(file_path) ->
            true
            
          # Check for embedded languages (e.g., SQL in JS)
          content && contains_embedded_language?(content) ->
            true
            
          true ->
            false
        end
      end
      
      defp matches_file_extension?(file_path) do
        ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
        
        Enum.any?(pattern().languages, fn lang ->
          case lang do
            "javascript" -> ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
            "typescript" -> ext in ["ts", "tsx"]
            "php" -> ext in ["php", "php3", "php4", "php5", "phtml"]
            "python" -> ext in ["py", "pyw"]
            "ruby" -> ext in ["rb", "erb", "rake"]
            "java" -> ext in ["java"]
            "elixir" -> ext in ["ex", "exs"]
            _ -> ext == lang
          end
        end)
      end
      
      defp contains_embedded_language?(content) do
        pattern_type = pattern().type
        
        cond do
          pattern_type == :sql_injection ->
            # SQL can be embedded in any language
            content =~ ~r/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/i
            
          pattern_type == :xss ->
            # HTML/JS can be embedded in backend languages
            content =~ ~r/<[^>]+>|innerHTML|document\.write/
            
          pattern_type == :command_injection ->
            # Shell commands can be called from any language
            content =~ ~r/system|exec|shell|spawn|popen/i
            
          true ->
            false
        end
      end
      
      defoverridable [pattern: 0, ast_enhancement: 0, applies_to_file?: 2]
    end
  end
end