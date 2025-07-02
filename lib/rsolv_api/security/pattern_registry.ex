defmodule RsolvApi.Security.PatternRegistry do
  @moduledoc """
  Registry for discovering and loading security patterns from the new file structure.
  
  Handles:
  - Language-specific patterns (e.g., javascript/sql_injection_concat.ex)
  - Framework-specific patterns (e.g., frameworks/rails/mass_assignment.ex)
  - Cross-language patterns (e.g., common/weak_jwt_secret.ex)
  - Pattern discovery and loading
  """
  
  require Logger
  
  @pattern_base_path "lib/rsolv_api/security/patterns"
  
  @doc """
  Get all patterns for a specific language.
  Includes both language-specific and cross-language patterns.
  """
  def get_patterns_for_language(language) do
    # Use PatternServer if available (which caches patterns efficiently)
    if Process.whereis(RsolvApi.Security.PatternServer) do
      case RsolvApi.Security.PatternServer.get_patterns(language) do
        {:ok, patterns} -> patterns
        _ -> load_patterns_directly(language)
      end
    else
      load_patterns_directly(language)
    end
  end
  
  defp load_patterns_directly(language) do
    language_modules = load_pattern_modules_from_directory("#{@pattern_base_path}/#{language}")
    common_modules = load_pattern_modules_from_directory("#{@pattern_base_path}/common")
    
    (language_modules ++ common_modules)
    |> Enum.map(& &1.pattern())
    |> Enum.uniq_by(& &1.id)
  end
  
  @doc """
  Get all patterns across all languages.
  """
  def get_all_patterns do
    # Get all pattern modules directly from the application
    case Application.spec(:rsolv_api, :modules) do
      modules when is_list(modules) ->
        modules
        |> Enum.filter(&is_pattern_module?/1)
        |> Enum.filter(&function_exported?(&1, :pattern, 0))
        |> Enum.map(& &1.pattern())
        |> Enum.uniq_by(& &1.id)
      
      _ ->
        []
    end
  end
  
  @doc """
  Get patterns by vulnerability type.
  """
  def get_patterns_by_type(type) do
    get_all_patterns()
    |> Enum.filter(&(&1.type == type))
  end
  
  @doc """
  Get patterns that apply to a specific file.
  Takes into account file extension, embedded languages, and content.
  """
  def get_patterns_for_file(file_path, content \\ nil) do
    # Get all pattern modules from the application
    case Application.spec(:rsolv_api, :modules) do
      modules when is_list(modules) ->
        modules
        |> Enum.filter(&is_pattern_module?/1)
        |> Enum.filter(&function_exported?(&1, :pattern, 0))
        |> Enum.filter(fn pattern_module ->
          if function_exported?(pattern_module, :applies_to_file?, 2) do
            pattern_module.applies_to_file?(file_path, content)
          else
            # Fallback to language matching
            pattern = pattern_module.pattern()
            matches_file_language?(file_path, pattern.languages)
          end
        end)
        |> Enum.map(& &1.pattern())
      
      _ ->
        []
    end
  end
  
  # Private functions
  
  defp load_pattern_modules_from_directory(dir_path) do
    # Extract the language/subdirectory name from the path
    # e.g., "lib/rsolv_api/security/patterns/python" -> "python"
    language = Path.basename(dir_path)
    
    # Get all modules from the application
    # This works in both development and releases
    case Application.spec(:rsolv_api, :modules) do
      modules when is_list(modules) ->
        # Filter modules that match our pattern namespace
        namespace = case language do
          "common" -> RsolvApi.Security.Patterns.Common
          "python" -> RsolvApi.Security.Patterns.Python
          "javascript" -> RsolvApi.Security.Patterns.Javascript
          "ruby" -> RsolvApi.Security.Patterns.Ruby
          "php" -> RsolvApi.Security.Patterns.Php
          "java" -> RsolvApi.Security.Patterns.Java
          "elixir" -> RsolvApi.Security.Patterns.Elixir
          "rails" -> RsolvApi.Security.Patterns.Rails
          "django" -> RsolvApi.Security.Patterns.Django
          _ -> nil
        end
        
        if namespace do
          modules
          |> Enum.filter(&pattern_module_in_namespace?(&1, namespace))
          |> Enum.filter(&function_exported?(&1, :pattern, 0))
        else
          []
        end
      
      _ ->
        # Fallback to empty if application not loaded yet
        []
    end
  end
  
  defp pattern_module_in_namespace?(module, namespace) do
    module_parts = Module.split(module)
    namespace_parts = Module.split(namespace)
    
    # Check if module starts with namespace
    List.starts_with?(module_parts, namespace_parts)
  end
  
  defp is_pattern_module?(module) do
    # Check if module is in the patterns namespace
    module_parts = Module.split(module)
    base_parts = Module.split(RsolvApi.Security.Patterns)
    
    # Must be in the patterns namespace and not be a base module
    List.starts_with?(module_parts, base_parts) && 
      length(module_parts) > length(base_parts)
  end
  
  
  defp matches_file_language?(file_path, languages) do
    if languages == ["all"] or languages == ["*"] do
      true
    else
      ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
      
      Enum.any?(languages, fn lang ->
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
  end
end