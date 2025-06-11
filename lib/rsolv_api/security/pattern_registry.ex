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
    # Scan all subdirectories
    pattern_dirs = File.ls!(@pattern_base_path)
    |> Enum.filter(&File.dir?("#{@pattern_base_path}/#{&1}"))
    
    pattern_dirs
    |> Enum.flat_map(&load_pattern_modules_from_directory("#{@pattern_base_path}/#{&1}"))
    |> Enum.map(& &1.pattern())
    |> Enum.uniq_by(& &1.id)
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
    all_modules = File.ls!(@pattern_base_path)
    |> Enum.filter(&File.dir?("#{@pattern_base_path}/#{&1}"))
    |> Enum.flat_map(&load_pattern_modules_from_directory("#{@pattern_base_path}/#{&1}"))
    
    all_modules
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
  end
  
  # Private functions
  
  defp load_pattern_modules_from_directory(dir_path) do
    if File.exists?(dir_path) do
      File.ls!(dir_path)
      |> Enum.filter(&String.ends_with?(&1, ".ex"))
      |> Enum.map(&load_pattern_module("#{dir_path}/#{&1}"))
      |> Enum.filter(& &1)
    else
      []
    end
  end
  
  defp load_pattern_module(file_path) do
    # Convert file path to module name
    module_name = file_path_to_module_name(file_path)
    
    try do
      module = String.to_existing_atom("Elixir.#{module_name}")
      if function_exported?(module, :pattern, 0) do
        module
      else
        Logger.warning("Pattern module #{module_name} does not export pattern/0")
        nil
      end
    rescue
      ArgumentError ->
        # Module doesn't exist yet (might need compilation)
        Logger.debug("Pattern module #{module_name} not loaded yet")
        nil
    end
  end
  
  defp file_path_to_module_name(file_path) do
    file_path
    |> String.replace_prefix("lib/", "")
    |> String.replace_suffix(".ex", "")
    |> String.split("/")
    |> Enum.map(&Macro.camelize/1)
    |> Enum.join(".")
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