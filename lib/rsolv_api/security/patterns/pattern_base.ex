defmodule RsolvApi.Security.Patterns.PatternBase do
  @moduledoc """
  Base module for all security patterns providing common functionality.
  
  Handles:
  - Cross-language patterns
  - Embedded language detection (SQL in JS, HTML in PHP, etc.)
  - Multi-language vulnerability detection
  """
  
  alias RsolvApi.Security.ASTPattern
  
  @doc """
  Behavior callback for pattern definition.
  """
  @callback pattern() :: RsolvApi.Security.Pattern.t()
  
  @doc """
  Optional behavior callback for vulnerability metadata.
  """
  @callback vulnerability_metadata() :: map()
  
  @doc """
  Optional behavior callback for AST enhancement rules.
  """
  @callback ast_enhancement() :: map() | nil
  
  defmacro __using__(_opts) do
    quote do
      @behaviour RsolvApi.Security.Patterns.PatternBase
      
      alias RsolvApi.Security.Pattern
      alias RsolvApi.Security.ASTPattern
      
      @doc """
      Returns the base pattern definition.
      Override this in your pattern module.
      """
      @impl true
      def pattern do
        raise "pattern/0 must be implemented"
      end
      
      @doc """
      Returns vulnerability metadata.
      Override this in your pattern module if needed.
      """
      @impl true
      def vulnerability_metadata do
        %{}
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
      @impl true
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
        
        # Handle both nil and map cases for enhancement
        if is_map(enhancement) and map_size(enhancement) > 0 do
          # Determine return type based on pattern language/framework
          # Django and Elixir patterns expect Pattern struct with :ast_enhancement field
          # Other patterns expect ASTPattern struct with fields merged directly
          languages = base_pattern.languages
          frameworks = base_pattern.frameworks || []
          
          should_keep_pattern_struct = 
            "elixir" in languages or
            "django" in frameworks or
            "rails" in frameworks
          
          if should_keep_pattern_struct do
            # Return Pattern struct with ast_enhancement field
            Map.put(base_pattern, :ast_enhancement, enhancement)
          else
            # Return ASTPattern struct with fields merged directly
            base_pattern
            |> Map.from_struct()
            |> Map.merge(enhancement)
            |> then(&struct(ASTPattern, &1))
          end
        else
          # Fall back to centralized enhancement
          ASTPattern.enhance(base_pattern)
        end
      end
      
      @doc """
      Checks if this pattern applies to a given file based on:
      - Explicit file_targeting rules (when available)
      - File extension
      - Framework-specific targeting rules
      - Embedded language detection
      - Content analysis
      
      The second parameter can be either:
      - A string containing file content (for embedded language detection)
      - A list of frameworks (for framework-specific patterns)
      """
      def applies_to_file?(file_path, content_or_frameworks ) do
        pattern_meta = pattern()
        
        # First check if pattern has explicit file_targeting rules
        case pattern_meta.file_targeting do
          nil ->
            # No explicit targeting, use legacy logic
            apply_legacy_targeting(file_path, pattern_meta, content_or_frameworks)
            
          file_targeting ->
            # Use explicit targeting rules
            apply_explicit_targeting(file_path, file_targeting, pattern_meta, content_or_frameworks)
        end
      end
      
      # Legacy targeting logic (current implementation)
      defp apply_legacy_targeting(file_path, pattern_meta, content_or_frameworks) do
        # First check language match
        if matches_language?(file_path) do
          # Then check framework-specific targeting
          pattern_frameworks = pattern_meta.frameworks || []
          
          # If pattern has framework requirements, check them
          if pattern_frameworks != [] do
            provided_frameworks = case content_or_frameworks do
              list when is_list(list) -> list
              _ -> []
            end
            
            # If no frameworks provided but pattern requires Rails, 
            # apply Rails-specific file targeting
            if provided_frameworks == [] && "rails" in pattern_frameworks do
              applies_to_rails_file?(pattern_meta, file_path)
            else
              # Pattern must match at least one framework
              has_framework_match = Enum.any?(pattern_frameworks, fn fw -> fw in provided_frameworks end)
              
              # Apply framework-specific file targeting rules
              if has_framework_match && "rails" in pattern_frameworks do
                applies_to_rails_file?(pattern_meta, file_path)
              else
                has_framework_match
              end
            end
          else
            # No framework requirements, check embedded languages if content provided
            case content_or_frameworks do
              content when is_binary(content) ->
                contains_embedded_language?(content)
              _ ->
                true  # No additional restrictions
            end
          end
        else
          false
        end
      end
      
      # Explicit targeting logic using file_targeting rules
      defp apply_explicit_targeting(file_path, file_targeting, pattern_meta, content_or_frameworks) do
        # First check language match (still required)
        if not matches_language_for_pattern?(file_path, pattern_meta) do
          false
        else
          # Apply explicit targeting rules
          applies_to_scope?(file_path, file_targeting.scope) and
          matches_include_paths?(file_path, file_targeting.include_paths) and
          not matches_exclude_paths?(file_path, file_targeting.exclude_paths) and
          matches_include_extensions?(file_path, file_targeting.include_extensions) and
          not matches_exclude_extensions?(file_path, file_targeting.exclude_extensions) and
          # Still check framework requirements if any
          matches_frameworks?(pattern_meta, content_or_frameworks) and
          # Still check embedded languages if content provided
          matches_embedded_languages?(content_or_frameworks, pattern_meta)
        end
      end
      
      # Helper functions for explicit targeting
      defp applies_to_scope?(file_path, :any), do: true
      defp applies_to_scope?(file_path, :models) do
        String.contains?(file_path, "model") or String.contains?(file_path, "app/models/")
      end
      defp applies_to_scope?(file_path, :controllers) do
        String.contains?(file_path, "controller") or String.contains?(file_path, "app/controllers/")
      end
      defp applies_to_scope?(file_path, :views) do
        String.contains?(file_path, "views/") or String.contains?(file_path, "app/views/") or
        String.ends_with?(file_path, ".html.erb") or String.ends_with?(file_path, ".html.haml") or
        String.ends_with?(file_path, ".haml") or String.ends_with?(file_path, ".erb")
      end
      defp applies_to_scope?(file_path, :configs) do
        String.contains?(file_path, "config/") or String.contains?(file_path, "initializers/")
      end
      defp applies_to_scope?(file_path, :routes) do
        String.contains?(file_path, "routes") or String.contains?(file_path, "config/routes")
      end
      defp applies_to_scope?(file_path, :middleware) do
        String.contains?(file_path, "middleware") or String.contains?(file_path, "app/middleware/")
      end
      defp applies_to_scope?(file_path, :helpers) do
        String.contains?(file_path, "helpers/") or String.contains?(file_path, "app/helpers/")
      end
      defp applies_to_scope?(file_path, :tests) do
        String.contains?(file_path, "test/") or String.contains?(file_path, "spec/")
      end
      
      defp matches_include_paths?(_, nil), do: true
      defp matches_include_paths?(file_path, include_paths) do
        Enum.any?(include_paths, fn path -> String.contains?(file_path, path) end)
      end
      
      defp matches_exclude_paths?(_, nil), do: false
      defp matches_exclude_paths?(file_path, exclude_paths) do
        Enum.any?(exclude_paths, fn path -> String.contains?(file_path, path) end)
      end
      
      defp matches_include_extensions?(_, nil), do: true
      defp matches_include_extensions?(file_path, include_extensions) do
        ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
        ext in include_extensions
      end
      
      defp matches_exclude_extensions?(_, nil), do: false
      defp matches_exclude_extensions?(file_path, exclude_extensions) do
        ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
        ext in exclude_extensions
      end
      
      defp matches_frameworks?(pattern_meta, content_or_frameworks) do
        pattern_frameworks = pattern_meta.frameworks || []
        
        if pattern_frameworks == [] do
          true
        else
          provided_frameworks = case content_or_frameworks do
            list when is_list(list) -> list
            _ -> []
          end
          
          # If no frameworks provided but pattern has explicit file_targeting,
          # don't require framework matching - explicit targeting replaces it
          if provided_frameworks == [] and pattern_meta.file_targeting != nil do
            true
          else
            # Pattern must match at least one framework
            Enum.any?(pattern_frameworks, fn fw -> fw in provided_frameworks end)
          end
        end
      end
      
      defp matches_embedded_languages?(content_or_frameworks, pattern_meta) do
        case content_or_frameworks do
          content when is_binary(content) ->
            contains_embedded_language_for_pattern?(content, pattern_meta)
          _ ->
            true  # No additional restrictions if no content provided
        end
      end
      
      # Helper function for explicit targeting that accepts pattern as parameter
      defp matches_language_for_pattern?(file_path, pattern_meta) do
        pattern_langs = pattern_meta.languages
        
        cond do
          # Cross-language patterns
          pattern_langs == ["all"] or pattern_langs == ["*"] ->
            true
            
          # Check file extension
          matches_file_extension_for_pattern?(file_path, pattern_meta) ->
            true
            
          true ->
            false
        end
      end
      
      defp matches_language?(file_path) do
        pattern_langs = pattern().languages
        
        cond do
          # Cross-language patterns
          pattern_langs == ["all"] or pattern_langs == ["*"] ->
            true
            
          # Check file extension
          matches_file_extension?(file_path) ->
            true
            
          true ->
            false
        end
      end
      
      # Rails-specific file targeting based on pattern type
      defp applies_to_rails_file?(pattern, file_path) do
        case pattern.type do
          # Mass assignment patterns - check pattern ID for specifics
          :mass_assignment ->
            if String.contains?(pattern.id, "strong") || String.contains?(pattern.id, "parameter") do
              # Strong parameters pattern targets controllers
              String.contains?(file_path, "controller") ||
              String.contains?(file_path, "app/controllers/")
            else
              # attr_accessible patterns target models
              String.contains?(file_path, "model") ||
              String.contains?(file_path, "app/models/")
            end
            
          # Parameter filtering patterns target controllers  
          :input_validation ->
            if String.contains?(pattern.id, "strong_param") do
              String.contains?(file_path, "controller") ||
              String.contains?(file_path, "app/controllers/")
            else
              true
            end
            
          # Security config patterns target config files
          :security_misconfiguration ->
            if String.contains?(pattern.id, "session") do
              String.contains?(file_path, "config/") ||
              String.contains?(file_path, "initializers/")
            else
              # Other misconfig patterns target broader files
              String.contains?(file_path, "config/") ||
              String.contains?(file_path, "app/")
            end
            
          # Path traversal patterns
          :path_traversal ->
            cond do
              # CVE-2019-5418 targets views/controllers/helpers (not test files)
              String.contains?(pattern.id, "5418") ->
                not String.contains?(file_path, "test/") &&
                not String.contains?(file_path, "db/") &&
                (String.contains?(file_path, "controller") ||
                 String.contains?(file_path, "app/controllers/") ||
                 String.contains?(file_path, "app/views/") ||
                 String.contains?(file_path, "app/helpers/") ||
                 # Also match view file extensions
                 String.ends_with?(file_path, ".html.erb") ||
                 String.ends_with?(file_path, ".html.haml") ||
                 String.ends_with?(file_path, ".haml") ||
                 String.ends_with?(file_path, ".erb"))
                
              # Unsafe globbing can appear anywhere
              true ->
                true
            end
            
          # Broken access control patterns
          :broken_access_control ->
            cond do
              # Route security targets route files and controllers
              String.contains?(pattern.id, "route") ->
                String.contains?(file_path, "routes") ||
                String.contains?(file_path, "config/") ||
                String.contains?(file_path, "controller") ||
                String.contains?(file_path, "app/controllers/")
                
              # Callback bypass targets controllers (but not test files)
              String.contains?(pattern.id, "callback") ->
                not String.contains?(file_path, "test/") &&
                (String.contains?(file_path, "controller") ||
                 String.contains?(file_path, "app/controllers/"))
                
              # Other access control patterns
              true ->
                true
            end
            
          # Authentication/session patterns target controllers and models
          :authentication ->
            String.contains?(file_path, "controller") ||
            String.contains?(file_path, "model") ||
            String.contains?(file_path, "app/")
            
          # Debug mode patterns can appear in config or Gemfile
          :debug_mode ->
            String.contains?(file_path, "config/") ||
            String.contains?(file_path, "Gemfile") ||
            String.contains?(file_path, "app/")
            
          # Open redirect patterns target controllers, configs, and middleware, not views
          :open_redirect ->
            not String.contains?(file_path, "views/") &&
            (String.contains?(file_path, "controller") ||
             String.contains?(file_path, "config/") ||
             String.contains?(file_path, "middleware") ||
             String.contains?(file_path, "app/") ||
             String.contains?(file_path, "lib/"))
            
          # Default: apply to all Rails files
          _ ->
            true
        end
      end
      
      defp matches_file_extension?(file_path) do
        ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
        filename = Path.basename(file_path)
        
        Enum.any?(pattern().languages, fn lang ->
          case lang do
            "javascript" -> ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
            "typescript" -> ext in ["ts", "tsx"]
            "php" -> ext in ["php", "php3", "php4", "php5", "phtml"]
            "python" -> ext in ["py", "pyw"]
            "ruby" -> 
              ext in ["rb", "erb", "rake", "ru", "haml", "slim"] ||
              filename in ["Gemfile", "Rakefile", "Guardfile", "Vagrantfile", "Thorfile", "config.ru"]
            "java" -> ext in ["java"]
            "elixir" -> ext in ["ex", "exs"]
            _ -> ext == lang
          end
        end)
      end
      
      defp contains_embedded_language?(content) do
        pattern_type = pattern().type
        
        injection_types = [:sql_injection, :xss, :command_injection, :injection, :rce,
                          :nosql_injection, :ldap_injection, :xpath_injection, :xxe,
                          :template_injection, :code_injection, :path_traversal, :ssrf]
        
        if pattern_type in injection_types do
          check_embedded_language_for_type(pattern_type, content)
        else
          # Non-injection types don't need embedded language checks
          false
        end
      end
      
      defp check_embedded_language_for_type(:sql_injection, content) do
        content =~ ~r/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/i
      end
      
      defp check_embedded_language_for_type(:xss, content) do
        content =~ ~r/<[^>]+>|innerHTML|document\.write/
      end
      
      defp check_embedded_language_for_type(:command_injection, content) do
        content =~ ~r/system|exec|shell|spawn|popen/i
      end
      
      defp check_embedded_language_for_type(:injection, content) do
        # Generic injection may contain SQL, XSS, or command injection
        check_embedded_language_for_type(:sql_injection, content) or
        check_embedded_language_for_type(:xss, content) or
        check_embedded_language_for_type(:command_injection, content)
      end
      
      defp check_embedded_language_for_type(:rce, content) do
        # Remote code execution often involves command injection
        content =~ ~r/system|exec|shell|spawn|popen/i
      end
      
      defp check_embedded_language_for_type(:nosql_injection, content) do
        content =~ ~r/\$where|\$ne|\$gt|\$lt|\$regex|\.find\(|\.findOne\(/
      end
      
      defp check_embedded_language_for_type(:ldap_injection, content) do
        content =~ ~r/ldap_search|ldap_bind|ldap_connect/i
      end
      
      defp check_embedded_language_for_type(:xpath_injection, content) do
        content =~ ~r/xpath|selectNodes|selectSingleNode/i
      end
      
      defp check_embedded_language_for_type(:xxe, content) do
        content =~ ~r/DOCTYPE|ENTITY|SYSTEM|xml/i
      end
      
      defp check_embedded_language_for_type(:template_injection, content) do
        content =~ ~r/\{\{|\{%|<%=|<%-/
      end
      
      defp check_embedded_language_for_type(:code_injection, content) do
        content =~ ~r/eval|exec|system|Function\(/i
      end
      
      defp check_embedded_language_for_type(:path_traversal, content) do
        content =~ ~r/\.\.\/|\.\.\\|readFile|readdir/i
      end
      
      defp check_embedded_language_for_type(:ssrf, content) do
        content =~ ~r/http|https|ftp|file:|gopher:|dict:/i
      end
      
      defp check_embedded_language_for_type(_, _content) do
        # Fallback for any unhandled injection types
        false
      end
      
      # Helper functions that accept pattern as parameter for explicit targeting
      defp matches_file_extension_for_pattern?(file_path, pattern_meta) do
        ext = Path.extname(file_path) |> String.downcase() |> String.trim_leading(".")
        filename = Path.basename(file_path)
        
        Enum.any?(pattern_meta.languages, fn lang ->
          case lang do
            "javascript" -> ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
            "typescript" -> ext in ["ts", "tsx"]
            "php" -> ext in ["php", "php3", "php4", "php5", "phtml"]
            "python" -> ext in ["py", "pyw"]
            "ruby" -> 
              ext in ["rb", "erb", "rake", "ru", "haml", "slim"] ||
              filename in ["Gemfile", "Rakefile", "Guardfile", "Vagrantfile", "Thorfile", "config.ru"]
            "java" -> ext in ["java"]
            "elixir" -> ext in ["ex", "exs"]
            _ -> ext == lang
          end
        end)
      end
      
      defp contains_embedded_language_for_pattern?(content, pattern_meta) do
        pattern_type = pattern_meta.type
        
        injection_types = [:sql_injection, :xss, :command_injection, :injection, :rce,
                          :nosql_injection, :ldap_injection, :xpath_injection, :xxe,
                          :template_injection, :code_injection, :path_traversal, :ssrf]
        
        if pattern_type in injection_types do
          check_embedded_language_for_type(pattern_type, content)
        else
          # Non-injection types don't need embedded language checks
          false
        end
      end
      
      defoverridable [pattern: 0, vulnerability_metadata: 0, ast_enhancement: 0, applies_to_file?: 2]
    end
  end
end
