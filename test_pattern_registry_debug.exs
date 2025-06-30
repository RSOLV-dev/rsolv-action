#!/usr/bin/env elixir

# Debug the namespace matching issue

# Compile necessary files
Code.compile_file("lib/rsolv_api/security/pattern.ex")
Code.compile_file("lib/rsolv_api/security/patterns/pattern_base.ex")
Code.compile_file("lib/rsolv_api/security/pattern_registry.ex")

# Compile pattern files
Code.compile_file("lib/rsolv_api/security/patterns/javascript/sql_injection_concat.ex")
Code.compile_file("lib/rsolv_api/security/patterns/python/sql_injection_concat.ex")
Code.compile_file("lib/rsolv_api/security/patterns/php/xss_echo.ex")
Code.compile_file("lib/rsolv_api/security/patterns/common/weak_jwt_secret.ex")

# Let's debug the actual filtering
all_modules = :code.all_loaded()
  |> Enum.map(&elem(&1, 0))
  |> Enum.filter(fn mod ->
    mod_str = to_string(mod)
    String.contains?(mod_str, "RsolvApi.Security.Patterns")
  end)

IO.puts("All pattern modules loaded:")
Enum.each(all_modules, fn mod ->
  IO.puts("  #{mod}")
end)

# Test namespace matching
defmodule DebugPatternRegistry do
  def test_namespace_matching do
    # Test Javascript namespace
    js_namespace = RsolvApi.Security.Patterns.Javascript
    IO.puts("\nTesting JavaScript namespace: #{js_namespace}")
    
    js_module = RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat
    IO.puts("JavaScript module: #{js_module}")
    
    # Test if module is in namespace
    module_parts = Module.split(js_module)
    namespace_parts = Module.split(js_namespace)
    
    IO.puts("Module parts: #{inspect(module_parts)}")
    IO.puts("Namespace parts: #{inspect(namespace_parts)}")
    IO.puts("Starts with?: #{List.starts_with?(module_parts, namespace_parts)}")
    
    # Try with PHP
    IO.puts("\nTesting PHP namespace:")
    php_namespace = RsolvApi.Security.Patterns.Php
    php_module = RsolvApi.Security.Patterns.Php.XssEcho
    
    module_parts = Module.split(php_module)
    namespace_parts = Module.split(php_namespace)
    
    IO.puts("Module parts: #{inspect(module_parts)}")
    IO.puts("Namespace parts: #{inspect(namespace_parts)}")
    IO.puts("Starts with?: #{List.starts_with?(module_parts, namespace_parts)}")
  end
  
  def test_pattern_loading_directly do
    IO.puts("\n\nTesting direct pattern loading:")
    
    # Let's manually test what get_patterns_for_language does
    language = "javascript"
    dir_path = "lib/rsolv_api/security/patterns/#{language}"
    
    IO.puts("Language: #{language}")
    IO.puts("Dir path: #{dir_path}")
    IO.puts("Basename: #{Path.basename(dir_path)}")
    
    # Simulate Application.spec
    modules = all_modules()
    IO.puts("Total modules available: #{length(modules)}")
    
    # Get namespace
    namespace = RsolvApi.Security.Patterns.Javascript
    IO.puts("Namespace: #{namespace}")
    
    # Filter by namespace
    filtered = modules
      |> Enum.filter(&pattern_module_in_namespace?(&1, namespace))
      |> Enum.filter(&function_exported?(&1, :pattern, 0))
    
    IO.puts("Filtered modules: #{length(filtered)}")
    Enum.each(filtered, fn mod ->
      IO.puts("  - #{mod}")
    end)
  end
  
  defp all_modules do
    :code.all_loaded()
    |> Enum.map(&elem(&1, 0))
    |> Enum.filter(fn mod ->
      mod_str = to_string(mod)
      String.contains?(mod_str, "RsolvApi.Security.Patterns")
    end)
  end
  
  defp pattern_module_in_namespace?(module, namespace) do
    module_parts = Module.split(module)
    namespace_parts = Module.split(namespace)
    
    # Check if module starts with namespace
    List.starts_with?(module_parts, namespace_parts)
  end
end

# Run the debug
DebugPatternRegistry.test_namespace_matching()
DebugPatternRegistry.test_pattern_loading_directly()