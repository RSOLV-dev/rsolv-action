#!/usr/bin/env elixir

# Standalone test to verify pattern registry without Phoenix

# First, compile the necessary files
Code.compile_file("lib/rsolv_api/security/pattern.ex")
Code.compile_file("lib/rsolv_api/security/patterns/pattern_base.ex")
Code.compile_file("lib/rsolv_api/security/pattern_registry.ex")

# Compile some pattern files for testing
Code.compile_file("lib/rsolv_api/security/patterns/javascript/sql_injection_concat.ex")
Code.compile_file("lib/rsolv_api/security/patterns/python/sql_injection_concat.ex")
Code.compile_file("lib/rsolv_api/security/patterns/php/xss_echo.ex")
Code.compile_file("lib/rsolv_api/security/patterns/common/weak_jwt_secret.ex")

# Mock Application.spec to return our compiled modules
defmodule MockApplication do
  def spec(:rsolv_api, :modules) do
    # Get all currently loaded modules that match our patterns
    :code.all_loaded()
    |> Enum.map(&elem(&1, 0))
    |> Enum.filter(fn mod ->
      mod_str = to_string(mod)
      String.contains?(mod_str, "RsolvApi.Security.Patterns")
    end)
  end
end

# Replace Application module temporarily
:code.purge(Application)
:code.delete(Application)
:code.load_binary(Application, ~c"nofile", :erlang.term_to_binary(MockApplication))

# Now test the pattern registry
alias RsolvApi.Security.PatternRegistry

IO.puts("\n=== Testing Pattern Registry ===\n")

# Test 1: JavaScript patterns
IO.puts("1. Testing JavaScript patterns:")
js_patterns = PatternRegistry.get_patterns_for_language("javascript")
IO.puts("   Found #{length(js_patterns)} patterns")
if length(js_patterns) > 0 do
  pattern = hd(js_patterns)
  IO.puts("   First pattern ID: #{pattern.id}")
  IO.puts("   ✓ JavaScript uses 'js-' prefix: #{String.starts_with?(pattern.id, "js-")}")
else
  IO.puts("   ✗ No JavaScript patterns found!")
end

# Test 2: Python patterns
IO.puts("\n2. Testing Python patterns:")
py_patterns = PatternRegistry.get_patterns_for_language("python")
IO.puts("   Found #{length(py_patterns)} patterns")
if length(py_patterns) > 0 do
  pattern = hd(py_patterns)
  IO.puts("   First pattern ID: #{pattern.id}")
  IO.puts("   ✓ Python uses 'python-' prefix: #{String.starts_with?(pattern.id, "python-")}")
else
  IO.puts("   ✗ No Python patterns found!")
end

# Test 3: PHP patterns
IO.puts("\n3. Testing PHP patterns:")
php_patterns = PatternRegistry.get_patterns_for_language("php")
IO.puts("   Found #{length(php_patterns)} patterns")
if length(php_patterns) > 0 do
  pattern = hd(php_patterns)
  IO.puts("   First pattern ID: #{pattern.id}")
  IO.puts("   ✓ PHP uses 'php-' prefix: #{String.starts_with?(pattern.id, "php-")}")
else
  IO.puts("   ✗ No PHP patterns found!")
end

# Test 4: Common patterns
IO.puts("\n4. Testing common patterns:")
all_patterns = PatternRegistry.get_all_patterns()
IO.puts("   Total patterns found: #{length(all_patterns)}")
jwt_patterns = Enum.filter(all_patterns, fn p -> String.contains?(p.id, "jwt") end)
IO.puts("   JWT-related patterns: #{length(jwt_patterns)}")
if length(jwt_patterns) > 0 do
  IO.puts("   Example: #{hd(jwt_patterns).id}")
end

# Test 5: Check actual module loading
IO.puts("\n5. Checking module loading:")
modules = MockApplication.spec(:rsolv_api, :modules)
IO.puts("   Total pattern modules: #{length(modules)}")
IO.puts("   Sample modules:")
modules
|> Enum.take(5)
|> Enum.each(fn mod ->
  has_pattern = function_exported?(mod, :pattern, 0)
  IO.puts("     - #{mod} (has pattern/0: #{has_pattern})")
end)

IO.puts("\n=== Summary ===")
IO.puts("JavaScript patterns: #{length(js_patterns)} (should use 'js-' prefix)")
IO.puts("Python patterns: #{length(py_patterns)} (should use 'python-' prefix)")
IO.puts("PHP patterns: #{length(php_patterns)} (should use 'php-' prefix)")
IO.puts("Total patterns: #{length(all_patterns)}")