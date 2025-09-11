#!/usr/bin/env elixir

# Script to fix test files using hardcoded API keys

test_files = [
  "test/rsolv_web/controllers/api/v1/vulnerability_validation_performance_test.exs",
  "test/rsolv_web/controllers/api/v1/vulnerability_validation_cache_test.exs",
  "test/integration/ast_validation_comprehensive_test.exs",
  "test/integration/php_pattern_ast_test.exs",
  "test/rsolv_web/controllers/credential_vending_test.exs",
  "test/rsolv_web/controllers/api/v1/pattern_controller_test.exs",
  "test/rsolv_web/controllers/api/v1/ast_pattern_serialization_test.exs",
  "test/rsolv/accounts_test.exs"
]

Enum.each(test_files, fn file_path ->
  if File.exists?(file_path) do
    content = File.read!(file_path)
    
    # Check if it needs fixing
    if String.contains?(content, "rsolv_test_abc123") do
      IO.puts("Fixing #{file_path}...")
      
      # Add import if not present
      if not String.contains?(content, "import Rsolv.APITestHelpers") do
        content = String.replace(content, 
          ~r/use (RsolvWeb\.ConnCase|Rsolv\.DataCase|Rsolv\.IntegrationCase)(.*?)\n/,
          "\\0  import Rsolv.APITestHelpers\n", 
          global: false)
      end
      
      # Replace the setup block with hardcoded API key
      content = String.replace(content,
        ~r/setup do\s*#.*?api_key = %\{key: "rsolv_test_abc123"\}.*?\{:ok, api_key: api_key\}\s*end/s,
        """
        setup do
          setup_api_auth()
        end
        """)
      
      # Also handle simpler patterns
      content = String.replace(content,
        ~r/api_key = %\{key: "rsolv_test_abc123"\}/,
        "# API key now created by setup_api_auth()")
        
      # Write back the file
      File.write!(file_path, content)
      IO.puts("  ✓ Fixed")
    else
      IO.puts("#{file_path} - no changes needed")
    end
  else
    IO.puts("#{file_path} - file not found")
  end
end)

IO.puts("\nDone!")