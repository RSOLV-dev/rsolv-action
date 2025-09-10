#!/usr/bin/env elixir

# Script to fix all User references in test files
# This replaces User-based customer creation with direct Customer creation

defmodule FixUserReferences do
  def run do
    test_files = [
      "test/rsolv/phases/phase_storage_test.exs",
      "test/rsolv/validation_cache/key_generator_test.exs",
      "test/rsolv/validation_cache_integration_test.exs",
      "test/rsolv/validation_cache_test.exs",
      "test/rsolv_web/controllers/api/v1/ast_controller_test.exs",
      "test/rsolv_web/controllers/api/v1/phase_controller_test.exs",
      "test/rsolv_web/controllers/api/v1/phase_retrieve_test.exs",
      "test/rsolv_web/controllers/credential_vending_integration_test.exs",
      "test/rsolv_web/controllers/credential_controller_test.exs"
    ]
    
    Enum.each(test_files, &fix_file/1)
    IO.puts "✅ Fixed all User references in test files"
  end
  
  defp fix_file(file_path) do
    if File.exists?(file_path) do
      content = File.read!(file_path)
      
      # Remove User alias
      content = String.replace(content, "alias Rsolv.Accounts.User\n", "")
      
      # Replace User-based customer creation patterns
      content = fix_user_creation_patterns(content)
      
      # Remove user_id references
      content = String.replace(content, ~r/user_id: user\.id,?\n/, "")
      
      File.write!(file_path, content)
      IO.puts "Fixed: #{file_path}"
    else
      IO.puts "Skipped (not found): #{file_path}"
    end
  end
  
  defp fix_user_creation_patterns(content) do
    # Pattern 1: User with registration changeset
    content = String.replace(content, ~r/user = %Rsolv\.Accounts\.User\{\}.*?\|> Repo\.insert!\(\)/s, 
      "# User creation removed - Customer now handles auth directly")
    
    # Pattern 2: Direct User struct creation
    content = String.replace(content, ~r/user = %Rsolv\.Accounts\.User\{[^}]*\}.*?\|> Repo\.insert!\(\)/s,
      "# User creation removed - Customer now handles auth directly")
      
    # Pattern 3: Customer creation that references user
    content = String.replace(content, ~r/user_id: user\.id,?/s, "")
    
    content
  end
end

FixUserReferences.run()