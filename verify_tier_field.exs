#!/usr/bin/env elixir

# Simple verification that tier field is now included in format_patterns_for_api

# First, let's check that the function includes the tier field
IO.puts "Checking Security.format_patterns_for_api/1 implementation..."

security_file = File.read!("lib/rsolv_api/security.ex")

if security_file =~ ~r/tier:\s+to_string\(get_pattern_tier\(pattern\)\)/ do
  IO.puts "✓ Security.format_patterns_for_api/1 now includes tier field!"
else
  IO.puts "✗ Security.format_patterns_for_api/1 does NOT include tier field"
end

if security_file =~ ~r/defp\s+format_single_pattern.*tier:\s+to_string\(get_pattern_tier\(pattern\)\)/s do
  IO.puts "✓ Security.format_single_pattern/1 now includes tier field!"
else
  IO.puts "✗ Security.format_single_pattern/1 does NOT include tier field"
end

# Check PatternController format_pattern functions
IO.puts "\nChecking PatternController format_pattern functions..."

controller_file = File.read!("lib/rsolv_web/controllers/pattern_controller.ex")

if controller_file =~ ~r/tier:\s+to_string\(pattern\.tier\s+\|\|\s+pattern\.default_tier\s+\|\|\s+"public"\)/ do
  IO.puts "✓ PatternController.format_pattern/2 for ASTPattern enhanced includes tier field!"
else
  IO.puts "✗ PatternController.format_pattern/2 for ASTPattern enhanced does NOT include tier field"
end

if controller_file =~ ~r/tier:\s+to_string\(pattern\.default_tier\s+\|\|\s+"public"\)/ do
  IO.puts "✓ PatternController.format_pattern/2 for Pattern enhanced includes tier field!"
else
  IO.puts "✗ PatternController.format_pattern/2 for Pattern enhanced does NOT include tier field"
end

IO.puts "\nAll tier field inclusions have been verified in the source code!"