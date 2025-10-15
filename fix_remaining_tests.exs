#!/usr/bin/env elixir

# Script to fix remaining test files with hardcoded API keys

files_to_fix = [
  "test/integration/ast_validation_comprehensive_test.exs",
  "test/integration/php_pattern_ast_test.exs",
  "test/rsolv/accounts_test.exs",
  "test/rsolv_web/controllers/api/v1/ast_pattern_serialization_test.exs",
  "test/rsolv_web/controllers/api/v1/pattern_controller_test.exs",
  "test/rsolv_web/controllers/credential_vending_test.exs"
]

Enum.each(files_to_fix, fn file ->
  if File.exists?(file) do
    IO.puts("Fixing #{file}...")
    content = File.read!(file)

    # Add import if not present and uses ConnCase or DataCase
    if String.contains?(content, ["RsolvWeb.ConnCase", "Rsolv.DataCase", "Rsolv.IntegrationCase"]) and
         not String.contains?(content, "import Rsolv.APITestHelpers") do
      content =
        String.replace(
          content,
          ~r/(use (RsolvWeb\.ConnCase|Rsolv\.DataCase|Rsolv\.IntegrationCase)[^\n]*\n)/,
          "\\1  import Rsolv.APITestHelpers\n",
          global: false
        )
    end

    # Replace hardcoded API key module attribute
    content =
      String.replace(
        content,
        ~r/@api_key "rsolv_test_abc123"/,
        "# API key now created dynamically in setup"
      )

    # Replace hardcoded customer setup
    if String.contains?(content, "api_key: @api_key") or
         String.contains?(content, "api_key: \"rsolv_test_abc123\"") do
      # Replace the entire setup that creates hardcoded customer
      content =
        String.replace(
          content,
          ~r/setup do\s*#[^\n]*\n\s*customer = %\{[\s\S]*?\}\s*\n\s*\{:ok, customer: customer\}\s*end/,
          """
          setup do
            setup_api_auth()
          end
          """
        )
    end

    # Update test signatures that reference customer
    content =
      String.replace(
        content,
        ~r/test "(.*?)", %\{conn: conn, customer: customer\} do/,
        "test \"\\1\", %{conn: conn, customer: customer, api_key: api_key} do"
      )

    # Replace @api_key references with api_key.key
    content =
      String.replace(
        content,
        ~r/put_req_header\("x-api-key", @api_key\)/,
        "put_req_header(\"x-api-key\", api_key.key)"
      )

    content =
      String.replace(
        content,
        ~r/put_req_header\("x-api-key", customer\.api_key\)/,
        "put_req_header(\"x-api-key\", api_key.key)"
      )

    File.write!(file, content)
    IO.puts("  ✓ Fixed")
  else
    IO.puts("#{file} - not found")
  end
end)

IO.puts("\nDone!")
