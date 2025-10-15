#!/usr/bin/env elixir

# Clean E2E Smoke Test for AST Service (without Mix install)
# Tests all 5 required languages

# Load application path
File.cd!(Path.dirname(__ENV__.file))

# Ensure code paths are set
Code.prepend_path("_build/dev/lib/rsolv_api/ebin")
Code.prepend_path("_build/dev/lib/rsolv_api/consolidated")

# Start required applications
{:ok, _} = Application.ensure_all_started(:rsolv_api)

alias Rsolv.AST.{SessionManager, ParserRegistry, AnalysisService}

IO.puts("🔥 Starting AST Service Smoke Test...\n")

# Create a test session
{:ok, session} = SessionManager.create_session("smoke-test-customer")
session_id = session.id
IO.puts("✅ Created session: #{session_id}")

# Test code samples
test_codes = %{
  "javascript" => """
  function vulnerable(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
  }
  """,
  "python" => """
  def get_user(user_id):
      # SQL injection vulnerability
      query = f"SELECT * FROM users WHERE id = {user_id}"
      return db.execute(query)
  """,
  "ruby" => """
  def find_user(name)
    # SQL injection vulnerability
    User.where("name = '\#{name}'")
  end
  """,
  "php" => """
  <?php
  function display_message($message) {
      // XSS vulnerability
      echo $message;
  }
  ?>
  """,
  "elixir" => """
  defmodule Vulnerable do
    def run_command(user_input) do
      # Command injection vulnerability
      System.cmd("sh", ["-c", user_input])
    end
  end
  """
}

# Helper functions
defmodule Helpers do
  def count_nodes(ast) when is_map(ast) do
    1 +
      Enum.reduce(ast, 0, fn
        {_k, v}, acc when is_map(v) -> acc + count_nodes(v)
        {_k, v}, acc when is_list(v) -> acc + Enum.reduce(v, 0, &(count_nodes(&1) + &2))
        _, acc -> acc
      end)
  end

  def count_nodes(ast) when is_list(ast) do
    Enum.reduce(ast, 0, &(count_nodes(&1) + &2))
  end

  def count_nodes(ast) when is_tuple(ast) do
    # For Elixir AST tuples
    1 + tuple_size(ast)
  end

  def count_nodes(_), do: 1

  def ext_for_language("javascript"), do: "js"
  def ext_for_language("python"), do: "py"
  def ext_for_language("ruby"), do: "rb"
  def ext_for_language("php"), do: "php"
  def ext_for_language("elixir"), do: "ex"
  def ext_for_language(_), do: "txt"
end

# Test each language
results =
  Enum.map(test_codes, fn {language, code} ->
    IO.puts("\n📝 Testing #{language}...")

    # Test parsing
    case ParserRegistry.parse_code(session_id, "smoke-test-customer", language, code) do
      {:ok, %{ast: ast}} ->
        IO.puts("  ✅ Parsing successful")
        IO.puts("  📊 AST nodes: #{Helpers.count_nodes(ast)}")

        # Test analysis
        file = %{
          path: "test.#{Helpers.ext_for_language(language)}",
          content: code,
          language: language
        }

        analysis_result = AnalysisService.analyze_file(file, %{})

        case analysis_result do
          {:ok, result} when is_map(result) ->
            findings = Map.get(result, :findings, [])
            IO.puts("  ✅ Analysis successful")
            IO.puts("  🔍 Findings: #{length(findings)}")

            if is_map(result[:astStats]) do
              IO.puts("  ⏱️  Parse time: #{result.astStats[:parseTimeMs]}ms")
            end

            if length(findings) > 0 do
              finding = hd(findings)

              IO.puts(
                "  🚨 Found: #{finding.type} (confidence: #{Float.round(finding.confidence, 3)})"
              )
            end

            {:ok, language, findings}

          {:ok, findings} when is_list(findings) ->
            # Direct findings list (backward compatibility)
            IO.puts("  ✅ Analysis successful")
            IO.puts("  🔍 Findings: #{length(findings)}")

            if length(findings) > 0 do
              finding = hd(findings)

              IO.puts(
                "  🚨 Found: #{finding.type} (confidence: #{Float.round(finding.confidence, 3)})"
              )
            end

            {:ok, language, findings}

          {:error, reason} ->
            IO.puts("  ❌ Analysis failed: #{inspect(reason)}")
            {:error, language, reason}
        end

      {:error, reason} ->
        IO.puts("  ❌ Parsing failed: #{inspect(reason)}")
        {:error, language, reason}
    end
  end)

# Cleanup
SessionManager.delete_session(session_id, "test-customer")

# Summary
IO.puts("\n\n📊 SUMMARY")
IO.puts("==========")

successful = Enum.filter(results, fn {status, _, _} -> status == :ok end)
failed = Enum.filter(results, fn {status, _, _} -> status == :error end)

IO.puts("✅ Successful: #{length(successful)}/5 languages")
IO.puts("❌ Failed: #{length(failed)}/5 languages")

if length(successful) == 5 do
  IO.puts("\n🎉 All languages working! Ready for Phase 6!")
else
  IO.puts("\n⚠️  Some languages need attention before Phase 6")

  Enum.each(failed, fn {:error, lang, reason} ->
    IO.puts("  - #{lang}: #{inspect(reason)}")
  end)
end

# Exit cleanly
System.halt(0)
