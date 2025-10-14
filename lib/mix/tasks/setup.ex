defmodule Mix.Tasks.Setup do
  use Mix.Task

  @shortdoc "Sets up the project for development"

  @moduledoc """
  Sets up the project by running all necessary setup tasks with pre-flight validation.

  This task:
  1. Checks for .env file and offers to run the setup wizard if missing
  2. Validates required environment variables
  3. Runs dependencies, assets, database, and OpenAPI setup
  4. Reports any configuration warnings

  ## Usage

      mix setup

  """

  @aliases_to_run ["deps.get", "assets.setup", "assets.build", "ecto.setup", "rsolv.openapi"]

  def run(_args) do
    IO.puts("\n🚀 " <> IO.ANSI.bright() <> "RSOLV Project Setup" <> IO.ANSI.reset() <> "\n")

    # Pre-flight checks
    preflight_checks()

    # Run all the setup tasks
    IO.puts(IO.ANSI.bright() <> "Running setup tasks..." <> IO.ANSI.reset() <> "\n")

    Enum.each(@aliases_to_run, fn task ->
      IO.puts("▶ Running: " <> IO.ANSI.cyan() <> "mix #{task}" <> IO.ANSI.reset())
      Mix.Task.run(task, [])
    end)

    IO.puts("\n" <> IO.ANSI.green() <> IO.ANSI.bright() <> "✅ Setup complete!" <> IO.ANSI.reset())
    IO.puts("\nNext: " <> IO.ANSI.cyan() <> "mix phx.server" <> IO.ANSI.reset() <> " to start the application\n")
  end

  defp preflight_checks do
    env_file_exists = File.exists?(".env")
    env_example_exists = File.exists?(".env.example")

    cond do
      not env_file_exists and not env_example_exists ->
        IO.puts("⚠️  " <> IO.ANSI.yellow() <> "Warning: Neither .env nor .env.example found" <> IO.ANSI.reset())
        IO.puts("   This may indicate you're not in the project root directory\n")

      not env_file_exists and env_example_exists ->
        IO.puts("⚠️  " <> IO.ANSI.yellow() <> "No .env file found" <> IO.ANSI.reset())
        IO.puts("\n💡 Run the environment setup wizard first:")
        IO.puts("   " <> IO.ANSI.cyan() <> "mix dev.env.setup" <> IO.ANSI.reset() <> "\n")

        if prompt_yes_no("Would you like to run the wizard now?", true) do
          Mix.Task.run("dev.env.setup", [])
          IO.puts("\nContinuing with project setup...\n")
        else
          IO.puts("\n⚠️  Continuing without .env configuration")
          IO.puts("   Some features may not work correctly\n")
        end

      env_file_exists ->
        validate_env_file()
    end
  end

  defp validate_env_file do
    warnings = []

    # Check SECRET_KEY_BASE
    secret = get_env_value("SECRET_KEY_BASE")
    warnings = if secret == nil or String.contains?(secret || "", "your_secret_key_base_here") or String.length(secret || "") < 64 do
      ["SECRET_KEY_BASE is missing or using example value" | warnings]
    else
      warnings
    end

    # Check if any AI provider is configured
    anthropic = get_env_value("ANTHROPIC_API_KEY")
    openai = get_env_value("OPENAI_API_KEY")
    openrouter = get_env_value("OPENROUTER_API_KEY")

    warnings = if (anthropic == nil or anthropic == "") and
                  (openai == nil or openai == "") and
                  (openrouter == nil or openrouter == "") do
      ["No AI provider API keys configured - AI features will be limited" | warnings]
    else
      warnings
    end

    # Display warnings
    unless Enum.empty?(warnings) do
      IO.puts("⚠️  " <> IO.ANSI.yellow() <> "Configuration warnings:" <> IO.ANSI.reset())
      Enum.each(warnings, fn warning ->
        IO.puts("   • #{warning}")
      end)
      IO.puts("\n💡 Fix these by editing .env or running: " <> IO.ANSI.cyan() <> "mix dev.env.setup --force" <> IO.ANSI.reset() <> "\n")
    else
      IO.puts("✅ Environment configuration looks good\n")
    end
  end

  defp get_env_value(key) do
    case File.read(".env") do
      {:ok, content} ->
        Regex.run(~r/^#{Regex.escape(key)}=(.*)$/m, content)
        |> case do
          [_, value] ->
            value = String.trim(value)
            if value == "", do: nil, else: value
          _ ->
            nil
        end

      {:error, _} ->
        nil
    end
  end

  defp prompt_yes_no(question, default \\ true) do
    default_str = if default, do: "Y/n", else: "y/N"

    case IO.gets("#{question} [#{default_str}] ") do
      input when is_binary(input) ->
        case String.trim(String.downcase(input)) do
          "" -> default
          "y" -> true
          "yes" -> true
          "n" -> false
          "no" -> false
          _ -> default
        end

      _ ->
        default
    end
  end
end
