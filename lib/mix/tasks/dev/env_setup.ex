defmodule Mix.Tasks.Dev.EnvSetup do
  use Mix.Task

  @shortdoc "Interactive environment setup wizard for RSOLV development"

  @moduledoc """
  Sets up the development environment by creating a .env file with all necessary configuration.

  This task:
  1. Copies .env.example to .env (if .env doesn't exist)
  2. Generates a secure SECRET_KEY_BASE
  3. Optionally prompts for AI provider API keys
  4. Validates PostgreSQL connection
  5. Displays setup summary

  ## Usage

      mix dev.env.setup

  ## Options

      --force    Overwrite existing .env file

  """

  @env_file ".env"
  @env_example ".env.example"

  def run(args) do
    {opts, _, _} = OptionParser.parse(args, switches: [force: :boolean])
    force = Keyword.get(opts, :force, false)

    IO.puts("\n🔧 " <> IO.ANSI.bright() <> "RSOLV Environment Setup Wizard" <> IO.ANSI.reset() <> "\n")

    cond do
      File.exists?(@env_file) and not force ->
        IO.puts("✅ Found existing .env file")
        IO.puts("\n💡 Run with --force to overwrite: " <> IO.ANSI.cyan() <> "mix dev.env.setup --force" <> IO.ANSI.reset())
        IO.puts("   Or edit .env manually\n")

      not File.exists?(@env_example) ->
        IO.puts("❌ Error: .env.example not found")
        IO.puts("   This file should exist in the project root\n")
        exit({:shutdown, 1})

      true ->
        setup_environment(force)
    end
  end

  defp setup_environment(force) do
    if force and File.exists?(@env_file) do
      IO.puts("⚠️  " <> IO.ANSI.yellow() <> "Overwriting existing .env file" <> IO.ANSI.reset())
    end

    # Step 1: Copy .env.example to .env
    IO.puts("📋 Copying .env.example to .env...")
    File.copy!(@env_example, @env_file)
    IO.puts("✅ Created .env file\n")

    # Step 2: Generate SECRET_KEY_BASE
    IO.puts("🔐 Generating SECRET_KEY_BASE...")
    secret_key_base = generate_secret_key_base()
    update_env_value("SECRET_KEY_BASE", secret_key_base)
    IO.puts("✅ SECRET_KEY_BASE configured\n")

    # Step 3: Prompt for AI provider keys
    ai_configured = setup_ai_providers()

    # Step 4: Validate database connection
    db_valid = validate_database()

    # Step 5: Check optional services
    email_configured = check_env_value("POSTMARK_API_KEY")

    # Step 6: Display summary
    display_summary(ai_configured, db_valid, email_configured)
  end

  defp generate_secret_key_base do
    # Generate 64 bytes of random data and encode as base64
    :crypto.strong_rand_bytes(64)
    |> Base.encode64()
    |> String.slice(0, 64)
  end

  defp setup_ai_providers do
    IO.puts("🤖 " <> IO.ANSI.bright() <> "AI Provider Setup" <> IO.ANSI.reset())
    IO.puts("   AI features require at least one provider API key.")
    IO.puts("   You can skip this and add keys later to .env\n")

    case prompt_yes_no("Would you like to configure AI providers now?", true) do
      true ->
        anthropic_configured = prompt_for_api_key(
          "Anthropic",
          "ANTHROPIC_API_KEY",
          "https://console.anthropic.com/"
        )

        openai_configured = prompt_for_api_key(
          "OpenAI",
          "OPENAI_API_KEY",
          "https://platform.openai.com/api-keys"
        )

        openrouter_configured = prompt_for_api_key(
          "OpenRouter",
          "OPENROUTER_API_KEY",
          "https://openrouter.ai/keys"
        )

        IO.puts("")
        anthropic_configured or openai_configured or openrouter_configured

      false ->
        IO.puts("⏭️  Skipping AI provider configuration\n")
        false
    end
  end

  defp prompt_for_api_key(provider_name, env_var, signup_url) do
    IO.puts("\n#{provider_name} API Key")
    IO.puts("   Get yours at: " <> IO.ANSI.cyan() <> signup_url <> IO.ANSI.reset())

    case IO.gets("   Enter API key (or press Enter to skip): ") do
      key when is_binary(key) ->
        key = String.trim(key)
        if key == "" do
          IO.puts("   ⏭️  Skipping #{provider_name}")
          false
        else
          update_env_value(env_var, key)
          IO.puts("   ✅ #{provider_name} configured")
          true
        end

      _ ->
        IO.puts("   ⏭️  Skipping #{provider_name}")
        false
    end
  end

  defp validate_database do
    IO.puts("🗄️  " <> IO.ANSI.bright() <> "Database Configuration" <> IO.ANSI.reset())

    current_url = get_env_value("DATABASE_URL")
    IO.puts("   Current: " <> IO.ANSI.cyan() <> current_url <> IO.ANSI.reset())

    if prompt_yes_no("Test database connection?", true) do
      IO.puts("   Testing PostgreSQL connection...")

      case test_database_connection(current_url) do
        :ok ->
          IO.puts("   ✅ Database connection successful\n")
          true

        {:error, :econnrefused} ->
          IO.puts("   ❌ Connection refused - PostgreSQL may not be running")
          suggest_database_alternatives()
          false

        {:error, reason} ->
          IO.puts("   ❌ Connection failed: #{inspect(reason)}")
          suggest_database_alternatives()
          false
      end
    else
      IO.puts("   ⏭️  Skipping database test\n")
      true
    end
  end

  defp test_database_connection(database_url) do
    # Parse the database URL
    case parse_database_url(database_url) do
      {:ok, config} ->
        try do
          # Try to connect using Postgrex directly
          case Postgrex.start_link(config) do
            {:ok, pid} ->
              GenServer.stop(pid)
              :ok

            {:error, reason} ->
              {:error, reason}
          end
        rescue
          e -> {:error, e}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_database_url(url) do
    uri = URI.parse(url)

    if uri.scheme == "postgresql" and uri.host do
      config = [
        hostname: uri.host,
        port: uri.port || 5432,
        username: uri.userinfo && String.split(uri.userinfo, ":") |> List.first(),
        password: uri.userinfo && String.split(uri.userinfo, ":") |> List.last(),
        database: String.trim_leading(uri.path || "", "/")
      ]

      {:ok, config}
    else
      {:error, :invalid_url}
    end
  end

  defp suggest_database_alternatives do
    IO.puts("\n   Common database URLs:")
    IO.puts("   1. postgresql://postgres:postgres@localhost/rsolv_dev")
    IO.puts("   2. postgresql://localhost/rsolv_dev")
    IO.puts("   3. Custom URL")

    case IO.gets("   Choose an option (1-3) or press Enter to keep current: ") do
      choice when is_binary(choice) ->
        choice = String.trim(choice)

        new_url = case choice do
          "1" -> "postgresql://postgres:postgres@localhost/rsolv_dev"
          "2" -> "postgresql://localhost/rsolv_dev"
          "3" ->
            case IO.gets("   Enter database URL: ") do
              url when is_binary(url) -> String.trim(url)
              _ -> nil
            end
          _ -> nil
        end

        if new_url do
          update_env_value("DATABASE_URL", new_url)
          IO.puts("   ✅ Updated DATABASE_URL\n")
        end

      _ ->
        IO.puts("   Keeping current configuration\n")
    end
  end

  defp check_env_value(key) do
    value = get_env_value(key)
    value != nil and value != ""
  end

  defp get_env_value(key) do
    case File.read(@env_file) do
      {:ok, content} ->
        Regex.run(~r/^#{key}=(.*)$/m, content)
        |> case do
          [_, value] -> String.trim(value)
          _ -> nil
        end

      {:error, _} ->
        nil
    end
  end

  defp update_env_value(key, value) do
    content = File.read!(@env_file)

    # Escape special regex characters in the key
    escaped_key = Regex.escape(key)

    # Replace the value for this key
    new_content = Regex.replace(
      ~r/^#{escaped_key}=.*$/m,
      content,
      "#{key}=#{value}"
    )

    File.write!(@env_file, new_content)
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

  defp display_summary(ai_configured, db_valid, email_configured) do
    IO.puts("\n" <> IO.ANSI.bright() <> "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" <> IO.ANSI.reset())
    IO.puts(IO.ANSI.green() <> IO.ANSI.bright() <> "✅ Environment configured!" <> IO.ANSI.reset())
    IO.puts(IO.ANSI.bright() <> "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" <> IO.ANSI.reset() <> "\n")

    IO.puts("Configuration Status:")
    IO.puts("  🔒 Required variables:  " <> status_icon(true) <> " Configured")
    IO.puts("  🗄️  Database:           " <> status_icon(db_valid) <> if db_valid, do: " Connected", else: " Not tested")
    IO.puts("  🤖 AI providers:        " <> status_icon(ai_configured) <> if ai_configured, do: " Configured", else: " Not configured")
    IO.puts("  📧 Email (Postmark):    " <> status_icon(email_configured) <> if email_configured, do: " Configured", else: " Not configured (optional)")

    IO.puts("\n" <> IO.ANSI.bright() <> "Next Steps:" <> IO.ANSI.reset())
    IO.puts("  1. Review and edit .env if needed")
    IO.puts("  2. Run: " <> IO.ANSI.cyan() <> "mix setup" <> IO.ANSI.reset() <> " to complete project setup")
    IO.puts("  3. Start the server: " <> IO.ANSI.cyan() <> "mix phx.server" <> IO.ANSI.reset())

    unless ai_configured do
      IO.puts("\n" <> IO.ANSI.yellow() <> "⚠️  Note: AI features require at least one provider API key" <> IO.ANSI.reset())
      IO.puts("   Add keys to .env to enable full functionality")
    end

    IO.puts("")
  end

  defp status_icon(true), do: IO.ANSI.green() <> "✅" <> IO.ANSI.reset()
  defp status_icon(false), do: IO.ANSI.yellow() <> "⚠️ " <> IO.ANSI.reset()
end
