defmodule Mix.Tasks.Dev.Preflight do
  @moduledoc """
  Runs pre-flight checks before setting up the development environment.

  Validates:
  - Elixir version compatibility
  - PostgreSQL availability
  - Port availability
  - Node.js availability
  - Required environment variables

  ## Usage

      mix dev.preflight

  Returns exit code 0 if all checks pass, non-zero otherwise.
  """

  use Mix.Task
  require Logger

  @shortdoc "Runs pre-flight checks for development environment"

  # Minimum required versions
  @min_elixir_version "1.18.0"
  @min_otp_version "26.0"
  @required_port 4000

  @impl Mix.Task
  def run(args) do
    # First, check for .env file and offer to run wizard if needed
    unless "--skip-env-check" in args do
      check_env_file()
    end

    Mix.shell().info("\n🔍 Pre-flight checks...")

    checks = [
      &check_elixir_version/0,
      &check_otp_version/0,
      &check_postgresql/0,
      &check_port_availability/0,
      &check_nodejs/0,
      &check_environment_variables/0
    ]

    results = Enum.map(checks, & &1.())
    failed = Enum.filter(results, fn {status, _, _} -> status == :error end)

    Mix.shell().info("")

    if failed == [] do
      Mix.shell().info("✅ All pre-flight checks passed!\n")
      :ok
    else
      Mix.shell().error("❌ #{length(failed)} check(s) failed. Please fix the issues above.\n")
      Mix.raise("Pre-flight checks failed")
    end
  end

  defp check_env_file do
    env_file_exists = File.exists?(".env")
    env_example_exists = File.exists?(".env.example")

    cond do
      not env_file_exists and not env_example_exists ->
        print_warning("Neither .env nor .env.example found")
        print_suggestion("This may indicate you're not in the project root directory")
        Mix.shell().info("")

      not env_file_exists and env_example_exists ->
        print_warning("No .env file found")
        Mix.shell().info("")
        Mix.shell().info("💡 Run the environment setup wizard to create .env:")
        Mix.shell().info("   mix dev.env.setup\n")

        if prompt_yes_no("Would you like to run the wizard now?", true) do
          Mix.Task.run("dev.env.setup", [])
          Mix.shell().info("\nContinuing with pre-flight checks...\n")
        else
          Mix.shell().info("\n⚠️  Continuing without .env configuration")
          Mix.shell().info("   Some features may not work correctly\n")
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
      print_warning("Configuration issues in .env:")
      Enum.each(warnings, fn warning ->
        Mix.shell().info("   • #{warning}")
      end)
      Mix.shell().info("\n💡 Fix these by editing .env or running: mix dev.env.setup --force\n")
    else
      print_success("Environment configuration looks good (.env)")
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

  defp check_elixir_version do
    current = System.version()

    case Version.compare(current, @min_elixir_version) do
      result when result in [:gt, :eq] ->
        print_success("Elixir #{current}")
        {:ok, :elixir, current}

      :lt ->
        print_error("Elixir version too old (#{current})")
        print_suggestion("Upgrade to Elixir >= #{@min_elixir_version}")
        print_suggestion("  asdf install elixir #{@min_elixir_version}")
        {:error, :elixir, current}
    end
  end

  defp check_otp_version do
    current = System.otp_release()

    case Version.compare(current, @min_otp_version) do
      result when result in [:gt, :eq] ->
        print_success("Erlang/OTP #{current}")
        {:ok, :otp, current}

      :lt ->
        print_error("OTP version too old (#{current})")
        print_suggestion("Upgrade to OTP >= #{@min_otp_version}")
        print_suggestion("  asdf install erlang 26.0")
        {:error, :otp, current}
    end
  rescue
    _ ->
      print_warning("Could not detect OTP version")
      {:ok, :otp, "unknown"}
  end

  defp check_postgresql do
    # Try to connect to PostgreSQL using psql command
    case System.cmd("psql", ["--version"], stderr_to_stdout: true) do
      {output, 0} ->
        version = extract_postgres_version(output)
        print_success("PostgreSQL #{version}")

        # Try to verify it's running
        case check_postgres_running() do
          :ok ->
            {:ok, :postgresql, version}

          :error ->
            print_warning("PostgreSQL installed but may not be running")
            print_suggestion("Start PostgreSQL:")
            print_suggestion("  macOS:  brew services start postgresql@16")
            print_suggestion("  Linux:  sudo systemctl start postgresql")
            print_suggestion("  Docker: docker-compose up -d postgres")
            {:error, :postgresql, "not running"}
        end

      {_output, _code} ->
        print_error("PostgreSQL not found")
        print_suggestion("Install PostgreSQL:")
        print_suggestion("  macOS:  brew install postgresql@16")
        print_suggestion("  Linux:  sudo apt install postgresql-16")
        print_suggestion("  Docker: docker-compose up -d postgres")
        {:error, :postgresql, "not installed"}
    end
  end

  defp check_postgres_running do
    db_config = Application.get_env(:rsolv, Rsolv.Repo, [])
    username = Keyword.get(db_config, :username, "postgres")
    hostname = Keyword.get(db_config, :hostname, "localhost")
    port = Keyword.get(db_config, :port, 5432)

    # Try to connect using pg_isready
    try do
      case System.cmd("pg_isready", ["-h", hostname, "-p", to_string(port), "-U", username],
             stderr_to_stdout: true
           ) do
        {_output, 0} -> :ok
        _ -> :error
      end
    rescue
      _ ->
        # If pg_isready doesn't exist, try psql
        try do
          case System.cmd("psql", ["-h", hostname, "-p", to_string(port), "-U", username, "-c", "SELECT 1"],
                 stderr_to_stdout: true
               ) do
            {_output, 0} -> :ok
            _ -> :error
          end
        rescue
          _ -> :error
        end
    end
  end

  defp extract_postgres_version(output) do
    case Regex.run(~r/(\d+\.\d+)/, output) do
      [_, version] -> version
      _ -> "installed"
    end
  end

  defp check_port_availability do
    case :gen_tcp.listen(@required_port, [:binary, active: false, reuseaddr: true]) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        print_success("Port #{@required_port} available")
        {:ok, :port, @required_port}

      {:error, :eaddrinuse} ->
        print_warning("Port #{@required_port} in use")
        print_suggestion("Another process is using port #{@required_port}")
        print_suggestion("  Find process: lsof -ti:#{@required_port}")
        print_suggestion("  Kill process: kill $(lsof -ti:#{@required_port})")
        {:ok, :port, "in use"}

      {:error, reason} ->
        print_error("Cannot bind to port #{@required_port}: #{reason}")
        {:error, :port, reason}
    end
  end

  defp check_nodejs do
    case System.cmd("node", ["--version"], stderr_to_stdout: true) do
      {output, 0} ->
        version = String.trim(output)
        print_success("Node.js #{version}")
        {:ok, :nodejs, version}

      {_output, _code} ->
        print_warning("Node.js not found")
        print_suggestion("Node.js is recommended for asset compilation")
        print_suggestion("  Install: brew install node (macOS) or nvm install --lts")
        {:ok, :nodejs, "not installed"}
    end
  end

  defp check_environment_variables do
    checks = [
      check_database_url(),
      check_secret_key_base(),
      check_ai_keys()
    ]

    # If any required checks fail, overall check fails
    required_failed = Enum.any?(checks, fn {status, required?, _, _} -> status == :error and required? end)

    if required_failed do
      {:error, :env_vars, "required variables missing"}
    else
      {:ok, :env_vars, "ok"}
    end
  end

  defp check_database_url do
    case System.get_env("DATABASE_URL") do
      nil ->
        print_info("DATABASE_URL not set (using config defaults)")
        {:ok, false, :database_url, "using defaults"}

      url ->
        if String.starts_with?(url, "postgres://") or String.starts_with?(url, "postgresql://") do
          print_success("DATABASE_URL configured")
          {:ok, false, :database_url, "set"}
        else
          print_warning("DATABASE_URL format looks incorrect")
          print_suggestion("Should start with postgres:// or postgresql://")
          {:ok, false, :database_url, "invalid format"}
        end
    end
  end

  defp check_secret_key_base do
    case System.get_env("SECRET_KEY_BASE") do
      nil ->
        print_info("SECRET_KEY_BASE not set (OK for dev)")
        print_suggestion("Generate with: mix phx.gen.secret")
        {:ok, false, :secret_key_base, "using default"}

      key when byte_size(key) >= 64 ->
        print_success("SECRET_KEY_BASE configured")
        {:ok, false, :secret_key_base, "set"}

      key ->
        print_warning("SECRET_KEY_BASE too short (#{byte_size(key)} bytes, need 64+)")
        print_suggestion("Generate with: mix phx.gen.secret")
        {:ok, false, :secret_key_base, "too short"}
    end
  end

  defp check_ai_keys do
    anthropic = System.get_env("ANTHROPIC_API_KEY")
    openai = System.get_env("OPENAI_API_KEY")

    cond do
      anthropic && openai ->
        print_success("AI provider keys configured (Anthropic + OpenAI)")
        {:ok, false, :ai_keys, "both"}

      anthropic ->
        print_success("AI provider key configured (Anthropic)")
        {:ok, false, :ai_keys, "anthropic"}

      openai ->
        print_success("AI provider key configured (OpenAI)")
        {:ok, false, :ai_keys, "openai"}

      true ->
        print_warning("No AI provider keys set (AI features will be limited)")
        print_suggestion("Set ANTHROPIC_API_KEY or OPENAI_API_KEY for full functionality")
        {:ok, false, :ai_keys, "none"}
    end
  end

  # Output helpers
  defp print_success(message), do: Mix.shell().info("  ✅ #{message}")
  defp print_error(message), do: Mix.shell().error("  ❌ #{message}")
  defp print_warning(message), do: Mix.shell().info("  ⚠️  #{message}")
  defp print_info(message), do: Mix.shell().info("  ℹ️  #{message}")

  defp print_suggestion(message), do: Mix.shell().info("     💡 #{message}")
end
