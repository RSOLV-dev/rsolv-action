defmodule Mix.Tasks.Dev.Summary do
  @moduledoc """
  Displays a helpful summary after development environment setup.

  Shows:
  - Test credentials (users and passwords)
  - Test API keys
  - Next steps
  - Quick reference links

  ## Usage

      mix dev.summary

  """

  use Mix.Task

  @shortdoc "Displays setup summary with credentials and next steps"

  @impl Mix.Task
  def run(_args) do
    # Start the application to query database
    Mix.Task.run("app.start")

    display_summary()
  end

  defp display_summary do
    Mix.shell().info("\n")
    Mix.shell().info("═══════════════════════════════════════════════════════════")
    Mix.shell().info("🎉 Setup Complete!")
    Mix.shell().info("═══════════════════════════════════════════════════════════\n")

    display_credentials()
    display_api_keys()
    display_next_steps()
    display_elapsed_time()
  end

  defp display_credentials do
    Mix.shell().info("📋 Test Credentials:")
    Mix.shell().info("┌─────────────────┬────────────────────────────┬──────────────────────────┐")
    Mix.shell().info("│ User            │ Email                      │ Password                 │")
    Mix.shell().info("├─────────────────┼────────────────────────────┼──────────────────────────┤")

    credentials = [
      {"Admin", "admin@rsolv.dev", "AdminP@ssw0rd2025!"},
      {"Staff", "staff@rsolv.dev", "StaffP@ssw0rd2025!"},
      {"Test User", "test@example.com", "TestP@ssw0rd2025!"},
      {"Demo", "demo@example.com", "DemoP@ssw0rd2025!"},
      {"Enterprise", "enterprise@bigcorp.com", "EnterpriseP@ssw0rd2025!"}
    ]

    Enum.each(credentials, fn {user, email, password} ->
      Mix.shell().info(
        "│ #{pad_right(user, 15)} │ #{pad_right(email, 26)} │ #{pad_right(password, 24)} │"
      )
    end)

    Mix.shell().info("└─────────────────┴────────────────────────────┴──────────────────────────┘\n")
  end

  defp display_api_keys do
    Mix.shell().info("🔑 Test API Keys:")

    try do
      # Query the database for test API keys
      case Rsolv.Repo.query("""
           SELECT ak.key, c.email
           FROM api_keys ak
           JOIN customers c ON c.id = ak.customer_id
           WHERE c.email IN ('test@example.com', 'demo@example.com', 'admin@rsolv.dev')
           AND ak.active = true
           ORDER BY c.email
           LIMIT 10
           """) do
        {:ok, result} ->
          if result.num_rows > 0 do
            Enum.each(result.rows, fn [key, email] ->
              Mix.shell().info("  • #{key} (#{email})")
            end)
          else
            display_default_api_keys()
          end

        _ ->
          display_default_api_keys()
      end
    rescue
      _ ->
        display_default_api_keys()
    end

    Mix.shell().info("")
  end

  defp display_default_api_keys do
    Mix.shell().info("  • rsolv_test_key_123 (test@example.com)")
    Mix.shell().info("  • rsolv_demo_key_456 (demo@example.com)")
  end

  defp display_next_steps do
    Mix.shell().info("🚀 Next Steps:")
    Mix.shell().info("  1. Start the development server:")
    Mix.shell().info("     mix phx.server")
    Mix.shell().info("")
    Mix.shell().info("  2. View the API documentation:")
    Mix.shell().info("     open http://localhost:4000/api/docs")
    Mix.shell().info("")
    Mix.shell().info("  3. Access the LiveView dashboard:")
    Mix.shell().info("     open http://localhost:4000/dev/dashboard")
    Mix.shell().info("")
    Mix.shell().info("  4. View feature flags:")
    Mix.shell().info("     open http://localhost:4000/dev/feature-flags")
    Mix.shell().info("")

    # Show environment-specific tips
    if System.get_env("ANTHROPIC_API_KEY") do
      Mix.shell().info("  ℹ️  AI features enabled (Anthropic API key detected)")
    else
      Mix.shell().info("  💡 Set ANTHROPIC_API_KEY to enable AI features")
    end

    Mix.shell().info("")
  end

  defp display_elapsed_time do
    # Get the process start time from the shell's history
    # This is approximate, but good enough for feedback
    case :erlang.statistics(:wall_clock) do
      {total_time, _} when total_time > 0 ->
        seconds = div(total_time, 1000)
        minutes = div(seconds, 60)
        remaining_seconds = rem(seconds, 60)

        time_str =
          if minutes > 0 do
            "#{minutes}m #{remaining_seconds}s"
          else
            "#{seconds}s"
          end

        Mix.shell().info("⏱️  Setup completed in ~#{time_str}")

      _ ->
        :ok
    end

    Mix.shell().info("═══════════════════════════════════════════════════════════\n")
  end

  # Helper to pad strings for table formatting
  defp pad_right(str, width) do
    str_length = String.length(str)

    if str_length >= width do
      String.slice(str, 0, width)
    else
      str <> String.duplicate(" ", width - str_length)
    end
  end
end
