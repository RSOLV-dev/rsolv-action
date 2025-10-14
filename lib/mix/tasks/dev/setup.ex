defmodule Mix.Tasks.Dev.Setup do
  @moduledoc """
  Enhanced development environment setup with validation and helpful feedback.

  This task orchestrates the complete setup process:
  1. Pre-flight checks (system requirements)
  2. Dependency installation
  3. Asset setup and compilation
  4. Database creation and migration
  5. Seed data loading
  6. OpenAPI spec generation
  7. Post-setup verification
  8. Summary with credentials and next steps

  ## Usage

      mix dev.setup

  The task will exit if pre-flight checks fail, preventing wasted time on
  incomplete setups. All output is designed to be clear and actionable.

  ## Options

      --skip-preflight    Skip pre-flight checks (not recommended)
      --skip-verify       Skip post-setup verification
      --quiet             Reduce output verbosity

  ## Examples

      # Normal setup (recommended)
      mix dev.setup

      # Quick setup (skip checks)
      mix dev.setup --skip-preflight --skip-verify

  """

  use Mix.Task

  @shortdoc "Enhanced development environment setup with validation"

  @impl Mix.Task
  def run(args) do
    start_time = System.monotonic_time(:millisecond)

    {opts, _, _} =
      OptionParser.parse(args,
        switches: [skip_preflight: :boolean, skip_verify: :boolean, quiet: :boolean],
        aliases: [q: :quiet]
      )

    Mix.shell().info("\n🚀 RSOLV Development Environment Setup")
    Mix.shell().info("══════════════════════════════════════════\n")

    # Step 1: Pre-flight checks
    unless opts[:skip_preflight] do
      run_step("Pre-flight checks", "dev.preflight", opts)
    end

    # Step 2: Install dependencies
    run_step("Installing dependencies", "deps.get", opts)

    # Step 3: Setup assets
    run_step("Setting up asset tools", "assets.setup", opts)

    # Step 4: Build assets
    run_step("Compiling assets", "assets.build", opts)

    # Step 5: Setup database
    run_step("Setting up database", "ecto.setup", opts)

    # Step 6: Generate OpenAPI spec
    run_step("Generating OpenAPI spec", "rsolv.openapi", opts)

    # Step 7: Verify setup
    unless opts[:skip_verify] do
      run_step("Verifying setup", "dev.verify", opts)
    end

    # Step 8: Display summary
    unless opts[:quiet] do
      Mix.Task.run("dev.summary")
    end

    end_time = System.monotonic_time(:millisecond)
    elapsed_ms = end_time - start_time
    elapsed_sec = div(elapsed_ms, 1000)
    minutes = div(elapsed_sec, 60)
    seconds = rem(elapsed_sec, 60)

    unless opts[:quiet] do
      time_str =
        if minutes > 0 do
          "#{minutes}m #{seconds}s"
        else
          "#{elapsed_sec}s"
        end

      Mix.shell().info("\n✨ Total setup time: #{time_str}\n")
    end

    :ok
  end

  defp run_step(description, task, opts) do
    unless opts[:quiet] do
      Mix.shell().info("📦 #{description}...")
    end

    start_time = System.monotonic_time(:millisecond)

    try do
      Mix.Task.run(task)

      end_time = System.monotonic_time(:millisecond)
      elapsed_ms = end_time - start_time
      elapsed_sec = (elapsed_ms / 1000) |> Float.round(1)

      unless opts[:quiet] do
        Mix.shell().info("   ✅ Complete (#{elapsed_sec}s)\n")
      end

      :ok
    rescue
      e ->
        Mix.shell().error("\n❌ Failed during: #{description}")
        Mix.shell().error("   Error: #{Exception.message(e)}\n")
        Mix.raise("Setup failed at step: #{description}")
    end
  end
end
