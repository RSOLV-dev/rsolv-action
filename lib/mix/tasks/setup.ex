defmodule Mix.Tasks.Setup do
  use Mix.Task

  @shortdoc "Sets up the project for development"

  @moduledoc """
  Sets up the project by running all necessary setup tasks with comprehensive validation.

  This is the standard entry point for project setup. It delegates to the enhanced
  setup implementation in `Mix.Tasks.Dev.Setup` which provides:

  1. Environment file (.env) checking and wizard
  2. Pre-flight system checks (Elixir, PostgreSQL, ports, etc.)
  3. Dependency installation
  4. Asset compilation
  5. Database setup and migrations
  6. OpenAPI spec generation
  7. Post-setup verification
  8. Summary with test credentials

  ## Usage

      mix setup

  ## Options

  All options are passed through to `dev.setup`:

      --skip-preflight    Skip pre-flight checks (not recommended)
      --skip-verify       Skip post-setup verification
      --quiet             Reduce output verbosity

  ## Examples

      # Standard setup (recommended)
      mix setup

      # Quick setup without checks
      mix setup --skip-preflight --skip-verify

      # Quiet mode
      mix setup --quiet

  ## Related Tasks

  - `mix dev.env.setup` - Create/configure .env file
  - `mix dev.preflight` - Run pre-flight checks only
  - `mix dev.verify` - Run post-setup verification only
  - `mix dev.summary` - Display setup summary only

  """

  def run(args) do
    # Delegate to the enhanced setup implementation
    Mix.Task.run("dev.setup", args)
  end
end
