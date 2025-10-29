defmodule Rsolv.ReleaseTasks do
  @moduledoc """
  Tasks for production releases including migrations and seeds.

  These tasks are designed to be run in production releases where Mix is not available.
  They handle proper application startup and shutdown for database operations.
  """

  @app :rsolv

  require Logger
  import Ecto.Query

  @doc """
  Run migrations for all repos in the application.

  ## Usage in release

      bin/rsolv eval "Rsolv.ReleaseTasks.migrate"

  ## Usage in Kubernetes Job

      command: ["bin/rsolv", "eval", "Rsolv.ReleaseTasks.migrate"]
  """
  def migrate do
    Logger.info("Running migrations for #{@app}")

    # Start the application to ensure all dependencies are available
    load_app()
    start_services()

    # Run migrations for each repo
    Enum.each(repos(), fn repo ->
      Logger.info("Running migrations for #{inspect(repo)}")
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end)

    Logger.info("Migrations completed successfully")
    stop_services()
  end

  @doc """
  Rollback migrations to a specific version.

  ## Usage

      bin/rsolv eval 'Rsolv.ReleaseTasks.rollback(Rsolv.Repo, 20240101120000)'
  """
  def rollback(repo, version) do
    Logger.info("Rolling back #{inspect(repo)} to version #{version}")

    load_app()
    start_services()

    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))

    Logger.info("Rollback completed")
    stop_services()
  end

  @doc """
  Run seed script for development/staging environments.

  ## Usage

      bin/rsolv eval "Rsolv.ReleaseTasks.seed"
  """
  def seed do
    Logger.info("Running seed script for #{@app}")

    load_app()
    start_services()

    # Run seed script
    seed_script = priv_path("repo/seeds.exs")

    if File.exists?(seed_script) do
      Logger.info("Running seed script: #{seed_script}")
      Code.eval_file(seed_script)
    else
      Logger.warning("No seed script found at: #{seed_script}")
    end

    Logger.info("Seeding completed")
    stop_services()
  end

  @doc """
  Create monthly analytics partitions for the next N months.

  ## Usage

      # Create partitions for next 3 months
      bin/rsolv eval "Rsolv.ReleaseTasks.create_analytics_partitions(3)"
  """
  def create_analytics_partitions(months_ahead \\ 3) do
    Logger.info("Creating analytics partitions for next #{months_ahead} months")

    load_app()
    start_services()

    today = Date.utc_today()

    # Create partitions for current month and future months
    0..months_ahead
    |> Enum.map(fn months ->
      Date.add(today, months * 30)
    end)
    |> Enum.each(fn date ->
      Logger.info("Ensuring partition exists for #{date}")
      Rsolv.Analytics.ensure_partition_exists(DateTime.new!(date, ~T[00:00:00]))
    end)

    Logger.info("Analytics partitions created")
    stop_services()
  end

  @doc """
  Run application setup including migrations, seeds, and initial data.

  ## Usage

      bin/rsolv eval "Rsolv.ReleaseTasks.setup"
  """
  def setup do
    Logger.info("Setting up #{@app}")

    # Run migrations first
    migrate()

    # Create analytics partitions
    create_analytics_partitions()

    # Run seeds if not in production
    if System.get_env("MIX_ENV") != "prod" do
      seed()
    end

    Logger.info("Setup completed")
  end

  @doc """
  Enable a feature flag.

  ## Usage

      bin/rsolv eval "Rsolv.ReleaseTasks.enable_feature_flag(:feedback_form)"
  """
  def enable_feature_flag(flag_name) do
    Logger.info("Enabling feature flag: #{flag_name}")

    load_app()
    start_services()

    # Also start FunWithFlags application
    Application.ensure_all_started(:fun_with_flags)

    result = Rsolv.FeatureFlags.enable(flag_name)
    Logger.info("Feature flag #{flag_name} enabled: #{inspect(result)}")

    stop_services()
  end

  @doc """
  Disable a feature flag.

  ## Usage

      bin/rsolv eval "Rsolv.ReleaseTasks.disable_feature_flag(:feedback_form)"
  """
  def disable_feature_flag(flag_name) do
    Logger.info("Disabling feature flag: #{flag_name}")

    load_app()
    start_services()

    # Also start FunWithFlags application
    Application.ensure_all_started(:fun_with_flags)

    result = Rsolv.FeatureFlags.disable(flag_name)
    Logger.info("Feature flag #{flag_name} disabled: #{inspect(result)}")

    stop_services()
  end

  @doc """
  Check application health including database connectivity and migrations status.

  ## Usage

      bin/rsolv eval "Rsolv.ReleaseTasks.health_check"
  """
  def health_check do
    load_app()
    start_services()

    health = %{
      database: check_database_health(),
      migrations: check_migrations_status(),
      analytics: check_analytics_health()
    }

    Logger.info("Health check results: #{inspect(health, pretty: true)}")

    stop_services()

    # Exit with appropriate code
    if Enum.all?(Map.values(health), &(&1 == :ok)) do
      :ok
    else
      exit({:shutdown, 1})
    end
  end

  @doc """
  Reset staging environment with test customer fixtures.

  This function:
  - ONLY runs if config_env() == :staging (safety check)
  - Deletes test data (emails matching *@example.com or *@test.example.com)
  - Re-seeds with factory fixtures covering various customer states
  - Returns summary of changes

  ## Safety

  This task will refuse to run in :prod environment to prevent accidental
  data deletion in production.

  ## Usage in Kubernetes

      kubectl exec -it <rsolv-pod> -- bin/rsolv eval "Rsolv.ReleaseTasks.reset_staging_data()"

  Or via remote console:

      kubectl exec -it <rsolv-pod> -- bin/rsolv remote
      > Rsolv.ReleaseTasks.reset_staging_data()

  ## Test Data Created

  The function creates customers in the following states:
  - Trial customer with credits (5 credits)
  - Trial customer with billing added (10 credits)
  - Trial expired (0 credits)
  - PAYG active (charges per fix)
  - Pro active (60 credits)
  - Pro past due (payment failure)
  - Pro cancelled (immediate)
  - Pro cancel scheduled (active until period end)
  - Pro with rollover credits
  """
  def reset_staging_data do
    env = config_env()

    Logger.info("Environment detected: #{env}")

    case env do
      :staging ->
        do_reset_staging_data()

      :dev ->
        Logger.warning("Running reset_staging_data in :dev environment")
        do_reset_staging_data()

      :test ->
        Logger.warning("Running reset_staging_data in :test environment")
        do_reset_staging_data()

      :prod ->
        Logger.error("REFUSED: reset_staging_data cannot run in :prod environment")
        {:error, :production_environment}
    end
  end

  # Private functions

  defp do_reset_staging_data do
    Logger.info("Starting staging data reset")

    load_app()
    start_services()

    # Ensure ExMachina is available
    Application.ensure_all_started(:ex_machina)

    alias Rsolv.CustomerFactory
    alias Rsolv.Customers.Customer
    alias Rsolv.Repo

    # Delete test customers (safe domains only)
    test_email_patterns = ["%@test.example.com", "%@example.com"]

    deleted_count =
      Enum.reduce(test_email_patterns, 0, fn pattern, acc ->
        {count, _} = Repo.delete_all(from(c in Customer, where: like(c.email, ^pattern)))
        Logger.info("Deleted #{count} customers matching #{pattern}")
        acc + count
      end)

    Logger.info("Total deleted: #{deleted_count} test customers")

    # Create test fixtures using factory
    fixtures = [
      # Trial customer with initial credits (5 credits)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_trial_credits(),
      # Trial customer with billing added (10 credits)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_billing_added(),
      # Trial expired (0 credits)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_expired_trial(),
      # PAYG active (charges per fix)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_payg(),
      # Pro active (60 credits)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_pro_plan(),
      # Pro active with partial usage (45 credits remaining)
      CustomerFactory.insert(:customer) |> CustomerFactory.with_pro_plan_partial_usage(),
      # Pro past due (payment failure)
      CustomerFactory.insert(:customer)
      |> CustomerFactory.with_pro_plan()
      |> CustomerFactory.with_past_due(),
      # Pro cancelled (immediate)
      CustomerFactory.insert(:customer)
      |> CustomerFactory.with_pro_plan()
      |> CustomerFactory.with_cancelled_pro(),
      # Pro cancel scheduled (active until period end)
      CustomerFactory.insert(:customer)
      |> CustomerFactory.with_pro_plan()
      |> CustomerFactory.with_cancel_scheduled(),
      # Pro with rollover credits
      CustomerFactory.insert(:customer) |> CustomerFactory.with_rollover_credits(10)
    ]

    Logger.info("Created #{length(fixtures)} test customer fixtures")

    # Log summary
    summary = %{
      deleted: deleted_count,
      created: length(fixtures),
      fixture_types: [
        "trial_credits",
        "billing_added",
        "trial_expired",
        "payg_active",
        "pro_active",
        "pro_partial_usage",
        "pro_past_due",
        "pro_cancelled",
        "pro_cancel_scheduled",
        "pro_rollover"
      ]
    }

    Logger.info("Staging data reset complete: #{inspect(summary, pretty: true)}")

    stop_services()

    {:ok, summary}
  end

  defp config_env do
    # Try multiple methods to determine environment
    cond do
      env = System.get_env("MIX_ENV") ->
        String.to_existing_atom(env)

      env = System.get_env("RELEASE_ENV") ->
        String.to_existing_atom(env)

      function_exported?(Mix, :env, 0) ->
        Mix.env()

      true ->
        # Default to checking application environment
        Application.get_env(@app, :environment, :prod)
    end
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.load(@app)
  end

  defp start_services do
    # Start the Repo(s) and other essential services
    # We don't start the full application to avoid starting web servers
    Application.ensure_all_started(:ssl)
    Application.ensure_all_started(:postgrex)
    Application.ensure_all_started(:ecto_sql)

    # Start repos
    Enum.each(repos(), fn repo ->
      {:ok, _} = repo.start_link(pool_size: 2)
    end)
  end

  defp stop_services do
    # Gracefully stop services
    Enum.each(repos(), fn repo ->
      :ok = repo.stop()
    end)
  end

  defp priv_path(path) do
    case :code.priv_dir(@app) do
      {:error, _} ->
        # In development
        Path.join([Path.dirname(__DIR__), "..", "priv", path])

      priv_dir ->
        # In release
        Path.join(priv_dir, path)
    end
  end

  defp check_database_health do
    try do
      Enum.all?(repos(), fn repo ->
        case repo.query("SELECT 1") do
          {:ok, _} -> true
          _ -> false
        end
      end)
      |> case do
        true -> :ok
        false -> :error
      end
    rescue
      _ -> :error
    end
  end

  defp check_migrations_status do
    try do
      pending =
        Enum.flat_map(repos(), fn repo ->
          Ecto.Migrator.migrations(repo, priv_path("repo/migrations"))
          |> Enum.filter(fn {status, _, _} -> status == :down end)
        end)

      case pending do
        [] ->
          :ok

        _ ->
          Logger.warning("Pending migrations: #{length(pending)}")
          :pending
      end
    rescue
      _ -> :error
    end
  end

  defp check_analytics_health do
    try do
      current_date = Date.utc_today()

      partition_name =
        "analytics_events_#{current_date.year}_#{String.pad_leading(to_string(current_date.month), 2, "0")}"

      query = """
        SELECT EXISTS (
          SELECT 1 FROM pg_tables
          WHERE schemaname = 'public'
            AND tablename = $1
        )
      """

      case Rsolv.Repo.query(query, [partition_name]) do
        {:ok, %{rows: [[true]]}} -> :ok
        _ -> :missing_partition
      end
    rescue
      _ -> :error
    end
  end
end
