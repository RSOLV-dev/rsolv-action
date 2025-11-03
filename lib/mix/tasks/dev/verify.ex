defmodule Mix.Tasks.Dev.Verify do
  @moduledoc """
  Verifies that the development environment setup was successful.

  Validates:
  - Database connectivity
  - Required tables exist
  - Seeds were loaded properly
  - OpenAPI spec was generated
  - Feature flags are initialized
  - Assets are compiled

  ## Usage

      mix dev.verify

  Returns exit code 0 if all verifications pass, non-zero otherwise.
  """

  use Mix.Task
  require Logger

  @shortdoc "Verifies development environment setup"

  @impl Mix.Task
  def run(_args) do
    # Start the application to ensure everything is loaded
    Mix.Task.run("app.start")

    Mix.shell().info("\n🔍 Verifying setup...")

    checks = [
      &verify_database_connection/0,
      &verify_tables_exist/0,
      &verify_seeds_loaded/0,
      &verify_openapi_spec/0,
      &verify_feature_flags/0,
      &verify_assets/0
    ]

    results = Enum.map(checks, & &1.())
    failed = Enum.filter(results, fn {status, _, _} -> status == :error end)

    Mix.shell().info("")

    if failed == [] do
      Mix.shell().info("✅ All verifications passed!\n")
      :ok
    else
      Mix.shell().error("❌ #{length(failed)} verification(s) failed.\n")
      Mix.raise("Setup verification failed")
    end
  end

  defp verify_database_connection do
    try do
      case Rsolv.Repo.query("SELECT 1", []) do
        {:ok, _} ->
          print_success("Database connection working")
          {:ok, :db_connection, "ok"}

        {:error, error} ->
          print_error("Database connection failed: #{inspect(error)}")
          {:error, :db_connection, error}
      end
    rescue
      e ->
        print_error("Database connection error: #{Exception.message(e)}")
        {:error, :db_connection, e}
    end
  end

  defp verify_tables_exist do
    required_tables = [
      "customers",
      "api_keys",
      "vulnerabilities",
      "fix_attempts",
      "schema_migrations"
    ]

    try do
      {:ok, result} =
        Rsolv.Repo.query("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        """)

      existing_tables = result.rows |> List.flatten() |> MapSet.new()
      required_set = MapSet.new(required_tables)
      missing = MapSet.difference(required_set, existing_tables) |> MapSet.to_list()

      if missing == [] do
        print_success("All required tables exist (#{length(required_tables)} tables)")
        {:ok, :tables, length(required_tables)}
      else
        print_error("Missing tables: #{Enum.join(missing, ", ")}")
        print_suggestion("Run: mix ecto.migrate")
        {:error, :tables, missing}
      end
    rescue
      e ->
        print_error("Could not verify tables: #{Exception.message(e)}")
        {:error, :tables, e}
    end
  end

  defp verify_seeds_loaded do
    try do
      # Check if we have at least some test customers
      customer_count = Rsolv.Repo.aggregate(Rsolv.Customers.Customer, :count, :id)
      api_key_count = Rsolv.Repo.aggregate(Rsolv.Customers.ApiKey, :count, :id)

      if customer_count >= 5 and api_key_count >= 5 do
        print_success("Seeds loaded (#{customer_count} customers, #{api_key_count} API keys)")
        {:ok, :seeds, %{customers: customer_count, api_keys: api_key_count}}
      else
        print_warning(
          "Seeds may not be complete (#{customer_count} customers, #{api_key_count} API keys)"
        )

        print_suggestion("Expected at least 5 customers and 5 API keys")
        print_suggestion("Run: mix run priv/repo/seeds.exs")
        {:ok, :seeds, %{customers: customer_count, api_keys: api_key_count}}
      end
    rescue
      e ->
        print_error("Could not verify seeds: #{Exception.message(e)}")
        {:error, :seeds, e}
    end
  end

  defp verify_openapi_spec do
    spec_path = "priv/static/openapi.json"

    case File.stat(spec_path) do
      {:ok, %{size: size}} when size > 1000 ->
        # Parse and validate the spec
        case File.read(spec_path) do
          {:ok, content} ->
            case JSON.decode(content) do
              {:ok, spec} ->
                paths = map_size(Map.get(spec, "paths", %{}))

                print_success(
                  "OpenAPI spec generated (#{paths} endpoints, #{format_bytes(size)})"
                )

                {:ok, :openapi, %{endpoints: paths, size: size}}

              {:error, _} ->
                print_error("OpenAPI spec is invalid JSON")
                print_suggestion("Run: mix rsolv.openapi")
                {:error, :openapi, "invalid json"}
            end

          {:error, _} ->
            print_error("Could not read OpenAPI spec")
            {:error, :openapi, "unreadable"}
        end

      {:ok, %{size: size}} ->
        print_warning("OpenAPI spec seems too small (#{format_bytes(size)})")
        print_suggestion("Run: mix rsolv.openapi")
        {:ok, :openapi, %{size: size}}

      {:error, :enoent} ->
        print_error("OpenAPI spec not found at #{spec_path}")
        print_suggestion("Run: mix rsolv.openapi")
        {:error, :openapi, "not found"}

      {:error, reason} ->
        print_error("Could not check OpenAPI spec: #{reason}")
        {:error, :openapi, reason}
    end
  end

  defp verify_feature_flags do
    try do
      # Try to query feature flags
      case Rsolv.Repo.query("SELECT COUNT(*) FROM fun_with_flags_toggles") do
        {:ok, result} ->
          count = result.rows |> List.first() |> List.first()
          print_success("Feature flags initialized (#{count} flags)")
          {:ok, :feature_flags, count}

        {:error, %{postgres: %{code: :undefined_table}}} ->
          print_warning("Feature flags table not found")
          print_suggestion("Run: mix ecto.migrate")
          {:ok, :feature_flags, 0}

        {:error, error} ->
          print_error("Feature flags check failed: #{inspect(error)}")
          {:error, :feature_flags, error}
      end
    rescue
      e ->
        print_error("Feature flags verification error: #{Exception.message(e)}")
        {:error, :feature_flags, e}
    end
  end

  defp verify_assets do
    # Check for compiled assets
    asset_checks = [
      {"priv/static/assets/app.css", "CSS"},
      {"priv/static/assets/app.js", "JavaScript"}
    ]

    results =
      Enum.map(asset_checks, fn {path, name} ->
        case File.stat(path) do
          {:ok, %{size: size}} when size > 0 ->
            {true, name, size}

          _ ->
            {false, name, 0}
        end
      end)

    compiled = Enum.filter(results, fn {ok, _, _} -> ok end)
    missing = Enum.filter(results, fn {ok, _, _} -> not ok end)

    if missing == [] do
      total_size = Enum.reduce(compiled, 0, fn {_, _, size}, acc -> acc + size end)
      print_success("Assets compiled (#{length(compiled)} files, #{format_bytes(total_size)})")
      {:ok, :assets, length(compiled)}
    else
      missing_names = Enum.map(missing, fn {_, name, _} -> name end)
      print_warning("Some assets not found: #{Enum.join(missing_names, ", ")}")
      print_suggestion("Run: mix assets.build")
      {:ok, :assets, length(compiled)}
    end
  end

  # Helpers
  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes}B"
  defp format_bytes(bytes) when bytes < 1024 * 1024, do: "#{div(bytes, 1024)}KB"
  defp format_bytes(bytes), do: "#{div(bytes, 1024 * 1024)}MB"

  defp print_success(message), do: Mix.shell().info("  ✅ #{message}")
  defp print_error(message), do: Mix.shell().error("  ❌ #{message}")
  defp print_warning(message), do: Mix.shell().info("  ⚠️  #{message}")
  defp print_suggestion(message), do: Mix.shell().info("     💡 #{message}")
end
