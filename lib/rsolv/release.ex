defmodule Rsolv.Release do
  @moduledoc """
  Tasks for Elixir releases - the idiomatic way to run migrations in production
  """
  @app :rsolv

  def migrate do
    load_app()
    
    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def rollback(repo, version) do
    load_app()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  def create_and_migrate do
    load_app()
    
    for repo <- repos() do
      # Create the database if it doesn't exist
      case repo.__adapter__.storage_up(repo.config) do
        :ok -> :ok
        {:error, :already_up} -> :ok
        {:error, term} -> {:error, term}
      end
      
      # Run migrations
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def seed do
    load_app()
    
    # Run the seed script
    seed_script = Path.join([:code.priv_dir(@app), "repo", "seeds.exs"])
    
    if File.exists?(seed_script) do
      Code.eval_file(seed_script)
      IO.puts("Seeds executed successfully")
    else
      IO.puts("Seeds file not found at: #{seed_script}")
    end
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.ensure_all_started(:ssl)
    Application.load(@app)
    
    # Ensure the repo config is loaded
    Application.put_env(@app, Rsolv.Repo, Rsolv.Repo.config())
  end
end