defmodule RsolvApi.Release do
  @moduledoc """
  Tasks for Elixir releases - the idiomatic way to run migrations in production
  """
  @app :rsolv_api

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

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.ensure_all_started(:ssl)
    Application.load(@app)
    
    # Ensure the repo config is loaded
    Application.put_env(@app, RsolvApi.Repo, RsolvApi.Repo.config())
  end
end