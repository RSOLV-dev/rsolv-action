defmodule Mix.Tasks.Assets.Deploy do
  @moduledoc """
  Deploy assets for production.
  """
  use Mix.Task

  @shortdoc "Deploy assets for production"
  def run(_) do
    Mix.shell().info("Building assets for production...")

    # Run npm build in production mode
    System.cmd("npm", ["run", "deploy"], cd: "assets", into: IO.stream(:stdio, :line))

    # Copy static assets
    System.cmd("cp", ["-r", "priv/static/.", "priv/static/"], into: IO.stream(:stdio, :line))

    # Generate cache manifest
    Mix.Task.run("phx.digest", [])

    Mix.shell().info("Assets deployed successfully!")
  end
end
