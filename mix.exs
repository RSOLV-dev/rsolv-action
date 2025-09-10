defmodule Rsolv.MixProject do
  use Mix.Project

  def project do
    [
      app: :rsolv,
      version: "0.1.0",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      mod: {Rsolv.Application, []},
      extra_applications: [:logger, :runtime_tools, :telemetry, :os_mon, :mnesia]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      {:phoenix_ecto, "~> 4.4"},
      {:ecto_sql, "~> 3.10"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_live_dashboard, "~> 0.8"},
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:plug_cowboy, "~> 2.5"},
      {:cors_plug, "~> 3.0"},
      {:bamboo, "~> 2.0"},
      {:bamboo_postmark, "~> 1.0"},
      {:ex_machina, "~> 2.7", only: :test},
      {:mock, "~> 0.3", only: :test},
      {:timex, "~> 3.7"},
      {:quantum, "~> 3.5"},
      {:cachex, "~> 3.6"},
      {:ex_rated, "~> 2.1"},
      {:httpoison, "~> 2.0"},
      {:tesla, "~> 1.4"},
      {:hackney, "~> 1.18"},
      {:libcluster, "~> 3.3"},
      {:prom_ex, "~> 1.9"},
      {:bcrypt_elixir, "~> 3.0"},
      {:phoenix_html, "~> 4.0"},
      {:phoenix_live_view, "~> 1.1"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:tidewave, "~> 0.4", only: :dev},
      {:fun_with_flags, "~> 1.11"},
      {:fun_with_flags_ui, "~> 1.0"},
      {:mdex, "~> 0.7"},
      {:yaml_elixir, "~> 2.9"},
      {:mox, "~> 1.0", only: :test},
      {:floki, ">= 0.30.0", only: :test},
      {:lazy_html, "~> 0.1", only: :test},
      {:local_cluster, "~> 2.0", only: :test},
      {:oban, "~> 2.17"},
      {:number, "~> 1.0"},
      {:esbuild, "~> 0.8", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.2", runtime: Mix.env() == :dev}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "assets.setup", "assets.build", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      "assets.setup": ["tailwind.install --if-missing", "esbuild.install --if-missing"],
      "assets.build": ["tailwind default", "esbuild default"],
      "assets.deploy": ["tailwind default --minify", "esbuild default --minify", "phx.digest"]
    ]
  end
end