defmodule RSOLV.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Telemetry supervisor
      RSOLVWeb.Telemetry,
      # Start the Ecto repository
      RSOLV.Repo,
      # Start the PubSub system
      {Phoenix.PubSub, name: RSOLV.PubSub},
      # Start Cachex
      {Cachex, name: :rsolv_cache},
      # Start the Endpoint (http/https)
      RSOLVWeb.Endpoint
      # Start a worker by calling: RSOLV.Worker.start_link(arg)
      # {RSOLV.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: RSOLV.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    RSOLVWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end