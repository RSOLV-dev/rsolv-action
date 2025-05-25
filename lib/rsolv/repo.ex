defmodule RSOLV.Repo do
  use Ecto.Repo,
    otp_app: :rsolv_api,
    adapter: Ecto.Adapters.Postgres
end