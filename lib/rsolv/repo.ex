defmodule Rsolv.Repo do
  use Ecto.Repo,
    otp_app: :rsolv,
    adapter: Ecto.Adapters.Postgres
end
