defmodule RsolvWeb.MetricsController do
  use RsolvWeb, :controller
  require Logger

  # Use PromEx.Plug for metrics export
  plug PromEx.Plug, prom_ex_module: Rsolv.PromEx

  def index(conn, _params) do
    # PromEx.Plug will handle the metrics export automatically
    # This should never be reached since the plug sends the response
    conn
  end
end
