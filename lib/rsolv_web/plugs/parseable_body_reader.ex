defmodule RsolvWeb.Plugs.ParseableBodyReader do
  @moduledoc """
  A body reader that caches the raw body for webhook signature verification
  while still allowing Plug.Parsers to parse the body.
  """

  def read_body(conn, opts) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, body, conn} ->
        # Store the raw body for webhook signature verification
        conn = Plug.Conn.assign(conn, :raw_body, body)
        {:ok, body, conn}

      other ->
        other
    end
  end
end
