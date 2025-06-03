defmodule RSOLVWeb.Plugs.CaptureRawBody do
  @moduledoc """
  Captures the raw request body for webhook signature verification.
  Must be placed before Plug.Parsers in the pipeline.
  """

  def init(opts), do: opts

  def call(conn, _opts) do
    case Plug.Conn.read_body(conn) do
      {:ok, body, conn} ->
        conn
        |> Plug.Conn.assign(:raw_body, body)
        |> Plug.Conn.put_private(:raw_body_read, true)
        
      {:more, _partial, conn} ->
        # Body too large
        conn
        
      {:error, _reason} ->
        # Body already read by Plug.Parsers, reconstruct from params
        raw_body = case conn.body_params do
          %{} = params when map_size(params) > 0 -> 
            Jason.encode!(params)
          _ ->
            ""
        end
        
        conn
        |> Plug.Conn.assign(:raw_body, raw_body)
    end
  end
end