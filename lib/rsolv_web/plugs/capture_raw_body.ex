defmodule RSOLVWeb.Plugs.CaptureRawBody do
  @moduledoc """
  Captures the raw request body for webhook signature verification.
  Must be placed before Plug.Parsers in the pipeline.
  """

  def init(opts), do: opts

  def call(conn, _opts) do
    require Logger
    
    case Plug.Conn.read_body(conn) do
      {:ok, body, conn} ->
        Logger.debug("CaptureRawBody: Successfully read body: #{inspect(body)}")
        conn
        |> Plug.Conn.assign(:raw_body, body)
        |> Plug.Conn.put_private(:raw_body_read, true)
        
      {:more, _partial, conn} ->
        Logger.debug("CaptureRawBody: Body too large")
        # Body too large
        conn
        
      {:error, reason} ->
        Logger.debug("CaptureRawBody: Error reading body: #{inspect(reason)}")
        # Body already read by Plug.Parsers, reconstruct from params
        raw_body = case conn.body_params do
          %{} = params when map_size(params) > 0 -> 
            Logger.debug("CaptureRawBody: Reconstructing from params: #{inspect(params)}")
            Jason.encode!(params)
          _ ->
            Logger.debug("CaptureRawBody: No params, using empty string")
            ""
        end
        
        conn
        |> Plug.Conn.assign(:raw_body, raw_body)
    end
  end
end