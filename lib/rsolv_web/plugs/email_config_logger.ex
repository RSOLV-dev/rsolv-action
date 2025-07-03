defmodule RsolvWeb.Plugs.EmailConfigLogger do
  @moduledoc """
  Plug to log email configuration on each request for debugging.
  This should be removed once email issues are resolved.
  """
  require Logger
  
  def init(opts), do: opts
  
  def call(conn, _opts) do
    # Only log on specific paths to avoid noise
    if conn.request_path in ["/", "/early-access", "/thank-you"] do
      mailer_config = Application.get_env(:rsolv, Rsolv.Mailer)
      
      Logger.info("[EMAIL CONFIG PLUG] Request to #{conn.request_path}",
        adapter: inspect(mailer_config[:adapter]),
        api_key_present: mailer_config[:api_key] != nil,
        timestamp: DateTime.utc_now() |> DateTime.to_string()
      )
    end
    
    conn
  end
end