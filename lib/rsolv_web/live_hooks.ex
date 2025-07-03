defmodule RsolvWeb.LiveHooks do
  @moduledoc """
  LiveView hooks for common functionality across all LiveViews
  """
  
  import Phoenix.Component

  def on_mount(:assign_current_path, _params, _session, socket) do
    # Extract current path from the socket's URI
    current_path = case socket.private.connect_params do
      %{"url" => url} when is_binary(url) ->
        case URI.parse(url) do
          %URI{path: path, query: nil} when is_binary(path) -> path
          %URI{path: path, query: query} when is_binary(path) and is_binary(query) -> "#{path}?#{query}"
          %URI{path: path} when is_binary(path) -> path
          _ -> "/"
        end
      _ -> 
        "/"
    end
    
    {:cont, assign(socket, :current_path, current_path)}
  end
end