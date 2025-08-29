defmodule RsolvWeb.Plugs.CacheFeaturePlug do
  @moduledoc """
  Plug to route validation requests to the appropriate controller based on feature flag.
  Allows gradual rollout of the new caching system.
  """
  
  import Plug.Conn
  
  alias FunWithFlags, as: Flags
  alias RsolvWeb.Api.V1.VulnerabilityValidationController
  alias RsolvWeb.Api.V1.VulnerabilityValidationControllerWithCache
  
  def init(opts), do: opts
  
  def call(conn, _opts) do
    # Check if the false positive caching feature is enabled
    case Flags.enabled?(:false_positive_caching) do
      {:ok, true} ->
        # Use the new controller with caching
        VulnerabilityValidationControllerWithCache.validate(conn, conn.params)
        |> halt()
        
      _ ->
        # Use the original controller
        VulnerabilityValidationController.validate(conn, conn.params)
        |> halt()
    end
  end
end