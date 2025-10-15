defmodule Rsolv.BlogFlagEnabler do
  @moduledoc """
  Enables blog flag with Phoenix.PubSub notification for cache invalidation
  """

  def enable_blog_with_notification do
    # Enable the flag
    {:ok, _} = FunWithFlags.enable(:blog)

    # Manually broadcast the cache invalidation
    if Process.whereis(Rsolv.PubSub) do
      Phoenix.PubSub.broadcast(
        Rsolv.PubSub,
        "fun_with_flags_cache_bust",
        {:cache_bust, :blog, [:all]}
      )

      {:ok, :flag_enabled_and_broadcast}
    else
      {:error, :pubsub_not_running}
    end
  end
end
