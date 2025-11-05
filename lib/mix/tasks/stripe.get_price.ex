defmodule Mix.Tasks.Stripe.GetPrice do
  @moduledoc """
  Fetches a Stripe price ID by lookup key.

  ## Usage

      # Get Pro monthly price ID for current environment (uses STRIPE_API_KEY)
      mix stripe.get_price pro_monthly

      # Get price from production Stripe account
      STRIPE_API_KEY=sk_live_xxx mix stripe.get_price pro_monthly

  ## Output

  Prints the price ID which can be used in STRIPE_PRO_PRICE_ID environment variable.

  ## Example

      $ mix stripe.get_price pro_monthly
      price_0SPvUw7pIu1KP146qVYwNTQ8

      # Use in deployment:
      export STRIPE_PRO_PRICE_ID=$(mix stripe.get_price pro_monthly)

  ## See Also

  - RFC-066: Stripe integration
  - .env.example: STRIPE_PRO_PRICE_ID documentation
  """
  use Mix.Task

  @shortdoc "Fetches Stripe price ID by lookup key"

  @impl Mix.Task
  def run([lookup_key]) do
    # Load config but don't start the full app (avoid port conflicts)
    Mix.Task.run("loadconfig")

    case fetch_price_by_lookup_key(lookup_key) do
      {:ok, price_id} ->
        Mix.shell().info(price_id)

      {:error, :not_found} ->
        Mix.shell().error("No price found with lookup_key: #{lookup_key}")
        exit({:shutdown, 1})

      {:error, :no_api_key} ->
        Mix.shell().error("STRIPE_API_KEY not set. Please configure it in .env or environment.")
        exit({:shutdown, 1})

      {:error, reason} ->
        Mix.shell().error("Failed to fetch price: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end

  def run(_) do
    Mix.shell().error("Usage: mix stripe.get_price <lookup_key>")
    Mix.shell().error("Example: mix stripe.get_price pro_monthly")
    exit({:shutdown, 1})
  end

  defp fetch_price_by_lookup_key(lookup_key) do
    api_key = System.get_env("STRIPE_API_KEY") || Application.get_env(:stripity_stripe, :api_key)

    unless api_key do
      {:error, :no_api_key}
    else
      do_fetch_price(lookup_key, api_key)
    end
  end

  defp do_fetch_price(lookup_key, api_key) do
    case Stripe.Price.list(%{lookup_keys: [lookup_key]}, api_key: api_key) do
      {:ok, %Stripe.List{data: [price | _]}} ->
        {:ok, price.id}

      {:ok, %Stripe.List{data: []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
