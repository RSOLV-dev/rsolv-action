defmodule RSOLVWeb.TestPatternController do
  @moduledoc """
  Test controller for accessing all pattern tiers during development.
  This should NEVER be deployed to production!
  """
  use RSOLVWeb, :controller
  
  alias RsolvApi.Security
  
  @doc """
  GET /api/v1/test/patterns/:language
  Returns ALL patterns regardless of tier (for testing only)
  """
  def all_tiers(conn, %{"language" => language}) do
    # WARNING: This bypasses all security - development only!
    if Mix.env() == :prod do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Test endpoints disabled in production"})
    else
      # Get all tiers
      all_tiers = ["public", "protected", "ai", "enterprise"]
      
      # Get all patterns for the language
      patterns = Security.list_patterns_by_language(language, all_tiers)
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      # Group by tier for clarity
      patterns_by_tier = Enum.group_by(patterns, fn pattern ->
        # Get the actual tier for each pattern
        tier = pattern.default_tier || :protected
        to_string(tier)
      end)
      
      tier_counts = Enum.map(patterns_by_tier, fn {tier, patterns} ->
        {tier, length(patterns)}
      end) |> Enum.into(%{})
      
      json(conn, %{
        patterns: formatted_patterns,
        total_count: length(formatted_patterns),
        language: language,
        tier_distribution: tier_counts,
        warning: "TEST ENDPOINT - ALL TIERS EXPOSED"
      })
    end
  end
  
  @doc """
  GET /api/v1/test/patterns/:language/:tier
  Returns patterns for a specific tier (for testing only)
  """
  def by_tier(conn, %{"language" => language, "tier" => tier}) do
    if Mix.env() == :prod do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Test endpoints disabled in production"})
    else
      patterns = Security.list_patterns_by_language_and_tier(language, tier)
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        count: length(formatted_patterns),
        language: language,
        tier: tier,
        warning: "TEST ENDPOINT"
      })
    end
  end
end