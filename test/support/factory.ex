defmodule RSOLV.Factory do
  @moduledoc """
  Factory for creating test data structures.
  
  This factory creates mock data structures that match the current
  implementation's format (which uses environment-based API keys
  rather than database schemas).
  """
  
  use ExMachina
  
  def customer_factory do
    %{
      id: sequence(:id, &"test_customer_#{&1}"),
      name: "Test Customer",
      email: sequence(:email, &"customer#{&1}@example.com"),
      api_key: sequence(:api_key, &"rsolv_test_#{&1}"),
      monthly_limit: 100,
      current_usage: 0,
      active: true,
      trial: true,
      subscription_tier: "standard",
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end
  
  def credential_factory do
    %{
      id: sequence(:credential_id, &"cred_#{&1}"),
      customer_id: "test_customer_1",
      provider: "anthropic",
      api_key: "temp_ant_test_key",
      encrypted_key: "temp_ant_test_key",
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
      usage_limit: 100,
      usage_count: 0,
      metadata: %{},
      revoked: false,
      github_job_id: nil,
      github_run_id: nil,
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end
  
  def usage_record_factory do
    %{
      id: sequence(:usage_id, &"usage_#{&1}"),
      customer_id: "test_customer_1", 
      provider: "anthropic",
      tokens_used: 1000,
      request_count: 1,
      job_id: sequence(:job_id, &"job_#{&1}"),
      created_at: DateTime.utc_now()
    }
  end
end