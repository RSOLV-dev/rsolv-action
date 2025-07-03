defmodule Rsolv.Consolidation.Phase1VerificationTest do
  use ExUnit.Case
  
  @moduledoc """
  Verification tests for Phase 1 completion of RFC-037.
  Ensures module renames and basic functionality work correctly.
  """
  
  describe "module naming verification" do
    test "application name is :rsolv" do
      loaded_apps = Application.loaded_applications() |> Enum.map(&elem(&1, 0))
      assert :rsolv in loaded_apps
    end
    
    test "core modules exist with correct names" do
      # Verify renamed modules are loadable
      assert Code.ensure_loaded?(Rsolv.Repo)
      assert Code.ensure_loaded?(Rsolv.Application)
      assert Code.ensure_loaded?(RsolvWeb.Endpoint)
      assert Code.ensure_loaded?(Rsolv.Accounts)
      assert Code.ensure_loaded?(Rsolv.Security)
    end
    
    test "no RsolvApi modules remain" do
      # Get all loaded modules
      all_modules = :code.all_loaded() |> Enum.map(&elem(&1, 0))
      
      rsolv_api_modules = all_modules
      |> Enum.map(&to_string/1)
      |> Enum.filter(&String.starts_with?(&1, "Elixir.RsolvApi"))
      
      assert rsolv_api_modules == [], 
        "Found remaining RsolvApi modules: #{inspect(rsolv_api_modules)}"
    end
  end
  
  describe "basic functionality" do
    test "configuration is loaded correctly" do
      assert Application.get_env(:rsolv, Rsolv.Repo) != nil
      assert Application.get_env(:rsolv, RsolvWeb.Endpoint) != nil
    end
    
    test "repo configuration has correct otp_app" do
      assert Rsolv.Repo.config()[:otp_app] == :rsolv
    end
  end
end