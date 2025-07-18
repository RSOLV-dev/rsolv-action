defmodule RsolvWeb.PageControllerAnalyticsTest do
  use RsolvWeb.ConnCase
  import Mox
  
  setup :verify_on_exit!
  
  setup do
    # Store original configs
    original_convertkit = Application.get_env(:rsolv, :convertkit)
    original_http_client = Application.get_env(:rsolv, :http_client)
    
    # Set up the correct HTTP client mock
    Application.put_env(:rsolv, :http_client, Rsolv.HTTPClientMock)
    
    # Enable required feature flags
    FunWithFlags.enable(:early_access_signup)
    FunWithFlags.enable(:welcome_email_sequence)
    
    # Set up ConvertKit config for testing with all required fields
    Application.put_env(:rsolv, :convertkit, [
      api_key: "test_api_key",
      form_id: "test_form_id",
      api_base_url: "https://api.convertkit.com/v3",
      early_access_tag_id: "7700607"
    ])
    
    on_exit(fn ->
      # Restore original configs
      Application.put_env(:rsolv, :convertkit, original_convertkit)
      Application.put_env(:rsolv, :http_client, original_http_client)
    end)
    
    :ok
  end
  
  describe "submit_early_access analytics tracking" do
    test "passes celebration data for Plausible and Simple Analytics", %{conn: conn} do
      # Mock ConvertKit API calls - POST to add subscriber, then POST to tag
      expect(Rsolv.HTTPClientMock, :post, 2, fn _url, _body, _headers, _opts ->
        {:ok, %HTTPoison.Response{
          status_code: 200,
          body: Jason.encode!(%{
            "subscription" => %{
              "id" => 12345,
              "state" => "active"
            }
          })
        }}
      end)
      
      # Submit signup with UTM parameters
      params = %{
        "email" => "analytics@example.com",
        "utm_source" => "twitter",
        "utm_medium" => "social",
        "utm_campaign" => "launch"
      }
      
      conn = post(conn, ~p"/early-access", params)
      
      # Should redirect to thank you page
      assert redirected_to(conn) =~ "/thank-you"
      
      # Get the celebration data from flash
      celebration_data_json = Phoenix.Flash.get(conn.assigns.flash, :celebration_data)
      assert celebration_data_json != nil
      
      # Parse and verify the celebration data
      celebration_data = Jason.decode!(celebration_data_json)
      assert celebration_data["email_domain"] == "example.com"
      assert celebration_data["source"] == "twitter"
      assert celebration_data["medium"] == "social"
      assert celebration_data["campaign"] == "launch"
    end
    
    test "provides default values when no UTM parameters present", %{conn: conn} do
      # Mock ConvertKit API calls - POST to add subscriber, then POST to tag
      expect(Rsolv.HTTPClientMock, :post, 2, fn _url, _body, _headers, _opts ->
        {:ok, %HTTPoison.Response{
          status_code: 200,
          body: Jason.encode!(%{
            "subscription" => %{
              "id" => 12345,
              "state" => "active"
            }
          })
        }}
      end)
      
      # Submit signup without UTM parameters
      params = %{"email" => "noparams@example.com"}
      
      conn = post(conn, ~p"/early-access", params)
      
      # Get the celebration data from flash
      celebration_data_json = Phoenix.Flash.get(conn.assigns.flash, :celebration_data)
      celebration_data = Jason.decode!(celebration_data_json)
      
      # Should have default values
      assert celebration_data["email_domain"] == "example.com"
      assert celebration_data["source"] == "direct"
      assert celebration_data["medium"] == "organic"
      assert celebration_data["campaign"] == "none"
    end
  end
end