defmodule RsolvWeb.PageControllerEmailTest do
  use RsolvWeb.ConnCase, async: false
  
  import Mox
  
  # Set up mocks to verify in tests
  setup :verify_on_exit!
  
  describe "early access form submission" do
    setup do
      # Store original configs
      original_http_client = Application.get_env(:rsolv, :http_client)
      original_convertkit = Application.get_env(:rsolv, :convertkit)
      
      # Set up the correct HTTP client mock
      Application.put_env(:rsolv, :http_client, Rsolv.HTTPClientMock)
      
      # Enable required feature flags
      FunWithFlags.enable(:early_access_signup)
      FunWithFlags.enable(:welcome_email_sequence)
      
      # Set up ConvertKit config for testing with all required fields
      Application.put_env(:rsolv, :convertkit, [
        subscription_plan: "trial",
        form_id: "test_form_id",
        api_base_url: "https://api.convertkit.com/v3",
        early_access_tag_id: "7700607"
      ])
      
      on_exit(fn ->
        # Restore original configs
        Application.put_env(:rsolv, :http_client, original_http_client)
        Application.put_env(:rsolv, :convertkit, original_convertkit)
      end)
      
      :ok
    end
    
    test "successful submission redirects to thank-you page", %{conn: conn} do
      # Mock ConvertKit API responses using the correct mock
      # Allow any number of calls to see if it's being called at all
      Rsolv.HTTPClientMock
      |> stub(:post, fn url, _body, _headers, _options ->
        # Log the URL to debug
        IO.puts("Mock HTTP POST called with URL: #{url}")
        {:ok, %HTTPoison.Response{
          status_code: 201,
          body: ~s({"subscriber": {"id": 12345}})
        }}
      end)
      
      # Submit the form
      conn = post(conn, ~p"/early-access", %{
        "email" => "test@example.com"
      })
      
      # Verify redirection
      assert redirected_to(conn) == "/thank-you"
    end
    
    test "successful submission with user data redirects correctly", %{conn: conn} do
      # Mock ConvertKit API responses using the correct mock
      # Allow any number of calls to see if it's being called at all
      Rsolv.HTTPClientMock
      |> stub(:post, fn url, _body, _headers, _options ->
        # Log the URL to debug
        IO.puts("Mock HTTP POST called with URL: #{url}")
        {:ok, %HTTPoison.Response{
          status_code: 201,
          body: ~s({"subscriber": {"id": 12345}})
        }}
      end)
      
      # Submit with additional information
      conn = post(conn, ~p"/early-access", %{
        "email" => "tester@example.com",
        "signup" => %{"email" => "tester@example.com"}
      })
      
      assert redirected_to(conn) == "/thank-you"
    end
  end
end