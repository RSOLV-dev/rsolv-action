defmodule RsolvWeb.EarlyAccessLiveTest do
  use RsolvWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  import Mox
  use Bamboo.Test, shared: true

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

    # Configure ConvertKit settings for test with all required fields
    Application.put_env(:rsolv, :convertkit,
      api_key: "test_api_key",
      form_id: "test_form_id",
      api_base_url: "https://api.convertkit.com/v3",
      early_access_tag_id: "7700607"
    )

    on_exit(fn ->
      # Restore original configs
      Application.put_env(:rsolv, :convertkit, original_convertkit)
      Application.put_env(:rsolv, :http_client, original_http_client)
    end)

    :ok
  end

  describe "admin notification emails" do
    test "admin notification email is sent when user submits early access form via LiveView", %{
      conn: conn
    } do
      # Mock ConvertKit API calls
      expect(Rsolv.HTTPClientMock, :post, 2, fn _url, _body, _headers, _opts ->
        {:ok,
         %HTTPoison.Response{
           status_code: 200,
           body:
             Jason.encode!(%{
               "subscription" => %{
                 "id" => 12345,
                 "state" => "active"
               }
             })
         }}
      end)

      # Setup test data
      email = "test@example.com"

      # Mount the LiveView
      {:ok, view, _html} = live(conn, "/")

      # Fill out and submit the form with correct field names
      view
      |> form("#early-access-form form", %{"signup" => %{"email" => email}})
      |> render_submit()

      # Wait a moment for async email processing
      Process.sleep(100)

      # Use assert_received to check for the admin email
      assert_received(
        {:delivered_email,
         %Bamboo.Email{
           from: {"RSOLV Team", "support@rsolv.dev"},
           to: [nil: "admin@rsolv.dev"],
           subject: "🎉 New RSOLV Signup: test@example.com"
         }}
      )
    end
  end
end
