defmodule RsolvWeb.EarlyAccessLiveTest do
  use RsolvWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  import Mox
  use Bamboo.Test, shared: true

  setup :verify_on_exit!
  
  setup do
    # Configure ConvertKit settings for test
    Application.put_env(:rsolv, :convertkit,
      api_key: "test_api_key",
      form_id: "test_form_id",
      api_base_url: "https://api.convertkit.com/v3"
    )
    :ok
  end

  describe "admin notification emails" do
    test "admin notification email is sent when user submits early access form via LiveView", %{conn: conn} do
      # Mock ConvertKit API calls
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
      assert_received({:delivered_email, %Bamboo.Email{
        from: {"RSOLV Team", "support@rsolv.dev"},
        to: [nil: "admin@rsolv.dev"],
        subject: "🎉 New RSOLV Signup: test@example.com"
      }})
    end
  end
end