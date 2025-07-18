defmodule RsolvWeb.EarlyAccessLiveTest do
  use RsolvWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  use Bamboo.Test, shared: true

  describe "admin notification emails" do
    test "admin notification email is sent when user submits early access form via LiveView", %{conn: conn} do
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