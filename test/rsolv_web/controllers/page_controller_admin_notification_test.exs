defmodule RsolvWeb.PageControllerAdminNotificationTest do
  use RsolvWeb.ConnCase, async: false
  use Bamboo.Test
  import Mox

  setup :verify_on_exit!

  # Helper function to collect all delivered emails from the mailbox
  defp collect_delivered_emails(emails \\ []) do
    receive do
      {:delivered_email, email} -> collect_delivered_emails([email | emails])
    after
      50 -> Enum.reverse(emails)
    end
  end

  # Helper to find admin notification email from delivered emails
  defp find_admin_notification(delivered_emails) do
    Enum.find(delivered_emails, fn email ->
      String.contains?(email.subject || "", "New RSOLV Signup")
    end)
  end

  # Helper to extract email address from recipient (handles tuple or string format)
  defp extract_email_address(recipient) do
    case recipient do
      {_name, email_address} -> email_address
      email_address when is_binary(email_address) -> email_address
      _ -> ""
    end
  end

  # Helper to verify admin notification was sent
  defp assert_admin_notification_sent(delivered_emails) do
    admin_notification = find_admin_notification(delivered_emails)

    assert admin_notification != nil,
           "Expected to find admin notification email. Found #{length(delivered_emails)} emails."

    admin_notification
  end

  # Helper to set up ConvertKit mock expectations
  defp expect_convertkit_success do
    expect(Rsolv.HTTPClientMock, :post, 2, fn _url, _body, _headers, _opts ->
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body:
           JSON.encode!(%{
             "subscription" => %{
               "id" => 12345,
               "state" => "active"
             }
           })
       }}
    end)
  end

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

  describe "submit_early_access with admin notifications" do
    test "sends admin notification email on successful signup", %{conn: conn} do
      expect_convertkit_success()

      # Submit signup form
      params = %{
        "email" => "newuser@example.com",
        "signup" => %{
          "email" => "newuser@example.com",
          "company" => "Test Corp"
        },
        "utm_source" => "twitter",
        "utm_medium" => "social",
        "utm_campaign" => "launch"
      }

      conn = post(conn, ~p"/early-access", params)
      assert redirected_to(conn) =~ "/thank-you"

      # Verify admin notification was sent
      admin_notification = assert_admin_notification_sent(collect_delivered_emails())

      # Verify content
      assert admin_notification.subject == "🎉 New RSOLV Signup: newuser@example.com"
      assert admin_notification.html_body =~ "newuser@example.com"
      assert admin_notification.html_body =~ "Test Corp"
      assert admin_notification.html_body =~ "twitter"

      # Verify sent to admin emails
      admin_recipients =
        case admin_notification.to do
          list when is_list(list) -> list
          single -> [single]
        end

      assert Enum.any?(admin_recipients, fn recipient ->
               String.ends_with?(extract_email_address(recipient), "@rsolv.dev")
             end)
    end

    test "includes UTM parameters in admin notification", %{conn: conn} do
      expect_convertkit_success()

      # Submit signup with UTM parameters
      conn = put_req_header(conn, "referer", "https://twitter.com/some_post")

      params = %{
        "email" => "utm@example.com",
        "utm_source" => "hackernews",
        "utm_medium" => "forum",
        "utm_campaign" => "beta_launch"
      }

      conn = post(conn, ~p"/early-access", params)
      assert redirected_to(conn) =~ "/thank-you"

      # Verify admin notification was sent
      admin_notification = assert_admin_notification_sent(collect_delivered_emails())

      # Verify UTM parameters and referrer are included
      assert admin_notification.subject =~ "utm@example.com"
      assert admin_notification.html_body =~ "hackernews"
      assert admin_notification.html_body =~ "forum"
      assert admin_notification.html_body =~ "beta_launch"
      assert admin_notification.html_body =~ "twitter.com"
    end

    test "handles minimal signup data gracefully", %{conn: conn} do
      expect_convertkit_success()

      params = %{"email" => "minimal@example.com"}
      conn = post(conn, ~p"/early-access", params)
      assert redirected_to(conn) =~ "/thank-you"

      # Verify admin notification was sent
      admin_notification = assert_admin_notification_sent(collect_delivered_emails())

      # Verify minimal data handling
      assert admin_notification.subject =~ "minimal@example.com"
      assert admin_notification.html_body =~ "minimal@example.com"
      assert admin_notification.html_body =~ "landing_page"
      refute admin_notification.html_body =~ "<div class=\"metric-label\">Company</div>"
    end
  end
end
