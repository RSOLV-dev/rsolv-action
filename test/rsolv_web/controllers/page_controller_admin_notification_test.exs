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
      # Mock ConvertKit API calls (subscribe + tag)
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

      # Should redirect to thank you page
      assert redirected_to(conn) =~ "/thank-you"

      # Collect all delivered emails from the mailbox
      # Since we're using Bamboo.TestAdapter with Oban testing: :inline,
      # all emails should be delivered synchronously before the request completes
      delivered_emails = collect_delivered_emails()

      # Find the admin notification email (not the welcome email to the user)
      admin_notification =
        Enum.find(delivered_emails, fn email ->
          String.contains?(email.subject || "", "New RSOLV Signup")
        end)

      assert admin_notification != nil,
             "Expected to find admin notification email. Found #{length(delivered_emails)} emails."

      # Verify it's the admin notification with correct content
      assert admin_notification.subject == "🎉 New RSOLV Signup: newuser@example.com"
      assert admin_notification.html_body =~ "newuser@example.com"
      assert admin_notification.html_body =~ "Test Corp"
      assert admin_notification.html_body =~ "twitter"

      # Check it's sent to admin emails
      admin_recipients =
        case admin_notification.to do
          list when is_list(list) -> list
          single -> [single]
        end

      assert Enum.any?(admin_recipients, fn recipient ->
               recipient_email =
                 case recipient do
                   {_name, email_address} -> email_address
                   email_address when is_binary(email_address) -> email_address
                   _ -> ""
                 end

               String.ends_with?(recipient_email, "@rsolv.dev")
             end)
    end

    test "includes UTM parameters in admin notification", %{conn: conn} do
      # Mock ConvertKit API calls (subscribe + tag)
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

      # Submit signup with UTM parameters in query string
      conn =
        conn
        |> put_req_header("referer", "https://twitter.com/some_post")

      params = %{
        "email" => "utm@example.com",
        "utm_source" => "hackernews",
        "utm_medium" => "forum",
        "utm_campaign" => "beta_launch"
      }

      # Send all params in the body (UTM params will be extracted from body_params)
      conn = post(conn, ~p"/early-access", params)

      assert redirected_to(conn) =~ "/thank-you"

      # Collect all delivered emails from the mailbox
      delivered_emails = collect_delivered_emails()

      # Find admin notification
      admin_notification =
        Enum.find(delivered_emails, fn email ->
          String.contains?(email.subject || "", "New RSOLV Signup")
        end)

      assert admin_notification != nil,
             "Expected admin notification to be sent. Found #{length(delivered_emails)} emails."

      assert admin_notification.subject =~ "utm@example.com"
      assert admin_notification.html_body =~ "hackernews"
      assert admin_notification.html_body =~ "forum"
      assert admin_notification.html_body =~ "beta_launch"
      # referrer
      assert admin_notification.html_body =~ "twitter.com"
    end

    test "handles minimal signup data gracefully", %{conn: conn} do
      # Mock ConvertKit API calls (subscribe + tag)
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

      params = %{"email" => "minimal@example.com"}

      conn = post(conn, ~p"/early-access", params)

      assert redirected_to(conn) =~ "/thank-you"

      # Collect all delivered emails from the mailbox
      delivered_emails = collect_delivered_emails()

      # Find admin notification
      admin_notification =
        Enum.find(delivered_emails, fn email ->
          String.contains?(email.subject || "", "New RSOLV Signup")
        end)

      assert admin_notification != nil,
             "Expected admin notification to be sent. Found #{length(delivered_emails)} emails."

      assert admin_notification.subject =~ "minimal@example.com"
      assert admin_notification.html_body =~ "minimal@example.com"
      # default source
      assert admin_notification.html_body =~ "landing_page"

      # Should not have company section
      refute admin_notification.html_body =~ "<div class=\"metric-label\">Company</div>"
    end
  end
end
