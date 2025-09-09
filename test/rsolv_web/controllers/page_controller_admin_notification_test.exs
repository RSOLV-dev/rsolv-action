defmodule RsolvWeb.PageControllerAdminNotificationTest do
  use RsolvWeb.ConnCase
  use Bamboo.Test
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
      subscription_plan: "trial",
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
  
  describe "submit_early_access with admin notifications" do
    test "sends admin notification email on successful signup", %{conn: conn} do
      # Mock ConvertKit API calls (subscribe + tag)
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
      
      # Check that admin notification was sent
      delivered_emails = Bamboo.SentEmail.all()
      
      # Find admin notification email
      admin_notification = Enum.find(delivered_emails, fn email ->
        String.contains?(email.subject || "", "New RSOLV Signup")
      end)
      
      # This assertion will fail initially
      assert admin_notification != nil, "Expected admin notification to be sent"
      
      # When we implement it, these assertions should pass
      if admin_notification do
        assert admin_notification.subject =~ "🎉 New RSOLV Signup: newuser@example.com"
        assert admin_notification.html_body =~ "newuser@example.com"
        assert admin_notification.html_body =~ "Test Corp"
        assert admin_notification.html_body =~ "twitter"
        
        # Check it's sent to admin emails
        assert Enum.any?(admin_notification.to, fn recipient ->
          case recipient do
            {_name, email_address} -> String.ends_with?(email_address, "@rsolv.dev")
            email_address when is_binary(email_address) -> String.ends_with?(email_address, "@rsolv.dev")
            _ -> false
          end
        end)
      end
    end
    
    test "includes UTM parameters in admin notification", %{conn: conn} do
      # Mock ConvertKit API calls (subscribe + tag)
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
      
      # Submit signup with UTM parameters in query string
      conn = conn
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
      
      # Check admin notification includes UTM data
      delivered_emails = Bamboo.SentEmail.all()
      admin_notification = Enum.find(delivered_emails, fn email ->
        String.contains?(email.subject || "", "New RSOLV Signup")
      end)
      
      assert admin_notification != nil, "Expected admin notification to be sent"
      assert admin_notification.subject =~ "utm@example.com"
      assert admin_notification.html_body =~ "hackernews"
      assert admin_notification.html_body =~ "forum" 
      assert admin_notification.html_body =~ "beta_launch"
      assert admin_notification.html_body =~ "twitter.com" # referrer
    end
    
    test "handles minimal signup data gracefully", %{conn: conn} do
      # Mock ConvertKit API calls (subscribe + tag)
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
      
      params = %{"email" => "minimal@example.com"}
      
      conn = post(conn, ~p"/early-access", params)
      
      assert redirected_to(conn) =~ "/thank-you"
      
      # Admin notification should still be sent with minimal data
      delivered_emails = Bamboo.SentEmail.all()
      admin_notification = Enum.find(delivered_emails, fn email ->
        String.contains?(email.subject || "", "New RSOLV Signup")
      end)
      
      assert admin_notification != nil, "Expected admin notification to be sent"
      assert admin_notification.subject =~ "minimal@example.com"
      assert admin_notification.html_body =~ "minimal@example.com"
      assert admin_notification.html_body =~ "landing_page" # default source
      
      # Should not have company section
      refute admin_notification.html_body =~ "<div class=\"metric-label\">Company</div>"
    end
  end
end