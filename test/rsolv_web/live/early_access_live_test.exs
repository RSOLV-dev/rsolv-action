defmodule RsolvWeb.EarlyAccessLiveTest do
  use RsolvWeb.ConnCase
  
  import Phoenix.LiveViewTest
  
  describe "EarlyAccessLive mount" do
    test "renders the early access signup page", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/signup")
      
      # Check basic structure
      assert html =~ "Get Early Access"
      assert html =~ "Enter your email"
      assert html =~ "Company (optional)"
      assert html =~ "Join Early Access"
    end
    
    test "initializes with empty form fields", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      assert view.assigns.email == ""
      assert view.assigns.company == ""
      assert view.assigns.errors == %{}
      assert view.assigns.submitting == false
    end
  end
  
  describe "form validation" do
    test "validates email on form change", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit empty email
      view
      |> form("form", signup: %{email: "", company: "Test Co"})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      assert view.assigns.email == ""
      assert view.assigns.company == "Test Co"
    end
    
    test "validates email format on form change", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit invalid email format
      view
      |> form("form", signup: %{email: "invalid-email", company: ""})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      assert view.assigns.email == "invalid-email"
    end
    
    test "clears errors with valid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # First trigger an error
      view
      |> form("form", signup: %{email: "", company: ""})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Then provide valid email
      view
      |> form("form", signup: %{email: "test@example.com", company: "Test Co"})
      |> render_change()
      
      assert view.assigns.errors == %{}
      assert view.assigns.email == "test@example.com"
      assert view.assigns.company == "Test Co"
    end
    
    test "accepts various valid email formats", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      valid_emails = [
        "user@example.com",
        "test.email@subdomain.example.org",
        "user+tag@example.co.uk",
        "user123@example-domain.com"
      ]
      
      for email <- valid_emails do
        view
        |> form("form", signup: %{email: email, company: ""})
        |> render_change()
        
        assert view.assigns.errors == %{}, "Email #{email} should be valid"
        assert view.assigns.email == email
      end
    end
    
    test "rejects invalid email formats", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      invalid_emails = [
        "",
        "invalid",
        "@example.com",
        "user@",
        "user..double.dot@example.com",
        "user@.example.com"
      ]
      
      for email <- invalid_emails do
        view
        |> form("form", signup: %{email: email, company: ""})
        |> render_change()
        
        assert view.assigns.errors[:email] == "Please enter a valid email address", 
               "Email '#{email}' should be invalid"
      end
    end
  end
  
  describe "form submission" do
    test "submits successfully with valid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "test@example.com", company: "Test Company"})
      |> render_submit()
      
      # Check success flash message
      assert Phoenix.Flash.get(view.assigns.flash, :success) =~ "Thank you for signing up"
      
      # Check form is cleared
      assert view.assigns.email == ""
      assert view.assigns.company == ""
    end
    
    test "submits successfully with just email (company optional)", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit with just email
      view
      |> form("form", signup: %{email: "test@example.com", company: ""})
      |> render_submit()
      
      # Check success flash message
      assert Phoenix.Flash.get(view.assigns.flash, :success) =~ "Thank you for signing up"
      
      # Check form is cleared
      assert view.assigns.email == ""
      assert view.assigns.company == ""
    end
    
    test "shows errors on invalid submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit invalid form
      view
      |> form("form", signup: %{email: "invalid", company: "Test Company"})
      |> render_submit()
      
      # Check errors are shown
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Check no success flash
      refute Phoenix.Flash.get(view.assigns.flash, :success)
      
      # Check form data is preserved
      assert view.assigns.email == "invalid"
      assert view.assigns.company == "Test Company"
    end
    
    test "handles empty email submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit with empty email
      view
      |> form("form", signup: %{email: "", company: "Test Company"})
      |> render_submit()
      
      # Check validation error
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Check no success flash
      refute Phoenix.Flash.get(view.assigns.flash, :success)
    end
    
    test "preserves company field when email is invalid", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      company_name = "Important Test Company"
      
      # Submit with invalid email but valid company
      view
      |> form("form", signup: %{email: "invalid", company: company_name})
      |> render_submit()
      
      # Check error is shown but company is preserved
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      assert view.assigns.company == company_name
    end
  end
  
  describe "integration with services" do
    test "should integrate with Analytics service for tracking", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "analytics-test@example.com", company: "Analytics Co"})
      |> render_submit()
      
      # For now, just verify the submission succeeds
      # TODO: Add Analytics.track_conversion("early_access_signup") integration
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
    
    test "should integrate with Kit service for email subscription", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "kit-test@example.com", company: "Kit Test Co"})
      |> render_submit()
      
      # For now, just verify the submission succeeds
      # TODO: Add Kit.subscribe_to_early_access integration
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
    
    test "should integrate with EmailSequence service for onboarding", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "sequence-test@example.com", company: "Sequence Co"})
      |> render_submit()
      
      # For now, just verify the submission succeeds
      # TODO: Add EmailSequence.start_early_access_onboarding integration
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
  end
  
  describe "accessibility and UX" do
    test "form has proper labels and structure", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/signup")
      
      # Check form has proper structure
      assert html =~ "phx-submit=\"submit\""
      assert html =~ "name=\"signup[email]\""
      assert html =~ "name=\"signup[company]\""
      assert html =~ "type=\"submit\""
    end
    
    test "error messages are displayed inline", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Trigger validation error
      html = view
             |> form("form", signup: %{email: "", company: ""})
             |> render_change()
      
      # Check error message appears in rendered HTML
      assert html =~ "Please enter a valid email address"
    end
    
    test "success message is displayed after submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      html = view
             |> form("form", signup: %{email: "success@example.com", company: ""})
             |> render_submit()
      
      # Check success message appears
      assert html =~ "Thank you for signing up"
    end
    
    test "form fields are cleared after successful submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "clear-test@example.com", company: "Clear Test Co"})
      |> render_submit()
      
      # Check fields are cleared
      assert view.assigns.email == ""
      assert view.assigns.company == ""
      assert view.assigns.errors == %{}
    end
  end
  
  describe "edge cases and security" do
    test "handles very long email addresses", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      long_email = String.duplicate("a", 200) <> "@example.com"
      
      view
      |> form("form", signup: %{email: long_email, company: ""})
      |> render_change()
      
      # Should handle gracefully (either accept or reject, but not crash)
      assert is_map(view.assigns.errors)
    end
    
    test "handles special characters in company name", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      special_company = "Test & Co. <script>alert('xss')</script>"
      
      view
      |> form("form", signup: %{email: "test@example.com", company: special_company})
      |> render_submit()
      
      # Should handle gracefully and show success
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
    
    test "handles concurrent form submissions gracefully", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/signup")
      
      # This tests that the form doesn't break with rapid submissions
      # In a real scenario, we might want to prevent double-submission
      
      view
      |> form("form", signup: %{email: "concurrent@example.com", company: ""})
      |> render_submit()
      
      view
      |> form("form", signup: %{email: "concurrent2@example.com", company: ""})
      |> render_submit()
      
      # Both should succeed (form is cleared after first submission)
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
  end
end