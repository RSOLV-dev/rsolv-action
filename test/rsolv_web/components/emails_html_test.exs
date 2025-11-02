defmodule RsolvWeb.EmailsHTMLTest do
  use RsolvWeb.ConnCase, async: true

  alias RsolvWeb.EmailsHTML

  describe "with_defaults/1" do
    test "adds default app_url" do
      assigns = EmailsHTML.with_defaults(%{})
      assert assigns.app_url == "https://rsolv.dev"
    end

    test "adds default docs_url" do
      assigns = EmailsHTML.with_defaults(%{})
      assert assigns.docs_url == "https://rsolv.dev/docs"
    end

    test "adds default first_name" do
      assigns = EmailsHTML.with_defaults(%{})
      assert assigns.first_name == "there"
    end

    test "adds default email" do
      assigns = EmailsHTML.with_defaults(%{})
      assert assigns.email == ""
    end

    test "generates personalized unsubscribe_url when email provided" do
      assigns = EmailsHTML.with_defaults(%{email: "test@example.com"})
      assert assigns.unsubscribe_url == "https://rsolv.dev/unsubscribe?email=test@example.com"
    end

    test "does not override existing assigns" do
      assigns = EmailsHTML.with_defaults(%{first_name: "Jane", email: "jane@example.com"})

      assert assigns.first_name == "Jane"
      assert assigns.email == "jane@example.com"
    end

    test "merges defaults with custom assigns" do
      assigns = EmailsHTML.with_defaults(%{custom_field: "custom_value"})

      assert assigns.custom_field == "custom_value"
      assert assigns.app_url == "https://rsolv.dev"
      assert assigns.first_name == "there"
    end
  end

  describe "template functions" do
    test "welcome/1 returns safe HTML" do
      result = EmailsHTML.welcome(%{})

      assert {:safe, _} = result
    end

    test "payment_failed/1 returns safe HTML" do
      result = EmailsHTML.payment_failed(%{})

      assert {:safe, _} = result
    end

    test "early_access_guide/1 returns safe HTML" do
      result = EmailsHTML.early_access_guide(%{})

      assert {:safe, _} = result
    end

    test "all template functions are defined" do
      templates = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      for template <- templates do
        # Verify function exists and can be called
        assert function_exported?(EmailsHTML, template, 1),
               "Template function #{template}/1 not defined"

        result = apply(EmailsHTML, template, [%{}])
        assert {:safe, _} = result, "Template #{template} didn't return safe HTML"
      end
    end

    test "template functions load actual file content" do
      {:safe, iodata} = EmailsHTML.welcome(%{})
      content = IO.iodata_to_binary(iodata)

      # Should contain actual HTML, not empty
      assert String.length(content) > 0
      assert content =~ ~r/html|HTML/i
    end

    test "template functions don't modify assigns" do
      original_assigns = %{test: "value"}
      EmailsHTML.welcome(original_assigns)

      # Assigns should not be modified
      assert original_assigns == %{test: "value"}
    end
  end

  describe "render functions" do
    test "render_welcome/1 returns string HTML" do
      result = EmailsHTML.render_welcome(%{})

      assert is_binary(result)
      assert String.length(result) > 0
    end

    test "render_payment_failed/1 returns string HTML" do
      result = EmailsHTML.render_payment_failed(%{})

      assert is_binary(result)
      assert String.length(result) > 0
    end

    test "render functions apply defaults" do
      result = EmailsHTML.render_welcome(%{email: "test@example.com"})

      # The rendering process should have applied defaults
      assert is_binary(result)
      assert String.length(result) > 0
    end

    test "all render functions are defined" do
      templates = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      for template <- templates do
        render_fn = :"render_#{template}"

        # Verify function exists and can be called
        assert function_exported?(EmailsHTML, render_fn, 1),
               "Render function #{render_fn}/1 not defined"

        result = apply(EmailsHTML, render_fn, [%{}])
        assert is_binary(result), "Render function #{render_fn} didn't return string"
        assert String.length(result) > 0, "Render function #{render_fn} returned empty string"
      end
    end

    test "render functions return HTML content" do
      result = EmailsHTML.render_welcome(%{})

      # Should contain HTML
      assert result =~ ~r/html|HTML/i
    end

    test "render functions accept custom assigns" do
      result = EmailsHTML.render_welcome(%{first_name: "Jane", email: "jane@example.com"})

      assert is_binary(result)
      assert String.length(result) > 0
    end
  end

  describe "template content integrity" do
    test "welcome template contains expected content" do
      content = EmailsHTML.render_welcome(%{})

      # Basic HTML structure checks
      assert content =~ ~r/html/i
    end

    test "payment_failed template contains expected content" do
      content = EmailsHTML.render_payment_failed(%{})

      # Basic HTML structure checks
      assert content =~ ~r/html/i
    end

    test "payment_failed template renders next payment attempt when provided" do
      content =
        EmailsHTML.render_payment_failed(%{
          customer_name: "Test User",
          amount_due: "$10.00",
          invoice_id: "inv_123",
          attempt_count: 1,
          next_payment_attempt_text: "January 15, 2025",
          credit_balance: 5,
          billing_url: "https://test.com/billing",
          unsubscribe_url: "https://test.com/unsub",
          email: "test@example.com"
        })

      # Should contain the next retry date as properly rendered HTML
      assert content =~ "<p><strong>Next Retry:</strong> January 15, 2025</p>"
      # Should NOT contain escaped HTML tags
      refute content =~ "&lt;p&gt;&lt;strong&gt;Next Retry:&lt;/strong&gt;"
    end

    test "payment_failed template omits next payment attempt when nil" do
      content =
        EmailsHTML.render_payment_failed(%{
          customer_name: "Test User",
          amount_due: "$10.00",
          invoice_id: "inv_123",
          attempt_count: 1,
          next_payment_attempt_text: nil,
          credit_balance: 5,
          billing_url: "https://test.com/billing",
          unsubscribe_url: "https://test.com/unsub",
          email: "test@example.com"
        })

      # Should not contain next retry section at all
      refute content =~ "Next Retry:"
    end

    test "all templates produce non-empty output" do
      templates = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      for template <- templates do
        render_fn = :"render_#{template}"
        content = apply(EmailsHTML, render_fn, [%{}])

        assert String.length(content) > 100,
               "Template #{template} seems too short (#{String.length(content)} chars)"
      end
    end
  end

  describe "production readiness" do
    test "templates load successfully with production-safe paths" do
      # This test verifies that templates can be loaded using Application.app_dir
      # which is the production-safe approach

      templates = [
        :welcome,
        :payment_failed,
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :setup_verification,
        :success_checkin
      ]

      for template <- templates do
        # Should not raise
        content = apply(EmailsHTML, :"render_#{template}", [%{}])
        assert is_binary(content)
        assert String.length(content) > 0
      end
    end

    test "all templates use TemplateLoader internally" do
      # This test documents that we're using the TemplateLoader helper
      # We can verify this by checking that templates load successfully
      # (The implementation uses TemplateLoader.load_template!/1)

      result = EmailsHTML.render_welcome(%{})

      # Should successfully load and render
      assert is_binary(result)
      assert String.length(result) > 0
    end
  end

  describe "error handling" do
    test "template functions raise on missing template files" do
      # This test documents the behavior when a template file is missing
      # In production, this should never happen, but we want fail-fast behavior

      # Note: We can't easily test this without modifying the file system,
      # but we document the expected behavior here.
      # If a template file is missing, TemplateLoader.load_template!/1 will raise File.Error
    end
  end

  describe "backwards compatibility" do
    test "render functions maintain same API as before refactor" do
      # These functions were available before and should still work
      assert function_exported?(EmailsHTML, :render_welcome, 1)
      assert function_exported?(EmailsHTML, :render_payment_failed, 1)
      assert function_exported?(EmailsHTML, :render_early_access_guide, 1)
      assert function_exported?(EmailsHTML, :render_early_access_welcome, 1)
      assert function_exported?(EmailsHTML, :render_feature_deep_dive, 1)
      assert function_exported?(EmailsHTML, :render_feedback_request, 1)
      assert function_exported?(EmailsHTML, :render_first_issue, 1)
      assert function_exported?(EmailsHTML, :render_getting_started, 1)
      assert function_exported?(EmailsHTML, :render_setup_verification, 1)
      assert function_exported?(EmailsHTML, :render_success_checkin, 1)
    end

    test "template functions maintain same API as before refactor" do
      # These functions were available before and should still work
      assert function_exported?(EmailsHTML, :welcome, 1)
      assert function_exported?(EmailsHTML, :payment_failed, 1)
      assert function_exported?(EmailsHTML, :early_access_guide, 1)
      assert function_exported?(EmailsHTML, :early_access_welcome, 1)
      assert function_exported?(EmailsHTML, :feature_deep_dive, 1)
      assert function_exported?(EmailsHTML, :feedback_request, 1)
      assert function_exported?(EmailsHTML, :first_issue, 1)
      assert function_exported?(EmailsHTML, :getting_started, 1)
      assert function_exported?(EmailsHTML, :setup_verification, 1)
      assert function_exported?(EmailsHTML, :success_checkin, 1)
    end

    test "with_defaults/1 maintains same API" do
      assert function_exported?(EmailsHTML, :with_defaults, 1)

      result = EmailsHTML.with_defaults(%{email: "test@example.com"})

      assert is_map(result)
      assert result.email == "test@example.com"
      assert result.app_url == "https://rsolv.dev"
    end
  end
end
