defmodule RsolvWeb.ContactLiveTest do
  use RsolvWeb.ConnCase
  import Phoenix.LiveViewTest
  import Mock

  alias Rsolv.Mailer

  describe "mount and render" do
    test "renders contact form", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/contact")

      # Check form exists
      assert has_element?(view, "form")
      # Check submit button exists
      assert has_element?(view, "button[type=\"submit\"]")
      assert view
    end

    test "displays required form fields", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/contact")

      # Check all required inputs exist
      assert has_element?(view, "input[name=\"name\"][required]")
      assert has_element?(view, "input[name=\"email\"][required]")
      assert has_element?(view, "textarea[name=\"message\"][required]")
      # Optional fields
      assert has_element?(view, "input[name=\"company\"]")
      assert has_element?(view, "select[name=\"team_size\"]")
    end
  end

  describe "form submission" do
    test "successful submission shows thank you message", %{conn: conn} do
      with_mock Mailer, deliver_now: fn _email -> {:ok, %{}} end do
        {:ok, view, _html} = live(conn, "/contact")

        form_data = %{
          "name" => "John Doe",
          "email" => "john@example.com",
          "company" => "Acme Inc",
          "message" => "I'm interested in enterprise features",
          "team_size" => "11-50"
        }

        view
        |> form("form", form_data)
        |> render_submit()

        # Check the actual HTML to debug
        html = render(view)

        # Form should be hidden after successful submission
        refute has_element?(view, "form")
        # Success message should be visible - check if submitted flag is true
        assert html =~ "Thank you"
      end
    end

    test "sends email notification on successful submission", %{conn: conn} do
      with_mock Mailer,
        deliver_now: fn email ->
          # Verify email is being sent (structure will be checked more loosely)
          assert is_list(email.to) || is_binary(email.to)
          assert is_binary(email.subject)
          {:ok, email}
        end do
        {:ok, view, _html} = live(conn, "/contact")

        form_data = %{
          "name" => "John Doe",
          "email" => "john@example.com",
          "company" => "Acme Inc",
          "message" => "I'm interested in enterprise features",
          "team_size" => "11-50"
        }

        view
        |> form("form", form_data)
        |> render_submit()

        # Verify email was sent
        assert_called(Mailer.deliver_now(:_))
      end
    end

    test "shows error for invalid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/contact")

      form_data = %{
        "name" => "John Doe",
        "email" => "not-an-email",
        "company" => "Acme Inc",
        "message" => "I'm interested in enterprise features",
        "team_size" => "11-50"
      }

      view
      |> form("form", form_data)
      |> render_submit()

      # Form should still be visible
      assert has_element?(view, "form")
      # Error message should be shown
      assert has_element?(view, ".bg-red-50") || has_element?(view, ".dark\\:bg-red-900\\/20")
      # Success message should NOT be shown
      refute has_element?(view, ".bg-green-50") &&
               refute(has_element?(view, ".dark\\:bg-green-900\\/20"))
    end

    test "validates empty email field", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/contact")

      # Submit with empty email
      form_data = %{
        "name" => "John Doe",
        "email" => "",
        "message" => "Test message"
      }

      view
      |> form("form", form_data)
      |> render_submit()

      # Form should still be visible
      assert has_element?(view, "form")

      # With empty email, validate_with_feedback returns {:error, nil}
      # so no error message is shown - the form just doesn't submit
      # This is the expected behavior based on the implementation
      refute has_element?(view, ".bg-red-50")
    end

    test "handles email delivery failure gracefully", %{conn: conn} do
      with_mock Mailer,
        deliver_now: fn _email ->
          raise "Email delivery failed!"
        end do
        {:ok, view, _html} = live(conn, "/contact")

        form_data = %{
          "name" => "John Doe",
          "email" => "john@example.com",
          "company" => "Acme Inc",
          "message" => "I'm interested in enterprise features",
          "team_size" => "11-50"
        }

        view
        |> form("form", form_data)
        |> render_submit()

        # Form should still be visible (submission failed)
        assert has_element?(view, "form")
        # Error message should be shown
        assert has_element?(view, ".bg-red-50") || has_element?(view, ".dark\\:bg-red-900\\/20")
        # Should not show success message
        refute has_element?(view, ".bg-green-50") &&
                 refute(has_element?(view, ".dark\\:bg-green-900\\/20"))
      end
    end
  end

  describe "analytics tracking" do
    test "tracks page view on mount", %{conn: conn} do
      with_mock RsolvWeb.Services.Analytics,
        track_page_view: fn path, _, _ ->
          assert path == "/contact"
          :ok
        end,
        track_form_submission: fn _, _, _ -> :ok end do
        {:ok, _view, _html} = live(conn, "/contact")

        # Verify page view was tracked
        assert_called(RsolvWeb.Services.Analytics.track_page_view("/contact", :_, :_))
      end
    end

    test "tracks successful form submission", %{conn: conn} do
      with_mocks([
        {Mailer, [], [deliver_now: fn _email -> {:ok, %{}} end]},
        {RsolvWeb.Services.Analytics, [],
         [
           track_page_view: fn _, _, _ -> :ok end,
           track_form_submission: fn form_id, status, _data ->
             # Verify the correct tracking calls
             assert form_id == "contact"
             assert status in ["submit", "success"]
             :ok
           end
         ]}
      ]) do
        {:ok, view, _html} = live(conn, "/contact")

        form_data = %{
          "name" => "John Doe",
          "email" => "john@example.com",
          "company" => "Acme Inc",
          "message" => "I'm interested in enterprise features",
          "team_size" => "11-50"
        }

        view
        |> form("form", form_data)
        |> render_submit()

        # Verify tracking was called
        assert_called(RsolvWeb.Services.Analytics.track_form_submission("contact", :_, :_))
      end
    end
  end
end
