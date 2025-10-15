defmodule RsolvWeb.Admin.AuthControllerTest do
  use RsolvWeb.ConnCase, async: false

  alias Rsolv.Customers

  setup do
    # Create a staff customer for testing
    {:ok, staff} =
      Customers.register_customer(%{
        name: "Staff Test",
        email: "staff_test@rsolv.dev",
        password: "TestP@ssw0rd2025!",
        is_staff: true,
        admin_level: "full"
      })

    # Create a non-staff customer for testing
    {:ok, regular} =
      Customers.register_customer(%{
        name: "Regular Test",
        email: "regular_test@example.com",
        password: "TestP@ssw0rd2025!",
        is_staff: false
      })

    %{staff: staff, regular: regular}
  end

  describe "authenticate/2" do
    test "successfully authenticates staff user with valid token", %{conn: conn, staff: staff} do
      # Generate a session token for the staff user
      token = Customers.generate_customer_session_token(staff)

      # Make the GET request to /admin/auth with the token
      conn = get(conn, ~p"/admin/auth", %{"token" => token})

      # Should redirect to admin dashboard
      assert redirected_to(conn) == ~p"/admin/dashboard"
      assert get_flash(conn, :info) == "Welcome back!"
    end

    test "rejects authentication with invalid token", %{conn: conn} do
      # Use an invalid token
      conn = get(conn, ~p"/admin/auth", %{"token" => "invalid_token_123"})

      # Should redirect back to login with error
      assert redirected_to(conn) == ~p"/admin/login"
      assert get_flash(conn, :error) == "Invalid or expired authentication token"
    end

    test "rejects authentication for non-staff user", %{conn: conn, regular: regular} do
      # Generate a session token for the non-staff user
      token = Customers.generate_customer_session_token(regular)

      # Make the GET request to /admin/auth with the token
      conn = get(conn, ~p"/admin/auth", %{"token" => token})

      # Should redirect back to login with error
      assert redirected_to(conn) == ~p"/admin/login"
      assert get_flash(conn, :error) == "You are not authorized to access the admin area."
    end

    test "GET request to /admin/auth should not be blocked by CSRF protection", %{conn: conn} do
      # This test specifically checks that CSRF protection doesn't interfere
      # with GET requests to the auth endpoint

      # Create a connection without session/CSRF token
      conn =
        conn
        |> Phoenix.ConnTest.init_test_session(%{})

      # Should be able to make the request without CSRF issues
      # (will fail due to missing token param, but not due to CSRF)
      conn = get(conn, ~p"/admin/auth", %{"token" => "test"})

      # Should get the expected "invalid token" error, not a CSRF error
      assert redirected_to(conn) == ~p"/admin/login"
      assert get_flash(conn, :error) == "Invalid or expired authentication token"
    end
  end
end
