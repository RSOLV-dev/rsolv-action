defmodule RsolvWeb.PageControllerTest do
  use RsolvWeb.ConnCase
  
  describe "thank_you/2" do
    test "renders thank you page", %{conn: conn} do
      conn = get(conn, ~p"/thank-you")
      
      assert html_response(conn, 200) =~ "Thank You"
    end
    
    test "includes success email from session", %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{success_email: "test@example.com"})
        |> get(~p"/thank-you")
      
      assert html_response(conn, 200) =~ "Thank You"
      assert conn.assigns[:success_email] == "test@example.com"
    end
    
    test "includes success email from test session setup", %{conn: conn} do
      # Test that email from test session is properly assigned
      conn =
        conn
        |> Phoenix.ConnTest.init_test_session(%{success_email: "session@example.com"})
        |> get(~p"/thank-you")
      
      assert html_response(conn, 200) =~ "Thank You"
      assert conn.assigns[:success_email] == "session@example.com"
    end
  end
  
  describe "privacy/2" do
    test "renders privacy policy page", %{conn: conn} do
      conn = get(conn, ~p"/docs/privacy")
      
      assert html_response(conn, 200) =~ "Privacy Policy"
    end
  end
  
  describe "terms/2" do
    test "renders terms of service page", %{conn: conn} do
      conn = get(conn, ~p"/docs/terms")
      
      assert html_response(conn, 200) =~ "Terms of Service"
    end
  end
  
  describe "unsubscribe/2" do
    test "renders unsubscribe page without email", %{conn: conn} do
      conn = get(conn, ~p"/unsubscribe")
      
      assert html_response(conn, 200) =~ "Unsubscribe"
    end
    
    test "renders unsubscribe page with email param", %{conn: conn} do
      conn = get(conn, ~p"/unsubscribe?email=test@example.com")
      
      assert html_response(conn, 200) =~ "Unsubscribe"
      assert html_response(conn, 200) =~ "test@example.com"
    end
  end
  
  describe "process_unsubscribe/2" do
    test "processes valid unsubscribe request", %{conn: conn} do
      conn = post(conn, ~p"/unsubscribe", %{email: "valid@example.com"})
      
      assert html_response(conn, 200) =~ "successfully unsubscribed"
    end
    
    test "shows error for invalid email", %{conn: conn} do
      conn = post(conn, ~p"/unsubscribe", %{email: "invalid-email"})
      
      assert html_response(conn, 200) =~ "error"
    end
    
    test "shows error when no email provided", %{conn: conn} do
      conn = post(conn, ~p"/unsubscribe", %{})
      
      assert html_response(conn, 200) =~ "error"
    end
  end
end