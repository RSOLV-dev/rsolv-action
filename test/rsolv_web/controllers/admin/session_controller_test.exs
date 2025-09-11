defmodule RsolvWeb.Admin.SessionControllerTest do
  use RsolvWeb.ConnCase, async: true

  describe "new" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, ~p"/admin/login")
      
      assert html_response(conn, 200) =~ "Admin Login"
    end
    
    test "shows email field", %{conn: conn} do
      conn = get(conn, ~p"/admin/login")
      
      assert html_response(conn, 200) =~ "name=\"session[email]\""
    end
    
    test "shows password field", %{conn: conn} do
      conn = get(conn, ~p"/admin/login")
      
      assert html_response(conn, 200) =~ "name=\"session[password]\""
    end
    
    test "has submit button", %{conn: conn} do
      conn = get(conn, ~p"/admin/login")
      
      assert html_response(conn, 200) =~ "type=\"submit\""
    end
  end
end