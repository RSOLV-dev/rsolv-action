defmodule RsolvWeb.Admin.SessionControllerTest do
  use RsolvWeb.ConnCase, async: true
  
  import Rsolv.CustomersFixtures

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
  
  describe "create" do
    test "logs in staff user with valid credentials", %{conn: conn} do
      staff_member = staff_customer_fixture()
      
      conn = post(conn, ~p"/admin/login", %{
        "session" => %{
          "email" => staff_member.email,
          "password" => "StaffPassword123!"
        }
      })
      
      assert redirected_to(conn) == ~p"/admin/dashboard"
      assert get_session(conn, :customer_token)
    end
    
    test "rejects non-staff users even with valid credentials", %{conn: conn} do
      regular_customer = customer_fixture()
      
      conn = post(conn, ~p"/admin/login", %{
        "session" => %{
          "email" => regular_customer.email,
          "password" => valid_customer_password()
        }
      })
      
      assert html_response(conn, 200) =~ "Admin Login"
      assert html_response(conn, 200) =~ "You are not authorized to access the admin area"
      refute get_session(conn, :customer_token)
    end
    
    test "shows error for invalid credentials", %{conn: conn} do
      staff_member = staff_customer_fixture()
      
      conn = post(conn, ~p"/admin/login", %{
        "session" => %{
          "email" => staff_member.email,
          "password" => "WrongPassword123!"
        }
      })
      
      assert html_response(conn, 200) =~ "Admin Login"
      assert html_response(conn, 200) =~ "Invalid email or password"
      refute get_session(conn, :customer_token)
    end
    
    test "shows error for non-existent email", %{conn: conn} do
      conn = post(conn, ~p"/admin/login", %{
        "session" => %{
          "email" => "nonexistent@example.com",
          "password" => "SomePassword123!"
        }
      })
      
      assert html_response(conn, 200) =~ "Admin Login"
      assert html_response(conn, 200) =~ "Invalid email or password"
      refute get_session(conn, :customer_token)
    end
    
    test "allows 5 failed login attempts", %{conn: conn} do
      # Reset rate limiter
      Rsolv.RateLimiter.reset()
      
      # Try 5 failed attempts (configured limit)
      for i <- 1..5 do
        conn = post(conn, ~p"/admin/login", %{
          "session" => %{
            "email" => "rate-limit-test@example.com",
            "password" => "wrong#{i}"
          }
        })
        
        assert html_response(conn, 200) =~ "Invalid email or password"
      end
    end
    
    test "blocks after 10 failed attempts", %{conn: conn} do
      # Reset rate limiter
      Rsolv.RateLimiter.reset()
      
      # Make 10 failed attempts (per RFC-056)
      for i <- 1..10 do
        post(conn, ~p"/admin/login", %{
          "session" => %{
            "email" => "rate-limit-test2@example.com",
            "password" => "wrong#{i}"
          }
        })
      end
      
      # 11th attempt should be blocked
      conn = post(conn, ~p"/admin/login", %{
        "session" => %{
          "email" => "rate-limit-test2@example.com",
          "password" => "wrong11"
        }
      })
      
      assert html_response(conn, 200) =~ "Too many login attempts"
    end
  end
end