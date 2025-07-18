defmodule RsolvWeb.FunWithFlagsUITest do
  use RsolvWeb.ConnCase
  
  @moduletag :integration
  
  describe "FunWithFlags UI Enable/Disable functionality" do
    setup do
      # Create a test flag
      flag_name = :ui_test_flag_#{:rand.uniform(10000)}
      
      # Ensure it's disabled initially
      FunWithFlags.disable(flag_name)
      
      # Set up admin auth
      credentials = Base.encode64("admin:#{Application.get_env(:rsolv, :admin_password)}")
      
      %{
        flag_name: flag_name,
        auth_header: {"authorization", "Basic #{credentials}"}
      }
    end
    
    test "Enable button updates flag state immediately", %{conn: conn, flag_name: flag_name, auth_header: auth_header} do
      # Verify flag is disabled
      refute FunWithFlags.enabled?(flag_name)
      
      # Click Enable button via UI endpoint
      conn = 
        conn
        |> put_req_header(elem(auth_header, 0), elem(auth_header, 1))
        |> patch("/feature-flags/flags/#{flag_name}/boolean", %{"enabled" => "true"})
      
      # Should redirect back
      assert redirected_to(conn) == "/feature-flags/flags/#{flag_name}"
      
      # Flag should be enabled immediately
      assert FunWithFlags.enabled?(flag_name)
      
      # Clean up
      FunWithFlags.disable(flag_name)
    end
    
    test "Disable button updates flag state immediately", %{conn: conn, flag_name: flag_name, auth_header: auth_header} do
      # Enable the flag first
      FunWithFlags.enable(flag_name)
      assert FunWithFlags.enabled?(flag_name)
      
      # Click Disable button via UI endpoint
      conn = 
        conn
        |> put_req_header(elem(auth_header, 0), elem(auth_header, 1))
        |> patch("/feature-flags/flags/#{flag_name}/boolean", %{"enabled" => "false"})
      
      # Should redirect back
      assert redirected_to(conn) == "/feature-flags/flags/#{flag_name}"
      
      # Flag should be disabled immediately
      refute FunWithFlags.enabled?(flag_name)
    end
  end
end