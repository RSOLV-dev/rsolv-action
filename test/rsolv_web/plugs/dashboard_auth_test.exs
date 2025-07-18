defmodule RsolvWeb.Plugs.DashboardAuthTest do
  use RsolvWeb.ConnCase
  alias RsolvWeb.Plugs.DashboardAuth
  
  setup do
    # Store original config
    original_password = Application.get_env(:rsolv, :admin_password)
    original_emails = Application.get_env(:rsolv, :admin_emails)
    
    # Set test config
    Application.put_env(:rsolv, :admin_password, "test123")
    Application.put_env(:rsolv, :admin_emails, ["admin@test.com"])
    
    on_exit(fn ->
      # Restore original config
      Application.put_env(:rsolv, :admin_password, original_password)
      Application.put_env(:rsolv, :admin_emails, original_emails)
    end)
    
    :ok
  end
  
  describe "authentication" do
    test "allows access with valid credentials", %{conn: conn} do
      auth = Base.encode64("admin:test123")
      
      conn =
        conn
        |> put_req_header("authorization", "Basic #{auth}")
        |> DashboardAuth.call([])
      
      assert conn.assigns[:current_user_email] == "admin@test.com"
      refute conn.halted
    end
    
    test "denies access with invalid credentials", %{conn: conn} do
      auth = Base.encode64("admin:wrong")
      
      conn =
        conn
        |> put_req_header("authorization", "Basic #{auth}")
        |> DashboardAuth.call([])
      
      assert conn.status == 401
      assert conn.halted
    end
    
    test "denies access without credentials", %{conn: conn} do
      conn = DashboardAuth.call(conn, [])
      
      assert conn.status == 401
      assert conn.halted
      assert get_resp_header(conn, "www-authenticate") == [~s(Basic realm="Admin Dashboard")]
    end
  end
  
  describe "feature flag checking" do
    test "allows access when feature is enabled", %{conn: conn} do
      auth = Base.encode64("admin:test123")
      
      # Enable a feature that admins have access to
      # FunWithFlags requires an actor struct
      actor = %FunWithFlags.UI.SimpleActor{id: "admin@test.com"}
      FunWithFlags.enable(:admin_dashboard, for_actor: actor)
      
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> put_req_header("authorization", "Basic #{auth}")
        |> DashboardAuth.call(require_feature: :admin_dashboard)
      
      refute conn.halted
      
      # Cleanup
      FunWithFlags.disable(:admin_dashboard)
    end
    
    test "authenticates successfully regardless of feature flags", %{conn: conn} do
      # DashboardAuth only handles authentication, not feature flags
      auth = Base.encode64("admin:test123")
      
      # Disable a feature flag to show it doesn't affect DashboardAuth
      FunWithFlags.disable(:core_features)
      
      conn =
        conn
        |> put_req_header("authorization", "Basic #{auth}")
        |> DashboardAuth.call([])
      
      # Auth should succeed even with feature disabled
      refute conn.halted
      assert conn.assigns.current_user_email == "admin@test.com"
    end
    
    test "denies access with invalid credentials", %{conn: conn} do
      # DashboardAuth only handles authentication
      auth = Base.encode64("wrong:wrong")
      
      conn =
        conn
        |> put_req_header("authorization", "Basic #{auth}")
        |> DashboardAuth.call([])
      
      # Should get 401 Unauthorized
      assert conn.status == 401
      assert conn.halted
    end
  end
end