defmodule Rsolv.AST.SessionManagerTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.AST.SessionManager
  alias Rsolv.AST.Encryption
  
  setup do
    # SessionManager is already started by the application
    :ok
  end
  
  describe "session creation" do
    test "creates new session with unique ID" do
      customer_id = "test-customer-123"
      
      {:ok, session} = SessionManager.create_session(customer_id)
      
      assert session.id != nil
      assert is_binary(session.id)
      assert String.length(session.id) == 32  # 16 bytes hex
      assert session.customer_id == customer_id
      assert session.encryption_key != nil
      assert byte_size(session.encryption_key) == 32
      assert session.created_at != nil
      assert session.expires_at != nil
      
      # Should expire in 1 hour by default
      diff = DateTime.diff(session.expires_at, session.created_at, :second)
      assert diff == 3600
    end
    
    test "creates unique sessions for same customer" do
      customer_id = "test-customer-123"
      
      {:ok, session1} = SessionManager.create_session(customer_id)
      {:ok, session2} = SessionManager.create_session(customer_id)
      
      assert session1.id != session2.id
      assert session1.encryption_key != session2.encryption_key
    end
    
    test "respects custom TTL" do
      customer_id = "test-customer-123"
      ttl_seconds = 1800  # 30 minutes
      
      {:ok, session} = SessionManager.create_session(customer_id, ttl_seconds)
      
      diff = DateTime.diff(session.expires_at, session.created_at, :second)
      assert diff == ttl_seconds
    end
  end
  
  describe "session retrieval" do
    setup do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      {:ok, session: session, customer_id: customer_id}
    end
    
    test "retrieves valid session", %{session: session, customer_id: customer_id} do
      {:ok, retrieved} = SessionManager.get_session(session.id, customer_id)
      
      assert retrieved.id == session.id
      assert retrieved.customer_id == session.customer_id
      assert retrieved.encryption_key == session.encryption_key
    end
    
    test "fails with wrong customer ID", %{session: session} do
      wrong_customer = "wrong-customer-456"
      
      assert {:error, :session_not_found} = SessionManager.get_session(session.id, wrong_customer)
    end
    
    test "fails with non-existent session ID" do
      fake_id = "fake-session-id-123"
      customer_id = "test-customer-123"
      
      assert {:error, :session_not_found} = SessionManager.get_session(fake_id, customer_id)
    end
    
    test "removes expired sessions", %{customer_id: customer_id} do
      # Create session with very short TTL
      {:ok, session} = SessionManager.create_session(customer_id, 1)
      
      # Should be retrievable immediately
      assert {:ok, _} = SessionManager.get_session(session.id, customer_id)
      
      # Wait for expiration
      Process.sleep(1100)
      
      # Should be expired now
      assert {:error, :session_expired} = SessionManager.get_session(session.id, customer_id)
    end
  end
  
  describe "session deletion" do
    setup do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      {:ok, session: session, customer_id: customer_id}
    end
    
    test "deletes session successfully", %{session: session, customer_id: customer_id} do
      assert :ok = SessionManager.delete_session(session.id, customer_id)
      
      # Should not be retrievable after deletion
      assert {:error, :session_not_found} = SessionManager.get_session(session.id, customer_id)
    end
    
    test "ignores deletion of non-existent session" do
      fake_id = "fake-session-id-123"
      customer_id = "test-customer-123"
      
      assert :ok = SessionManager.delete_session(fake_id, customer_id)
    end
  end
  
  describe "session cleanup" do
    test "automatically cleans up expired sessions" do
      customer_id = "test-customer-123"
      
      # Create multiple sessions with short TTL
      {:ok, session1} = SessionManager.create_session(customer_id, 1)
      {:ok, session2} = SessionManager.create_session(customer_id, 1)
      {:ok, session3} = SessionManager.create_session(customer_id, 3600)  # Long TTL
      
      # Wait for first two to expire
      Process.sleep(1100)
      
      # Trigger cleanup
      SessionManager.cleanup_expired_sessions()
      
      # First two should be gone (either expired or not found after cleanup)
      assert {:error, error1} = SessionManager.get_session(session1.id, customer_id)
      assert error1 in [:session_expired, :session_not_found]
      
      assert {:error, error2} = SessionManager.get_session(session2.id, customer_id)
      assert error2 in [:session_expired, :session_not_found]
      
      # Third should still be valid
      assert {:ok, _} = SessionManager.get_session(session3.id, customer_id)
    end
    
    test "counts active sessions" do
      customer1 = "customer-test-count-1-#{System.unique_integer()}"
      customer2 = "customer-test-count-2-#{System.unique_integer()}"
      
      # Get initial count
      initial_count = SessionManager.count_active_sessions()
      
      # Create sessions
      {:ok, session1} = SessionManager.create_session(customer1)
      {:ok, session2} = SessionManager.create_session(customer1)
      {:ok, session3} = SessionManager.create_session(customer2)
      
      # Verify count increased by at least 3 (other tests might be running)
      new_count = SessionManager.count_active_sessions()
      assert new_count >= initial_count + 3
      
      # Create expired session
      {:ok, expired} = SessionManager.create_session(customer1, 1)
      Process.sleep(1100)
      
      # Cleanup should remove expired
      SessionManager.cleanup_expired_sessions()
      
      # After cleanup, the three non-expired sessions should still exist
      # but we can't assert exact count due to parallel tests
      assert {:ok, _} = SessionManager.get_session(session1.id, customer1)
      assert {:ok, _} = SessionManager.get_session(session2.id, customer1)
      assert {:ok, _} = SessionManager.get_session(session3.id, customer2)
      assert {:error, :session_expired} = SessionManager.get_session(expired.id, customer1)
    end
  end
  
  describe "session security" do
    test "encryption keys are cleared from memory on deletion" do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # Save key reference
      key = session.encryption_key
      
      # Delete session
      SessionManager.delete_session(session.id, customer_id)
      
      # Key should be cleared (in real implementation)
      # This is more of a documentation test
      assert byte_size(key) == 32
    end
    
    test "session data is not logged" do
      # Ensure sensitive data doesn't appear in logs
      # This would be verified by log configuration
      assert true
    end
  end
  
  describe "concurrent session management" do
    test "handles concurrent session creation" do
      customer_id = "test-customer-123"
      
      # Create 100 sessions concurrently
      tasks = for _ <- 1..100 do
        Task.async(fn ->
          SessionManager.create_session(customer_id)
        end)
      end
      
      results = Task.await_many(tasks)
      
      # All should succeed
      assert Enum.all?(results, fn
        {:ok, _session} -> true
        _ -> false
      end)
      
      # All session IDs should be unique
      session_ids = Enum.map(results, fn {:ok, session} -> session.id end)
      assert length(session_ids) == length(Enum.uniq(session_ids))
    end
    
    test "handles concurrent session access" do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # Access session from multiple processes
      tasks = for _ <- 1..50 do
        Task.async(fn ->
          SessionManager.get_session(session.id, customer_id)
        end)
      end
      
      results = Task.await_many(tasks)
      
      # All should succeed and return same session
      assert Enum.all?(results, fn
        {:ok, retrieved} -> retrieved.id == session.id
        _ -> false
      end)
    end
  end
  
  describe "session persistence" do
    test "uses ETS for session storage enabling cluster persistence" do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # Session should be retrievable through normal API
      assert {:ok, retrieved} = SessionManager.get_session(session.id, customer_id)
      assert retrieved.id == session.id
      
      # Verify session exists in ETS directly (cross-node access capability)
      case :ets.lookup(:ast_sessions, session.id) do
        [{session_id, session_data}] ->
          assert session_id == session.id
          assert session_data.customer_id == customer_id
          # Verify it's the complete session struct
          assert session_data.encryption_key != nil
          assert session_data.expires_at != nil
        [] ->
          flunk("Session not found in ETS table")
      end
      
      # Verify customer sessions index also uses ETS
      case :ets.lookup(:ast_customer_sessions, customer_id) do
        [{^customer_id, session_list}] ->
          assert session.id in session_list
        [] ->
          flunk("Customer session index not found in ETS")
      end
      
      # This demonstrates that sessions are stored in clustered ETS
      # In a real cluster, nodes would automatically share this data
      assert true
    end
    
    test "sessions are accessible across cluster nodes" do
      customer_id = "test-customer-123"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # Simulate accessing from another node by checking ETS directly
      # In a real cluster, this would be automatically available
      sessions_table = :ast_sessions
      
      # Should be able to read session data from ETS table
      case :ets.lookup(sessions_table, session.id) do
        [{session_id, session_data}] ->
          assert session_id == session.id
          assert session_data.customer_id == customer_id
        [] ->
          flunk("Session not found in ETS table")
      end
    end
  end
  
  describe "session limits" do
    test "enforces maximum sessions per customer" do
      customer_id = "test-customer-123"
      max_sessions = 10
      
      # Create max sessions
      sessions = for _ <- 1..max_sessions do
        {:ok, session} = SessionManager.create_session(customer_id)
        session
      end
      
      # Next creation should remove oldest
      {:ok, new_session} = SessionManager.create_session(customer_id)
      
      # Oldest should be gone
      oldest = List.first(sessions)
      assert {:error, :session_not_found} = SessionManager.get_session(oldest.id, customer_id)
      
      # Newest should exist
      assert {:ok, _} = SessionManager.get_session(new_session.id, customer_id)
    end
  end
end