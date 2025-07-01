defmodule RsolvApi.AST.EncryptionKeyRotationTest do
  use ExUnit.Case, async: true
  
  @moduletag :skip
  
  alias RsolvApi.AST.{Encryption, SessionManager, AuditLogger}
  
  setup do
    # Ensure services are started
    ensure_services_started()
    
    # Clean up any existing data
    cleanup_test_data()
    
    {:ok, %{}}
  end
  
  describe "key rotation functionality" do
    test "can rotate encryption keys while maintaining data access" do
      # Create a session with initial key
      {:ok, session} = SessionManager.create_session(123)
      initial_key = session.encryption_key
      
      # Encrypt data with initial key
      plaintext = "sensitive customer code"
      encrypted_data = Encryption.encrypt(plaintext, initial_key)
      
      # Rotate the key
      {:ok, new_key} = Encryption.rotate_key(session.id, initial_key)
      
      # Verify new key is different
      assert new_key != initial_key
      
      # Verify we can still decrypt old data with key history
      {:ok, decrypted} = Encryption.decrypt_with_rotation(encrypted_data, session.id)
      assert decrypted == plaintext
    end
    
    test "tracks key versions and rotation history" do
      {:ok, session} = SessionManager.create_session(456)
      initial_key = session.encryption_key
      
      # Rotate key multiple times
      {:ok, key_v2} = Encryption.rotate_key(session.id, initial_key)
      {:ok, key_v3} = Encryption.rotate_key(session.id, key_v2)
      
      # Get key history
      {:ok, history} = Encryption.get_key_history(session.id)
      
      assert length(history) == 3
      assert Enum.at(history, 0).version == 1
      assert Enum.at(history, 1).version == 2
      assert Enum.at(history, 2).version == 3
      
      # Verify each rotation is logged
      assert Enum.at(history, 0).key == initial_key
      assert Enum.at(history, 1).key == key_v2
      assert Enum.at(history, 2).key == key_v3
      assert Enum.at(history, 2).active == true
    end
    
    test "can decrypt data encrypted with any previous key version" do
      {:ok, session} = SessionManager.create_session(789)
      
      # Encrypt data with initial key
      plaintext1 = "data version 1"
      {:ok, key1} = Encryption.get_current_key(session.id)
      cipher1 = Encryption.encrypt(plaintext1, key1)
      
      # Rotate and encrypt with new key
      {:ok, key2} = Encryption.rotate_key(session.id, key1)
      plaintext2 = "data version 2"
      cipher2 = Encryption.encrypt(plaintext2, key2)
      
      # Rotate again and encrypt
      {:ok, key3} = Encryption.rotate_key(session.id, key2)
      plaintext3 = "data version 3"
      cipher3 = Encryption.encrypt(plaintext3, key3)
      
      # Verify all can be decrypted
      {:ok, decrypted1} = Encryption.decrypt_with_rotation(cipher1, session.id)
      {:ok, decrypted2} = Encryption.decrypt_with_rotation(cipher2, session.id)
      {:ok, decrypted3} = Encryption.decrypt_with_rotation(cipher3, session.id)
      
      assert decrypted1 == plaintext1
      assert decrypted2 == plaintext2
      assert decrypted3 == plaintext3
    end
    
    test "rotation is atomic and handles failures gracefully" do
      {:ok, session} = SessionManager.create_session(999)
      initial_key = session.encryption_key
      
      # Simulate rotation failure
      {:error, reason} = Encryption.rotate_key(session.id, "invalid_key")
      
      assert reason == :invalid_current_key
      
      # Verify original key still works
      {:ok, current_key} = Encryption.get_current_key(session.id)
      assert current_key == initial_key
    end
    
    test "old keys are marked inactive but retained for decryption" do
      {:ok, session} = SessionManager.create_session(111)
      initial_key = session.encryption_key
      
      # Rotate key
      {:ok, new_key} = Encryption.rotate_key(session.id, initial_key)
      
      # Check key status
      {:ok, history} = Encryption.get_key_history(session.id)
      
      old_key_record = Enum.find(history, & &1.key == initial_key)
      new_key_record = Enum.find(history, & &1.key == new_key)
      
      assert old_key_record.active == false
      assert new_key_record.active == true
      assert old_key_record.rotated_at != nil
    end
    
    test "rotation triggers audit logging" do
      {:ok, session} = SessionManager.create_session(222)
      initial_key = session.encryption_key
      
      # Clear audit logs
      clear_audit_logs()
      
      # Rotate key
      {:ok, _new_key} = Encryption.rotate_key(session.id, initial_key)
      
      # Check audit logs
      events = AuditLogger.query_events(%{event_type: :encryption_key_rotated})
      
      assert length(events) == 1
      event = hd(events)
      
      assert event.metadata.session_id == session.id
      assert event.metadata.from_version == 1
      assert event.metadata.to_version == 2
      assert event.severity == :info
    end
    
    test "supports automatic rotation based on age" do
      # Create session with short rotation period for testing
      {:ok, session} = SessionManager.create_session(333, 3600, %{
        key_rotation_interval: 100  # 100ms for testing
      })
      
      initial_key = session.encryption_key
      
      # Force key history creation to set the timestamp
      {:ok, _} = Encryption.get_current_key(session.id)
      
      # Wait for rotation interval
      Process.sleep(200)
      
      # Check if rotation is needed
      assert Encryption.rotation_needed?(session.id) == true
      
      # Perform automatic rotation
      {:ok, new_key} = Encryption.auto_rotate_if_needed(session.id)
      
      assert new_key != initial_key
      
      # Check again after rotation
      assert Encryption.rotation_needed?(session.id) == false
    end
    
    test "handles concurrent rotation attempts safely" do
      {:ok, session} = SessionManager.create_session(444)
      initial_key = session.encryption_key
      
      # Get the actual initial key for all concurrent attempts
      {:ok, current_key} = Encryption.get_current_key(session.id)
      
      # Spawn multiple concurrent rotation attempts
      tasks = for _ <- 1..5 do
        Task.async(fn ->
          Encryption.rotate_key(session.id, current_key)
        end)
      end
      
      results = Task.await_many(tasks)
      
      # Only one should succeed, others should get rotation_in_progress error
      successful = Enum.filter(results, fn
        {:ok, _} -> true
        _ -> false
      end)
      
      failed = Enum.filter(results, fn
        {:error, :rotation_in_progress} -> true
        _ -> false
      end)
      
      assert length(successful) == 1
      assert length(failed) == 4
      
      # Verify final state is consistent
      {:ok, history} = Encryption.get_key_history(session.id)
      assert length(history) == 2  # Initial + one rotation
    end
    
    test "can export key history for compliance" do
      {:ok, session} = SessionManager.create_session(555)
      initial_key = session.encryption_key
      
      # Perform rotations
      {:ok, key2} = Encryption.rotate_key(session.id, initial_key)
      {:ok, _key3} = Encryption.rotate_key(session.id, key2)
      
      # Export history
      {:ok, export} = Encryption.export_key_history(session.id, :json)
      
      parsed = JSON.decode!(export)
      
      assert parsed["session_id"] == session.id
      assert length(parsed["keys"]) == 3
      assert parsed["keys"] |> Enum.all?(& Map.has_key?(&1, "version"))
      assert parsed["keys"] |> Enum.all?(& Map.has_key?(&1, "created_at"))
      assert parsed["keys"] |> Enum.all?(& !Map.has_key?(&1, "key"))  # Keys should be redacted
    end
    
    test "cleanup removes old inactive keys after retention period" do
      # Create session with short retention for testing
      {:ok, session} = SessionManager.create_session(666, 3600, %{
        key_retention_days: 0  # Immediate cleanup for testing
      })
      
      initial_key = session.encryption_key
      
      # Encrypt data with initial key
      ciphertext = Encryption.encrypt("test data", initial_key)
      
      # Rotate key
      {:ok, _new_key} = Encryption.rotate_key(session.id, initial_key)
      
      # Run cleanup
      {:ok, cleaned} = Encryption.cleanup_old_keys()
      
      assert cleaned == 0  # Should not clean keys still needed
      
      # Mark data as deleted
      Encryption.mark_data_deleted(session.id, ciphertext)
      
      # Run cleanup again
      {:ok, cleaned} = Encryption.cleanup_old_keys()
      
      assert cleaned == 1  # Now safe to clean
      
      # Verify old key is gone
      {:ok, history} = Encryption.get_key_history(session.id)
      assert length(history) == 1  # Only current key remains
    end
  end
  
  # Helper functions
  
  defp ensure_services_started do
    services = [
      {SessionManager, []},
      {AuditLogger, []}
    ]
    
    Enum.each(services, fn {module, opts} ->
      case GenServer.whereis(module) do
        nil -> {:ok, _} = apply(module, :start_link, [opts])
        _pid -> :ok
      end
    end)
  end
  
  defp cleanup_test_data do
    # Clean up ETS tables
    tables = [:ast_sessions, :encryption_keys, :key_history, :audit_log_buffer, :key_rotation_locks, :deleted_data_tracker]
    
    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined -> :ok
        _ -> :ets.delete_all_objects(table)
      end
    end)
  end
  
  defp clear_audit_logs do
    case :ets.whereis(:audit_log_buffer) do
      :undefined -> :ok
      _ -> :ets.delete_all_objects(:audit_log_buffer)
    end
  end
end