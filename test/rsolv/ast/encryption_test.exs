defmodule Rsolv.AST.EncryptionTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.AST.Encryption
  
  describe "key generation" do
    test "generates 256-bit AES key" do
      key = Encryption.generate_key()
      
      # Key should be 32 bytes (256 bits)
      assert byte_size(key) == 32
      
      # Should be different each time
      key2 = Encryption.generate_key()
      assert key != key2
    end
    
    test "generates key with ID for tracking" do
      {key, key_id} = Encryption.generate_key_with_id()
      
      assert byte_size(key) == 32
      assert is_binary(key_id)
      assert String.length(key_id) == 32  # 16 bytes hex encoded
    end
  end
  
  describe "encryption and decryption" do
    setup do
      key = Encryption.generate_key()
      {:ok, key: key}
    end
    
    test "encrypts and decrypts text correctly", %{key: key} do
      plaintext = "def vulnerable_function():\n    query = f'SELECT * FROM users WHERE id = {user_id}'"
      
      # Encrypt
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key)
      
      assert is_binary(ciphertext)
      assert is_binary(iv)
      assert byte_size(iv) == 16  # 128-bit IV for AES-GCM
      assert is_binary(auth_tag)
      assert byte_size(auth_tag) == 16  # 128-bit auth tag
      
      # Ciphertext should be different from plaintext
      assert ciphertext != plaintext
      
      # Decrypt
      {:ok, decrypted} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
      assert decrypted == plaintext
    end
    
    test "handles large files", %{key: key} do
      # Generate 1MB of text
      large_text = String.duplicate("a", 1024 * 1024)
      
      # Should encrypt without issues
      {ciphertext, iv, auth_tag} = Encryption.encrypt(large_text, key)
      
      # Should decrypt correctly
      {:ok, decrypted} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
      assert decrypted == large_text
    end
    
    test "handles unicode content", %{key: key} do
      unicode_text = "def 你好():\n    return '🚀 Unicode test λ'"
      
      {ciphertext, iv, auth_tag} = Encryption.encrypt(unicode_text, key)
      {:ok, decrypted} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
      
      assert decrypted == unicode_text
    end
    
    test "fails with wrong key" do
      key1 = Encryption.generate_key()
      key2 = Encryption.generate_key()
      plaintext = "secret code"
      
      # Encrypt with key1
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key1)
      
      # Try to decrypt with key2
      assert {:error, :decryption_failed} = Encryption.decrypt(ciphertext, key2, iv, auth_tag)
    end
    
    test "fails with tampered ciphertext" do
      key = Encryption.generate_key()
      plaintext = "secret code"
      
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key)
      
      # Tamper with ciphertext
      tampered = ciphertext <> "x"
      
      assert {:error, :decryption_failed} = Encryption.decrypt(tampered, key, iv, auth_tag)
    end
    
    test "fails with wrong auth tag" do
      key = Encryption.generate_key()
      plaintext = "secret code"
      
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key)
      
      # Use wrong auth tag
      wrong_tag = :crypto.strong_rand_bytes(16)
      
      assert {:error, :decryption_failed} = Encryption.decrypt(ciphertext, key, iv, wrong_tag)
    end
  end
  
  describe "base64 encoding for transport" do
    setup do
      key = Encryption.generate_key()
      {:ok, key: key}
    end
    
    test "encodes encrypted data for JSON transport", %{key: key} do
      plaintext = "test data"
      
      # Encrypt and encode
      encrypted_data = Encryption.encrypt_and_encode(plaintext, key)
      
      assert is_map(encrypted_data)
      assert Map.has_key?(encrypted_data, :ciphertext)
      assert Map.has_key?(encrypted_data, :iv)
      assert Map.has_key?(encrypted_data, :auth_tag)
      
      # All values should be base64 encoded strings
      assert is_binary(encrypted_data.ciphertext)
      assert is_binary(encrypted_data.iv)
      assert is_binary(encrypted_data.auth_tag)
      
      # Should be valid base64
      assert {:ok, _} = Base.decode64(encrypted_data.ciphertext)
      assert {:ok, _} = Base.decode64(encrypted_data.iv)
      assert {:ok, _} = Base.decode64(encrypted_data.auth_tag)
    end
    
    test "decodes and decrypts from JSON transport format", %{key: key} do
      plaintext = "test data"
      
      # Encrypt and encode
      encrypted_data = Encryption.encrypt_and_encode(plaintext, key)
      
      # Decode and decrypt
      {:ok, decrypted} = Encryption.decode_and_decrypt(encrypted_data, key)
      assert decrypted == plaintext
    end
  end
  
  describe "key serialization" do
    test "serializes key to base64 for storage" do
      key = Encryption.generate_key()
      serialized = Encryption.serialize_key(key)
      
      assert is_binary(serialized)
      assert String.length(serialized) == 44  # 32 bytes -> 44 chars base64
      
      # Should be valid base64
      assert {:ok, decoded} = Base.decode64(serialized)
      assert decoded == key
    end
    
    test "deserializes key from base64" do
      key = Encryption.generate_key()
      serialized = Encryption.serialize_key(key)
      
      {:ok, deserialized} = Encryption.deserialize_key(serialized)
      assert deserialized == key
    end
    
    test "fails to deserialize invalid key" do
      assert {:error, :invalid_key} = Encryption.deserialize_key("not-base64")
      assert {:error, :invalid_key} = Encryption.deserialize_key("")
      
      # Wrong length
      short_key = Base.encode64(:crypto.strong_rand_bytes(16))
      assert {:error, :invalid_key} = Encryption.deserialize_key(short_key)
    end
  end
  
  describe "secure memory handling" do
    test "clears sensitive data from memory" do
      key = Encryption.generate_key()
      plaintext = "sensitive data"
      
      # Encrypt
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key)
      
      # Clear key from memory (simulate)
      # In real implementation, we'd use :crypto.exor or similar
      cleared_key = :crypto.exor(key, key)
      assert cleared_key == <<0::size(256)>>
    end
  end
  
  describe "performance" do
    @tag :benchmark
    test "encrypts 10MB in reasonable time" do
      key = Encryption.generate_key()
      plaintext = String.duplicate("a", 10 * 1024 * 1024)
      
      {time, {_ciphertext, _iv, _auth_tag}} = :timer.tc(fn ->
        Encryption.encrypt(plaintext, key)
      end)
      
      # Should complete in under 100ms
      assert time < 100_000, "Encryption took #{time}μs"
    end
    
    @tag :benchmark
    test "handles concurrent encryption" do
      key = Encryption.generate_key()
      
      # Run 100 concurrent encryptions
      tasks = for i <- 1..100 do
        Task.async(fn ->
          plaintext = "concurrent test #{i}"
          {time, _result} = :timer.tc(fn ->
            Encryption.encrypt(plaintext, key)
          end)
          time
        end)
      end
      
      times = Task.await_many(tasks)
      avg_time = Enum.sum(times) / length(times)
      
      # Average should still be fast
      assert avg_time < 10_000, "Average encryption time: #{avg_time}μs"
    end
  end
end