defmodule Rsolv.AST.EncryptionFixTest do
  @moduledoc """
  TDD tests for fixing the encryption key exchange issue.

  The fix: Use client-provided encryption key from X-Encryption-Key header
  instead of server-generated session key.
  """

  use ExUnit.Case
  alias Rsolv.AST.Encryption

  describe "Client-provided key encryption" do
    test "server should decrypt using client-provided key from header" do
      # Client generates key and sends in header
      client_key = :crypto.strong_rand_bytes(32)
      client_key_base64 = Base.encode64(client_key)

      # Client encrypts data
      plaintext = "sensitive source code"
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, client_key)

      # Simulate what server receives
      encrypted_file = %{
        "encryptedContent" => Base.encode64(ciphertext),
        "encryption" => %{
          "iv" => Base.encode64(iv),
          "authTag" => Base.encode64(auth_tag),
          "algorithm" => "aes-256-gcm"
        }
      }

      # Server should use client key from header (not session key)
      header_key = Base.decode64!(client_key_base64)

      # Server decrypts using client-provided key
      {:ok, decrypted} =
        with {:ok, encrypted_content} <- Base.decode64(encrypted_file["encryptedContent"]),
             {:ok, iv} <- Base.decode64(encrypted_file["encryption"]["iv"]),
             {:ok, auth_tag} <- Base.decode64(encrypted_file["encryption"]["authTag"]) do
          Encryption.decrypt(encrypted_content, header_key, iv, auth_tag)
        end

      assert decrypted == plaintext
    end

    test "decryption should fail with wrong key" do
      # Client encrypts with one key
      client_key = :crypto.strong_rand_bytes(32)
      plaintext = "sensitive source code"
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, client_key)

      # Server tries to decrypt with different key
      wrong_key = :crypto.strong_rand_bytes(32)

      result = Encryption.decrypt(ciphertext, wrong_key, iv, auth_tag)
      assert result == {:error, :decryption_failed}
    end

    test "controller should extract key from X-Encryption-Key header" do
      # This test demonstrates what the controller needs to do
      client_key = :crypto.strong_rand_bytes(32)
      headers = [{"x-encryption-key", Base.encode64(client_key)}]

      # Extract key from headers
      encryption_key =
        case List.keyfind(headers, "x-encryption-key", 0) do
          {_, key_base64} -> Base.decode64!(key_base64)
          nil -> nil
        end

      assert encryption_key == client_key
      assert byte_size(encryption_key) == 32
    end
  end

  describe "Backwards compatibility" do
    test "should support session-based encryption for existing clients" do
      # For clients that don't send X-Encryption-Key header,
      # fall back to session-based encryption

      session = %{encryption_key: :crypto.strong_rand_bytes(32)}
      plaintext = "code"

      # Encrypt with session key
      {ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, session.encryption_key)

      # Decrypt with session key
      {:ok, decrypted} = Encryption.decrypt(ciphertext, session.encryption_key, iv, auth_tag)

      assert decrypted == plaintext
    end
  end
end
