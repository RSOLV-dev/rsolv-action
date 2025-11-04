defmodule Rsolv.AST.FileTransmissionTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false

  alias Rsolv.AST.FileTransmission
  alias Rsolv.AST.SessionManager
  alias Rsolv.AST.Encryption

  setup do
    # Create a test session
    session = %SessionManager.Session{
      id: "test-session-123",
      customer_id: "test-customer",
      encryption_key: Encryption.generate_key(),
      created_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }

    {:ok, session: session}
  end

  describe "prepare_for_transmission/2" do
    test "prepares small file for transmission", %{session: session} do
      content = "def hello():\n    return 'Hello, World!'"

      {:ok, result} = FileTransmission.prepare_for_transmission(content, session)

      assert Map.has_key?(result, :chunks)
      assert Map.has_key?(result, :metadata)
      assert result.metadata.total_chunks == 1
      assert result.metadata.file_size == byte_size(content)
      assert is_binary(result.metadata.content_hash)
      # SHA256 hex
      assert String.length(result.metadata.content_hash) == 64
    end

    test "chunks large file correctly", %{session: session} do
      # Create 2.5MB file (should be 3 chunks)
      content = String.duplicate("a", 2_500_000)

      {:ok, result} = FileTransmission.prepare_for_transmission(content, session)

      assert result.metadata.total_chunks == 3
      assert result.metadata.file_size == 2_500_000
      assert length(result.chunks) == 3

      # Each chunk should be encrypted
      Enum.each(result.chunks, fn chunk ->
        assert Map.has_key?(chunk, :ciphertext)
        assert Map.has_key?(chunk, :iv)
        assert Map.has_key?(chunk, :auth_tag)
      end)
    end

    test "rejects files over size limit", %{session: session} do
      # Create 11MB file (over 10MB limit)
      content = String.duplicate("a", 11 * 1024 * 1024)

      assert {:error, reason} = FileTransmission.prepare_for_transmission(content, session)
      assert String.contains?(reason, "too large")
    end
  end

  describe "receive_transmission/3" do
    test "reassembles chunked file correctly", %{session: session} do
      original = "This is a test file that will be chunked and transmitted securely."

      # Prepare transmission
      {:ok, prepared} = FileTransmission.prepare_for_transmission(original, session)

      # Receive and reassemble
      {:ok, received} =
        FileTransmission.receive_transmission(
          prepared.chunks,
          prepared.metadata.content_hash,
          session
        )

      assert received == original
    end

    test "detects tampered chunks", %{session: session} do
      original = "This is a test file."

      {:ok, prepared} = FileTransmission.prepare_for_transmission(original, session)

      # Tamper with first chunk
      [first | rest] = prepared.chunks
      # Decode, tamper, and re-encode to maintain valid base64
      {:ok, decoded} = Base.decode64(first.ciphertext)
      tampered = decoded <> <<1, 2, 3>>
      tampered_ciphertext = Base.encode64(tampered)
      tampered_first = %{first | ciphertext: tampered_ciphertext}
      tampered_chunks = [tampered_first | rest]

      assert {:error, :decryption_failed} =
               FileTransmission.receive_transmission(
                 tampered_chunks,
                 prepared.metadata.content_hash,
                 session
               )
    end

    test "detects wrong hash", %{session: session} do
      original = "This is a test file."

      {:ok, prepared} = FileTransmission.prepare_for_transmission(original, session)

      # Use wrong hash
      wrong_hash = :crypto.hash(:sha256, "different content") |> Base.encode16(case: :lower)

      assert {:error, :integrity_check_failed} =
               FileTransmission.receive_transmission(
                 prepared.chunks,
                 wrong_hash,
                 session
               )
    end
  end

  describe "encrypt_file/3" do
    test "encrypts file with metadata", %{session: session} do
      path = "test/example.py"
      content = "print('Hello, World!')"

      result = FileTransmission.encrypt_file(path, content, session)

      assert result.path == path
      assert is_binary(result.encryptedContent)
      assert result.encryption.algorithm == "aes-256-gcm"
      assert is_binary(result.encryption.iv)
      assert is_binary(result.encryption.authTag)
      assert result.metadata.size == byte_size(content)
      assert is_binary(result.metadata.hash)
    end

    test "produces different ciphertext for same content", %{session: session} do
      path = "test.py"
      content = "same content"

      result1 = FileTransmission.encrypt_file(path, content, session)
      result2 = FileTransmission.encrypt_file(path, content, session)

      # Same content should have same hash
      assert result1.metadata.hash == result2.metadata.hash

      # But different ciphertext due to different IVs
      assert result1.encryptedContent != result2.encryptedContent
      assert result1.encryption.iv != result2.encryption.iv
    end
  end

  describe "decrypt_file/2" do
    test "decrypts file successfully", %{session: session} do
      path = "test.rb"
      original_content = "puts 'Hello, Ruby!'"

      # Encrypt
      encrypted = FileTransmission.encrypt_file(path, original_content, session)

      # Convert to format expected by decrypt_file
      encrypted_file = %{
        "path" => encrypted.path,
        "encryptedContent" => encrypted.encryptedContent,
        "encryption" => %{
          "iv" => encrypted.encryption.iv,
          "algorithm" => encrypted.encryption.algorithm,
          "authTag" => encrypted.encryption.authTag
        },
        "metadata" => %{
          "contentHash" => encrypted.metadata.hash
        }
      }

      # Decrypt
      {:ok, decrypted} = FileTransmission.decrypt_file(encrypted_file, session)

      assert decrypted == original_content
    end

    test "fails with wrong session key", %{session: session} do
      path = "test.php"
      content = "<?php echo 'Hello'; ?>"

      # Encrypt with one key
      encrypted = FileTransmission.encrypt_file(path, content, session)

      # Try to decrypt with different key
      wrong_session = %{session | encryption_key: Encryption.generate_key()}

      encrypted_file = %{
        "encryptedContent" => encrypted.encryptedContent,
        "encryption" => %{
          "iv" => encrypted.encryption.iv,
          "algorithm" => encrypted.encryption.algorithm,
          "authTag" => encrypted.encryption.authTag
        }
      }

      assert {:error, :decryption_failed} =
               FileTransmission.decrypt_file(encrypted_file, wrong_session)
    end

    test "detects hash mismatch", %{session: session} do
      path = "test.java"
      content = "public class Test {}"

      encrypted = FileTransmission.encrypt_file(path, content, session)

      # Provide wrong hash
      encrypted_file = %{
        "encryptedContent" => encrypted.encryptedContent,
        "encryption" => %{
          "iv" => encrypted.encryption.iv,
          "algorithm" => encrypted.encryption.algorithm,
          "authTag" => encrypted.encryption.authTag
        },
        "metadata" => %{
          "contentHash" => "wrong_hash_value"
        }
      }

      assert {:error, :integrity_check_failed} =
               FileTransmission.decrypt_file(encrypted_file, session)
    end
  end

  describe "stream_file/2" do
    test "streams file in chunks", %{session: session} do
      # Create a temporary file
      content = String.duplicate("Hello World!\n", 100_000)
      temp_path = Path.join(System.tmp_dir!(), "test_stream_#{:rand.uniform(10000)}.txt")

      try do
        File.write!(temp_path, content)

        # Stream the file
        chunks =
          FileTransmission.stream_file(temp_path, session)
          |> Enum.to_list()

        assert length(chunks) > 0

        # Each chunk should have proper structure
        Enum.each(chunks, fn chunk ->
          assert Map.has_key?(chunk, :chunk_index)
          assert Map.has_key?(chunk, :data)
          assert Map.has_key?(chunk.data, :ciphertext)
          assert Map.has_key?(chunk.data, :iv)
          assert Map.has_key?(chunk.data, :auth_tag)
        end)

        # Chunks should be numbered sequentially
        indices = Enum.map(chunks, & &1.chunk_index)
        assert indices == Enum.to_list(0..(length(chunks) - 1))
      after
        File.rm(temp_path)
      end
    end
  end

  describe "security properties" do
    test "different sessions produce different ciphertext", %{session: session} do
      content = "sensitive data"

      # Create another session
      session2 = %{session | encryption_key: Encryption.generate_key()}

      {:ok, result1} = FileTransmission.prepare_for_transmission(content, session)
      {:ok, result2} = FileTransmission.prepare_for_transmission(content, session2)

      # Same content hash
      assert result1.metadata.content_hash == result2.metadata.content_hash

      # Different ciphertext
      assert result1.chunks != result2.chunks
    end

    test "handles unicode content correctly", %{session: session} do
      content = "Hello 世界! 🚀 λ-calculus"

      {:ok, prepared} = FileTransmission.prepare_for_transmission(content, session)

      {:ok, received} =
        FileTransmission.receive_transmission(
          prepared.chunks,
          prepared.metadata.content_hash,
          session
        )

      assert received == content
    end
  end
end
