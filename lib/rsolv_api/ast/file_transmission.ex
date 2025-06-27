defmodule RsolvApi.AST.FileTransmission do
  @moduledoc """
  Secure file transmission protocol for AST service.
  
  Handles:
  - File chunking for large files
  - Progress tracking
  - Integrity verification
  - Automatic cleanup
  """
  
  alias RsolvApi.AST.Encryption
  
  require Logger
  
  @chunk_size 1024 * 1024  # 1MB chunks
  @max_file_size 10 * 1024 * 1024  # 10MB max
  
  @doc """
  Prepares a file for secure transmission.
  Returns encrypted chunks with metadata.
  """
  def prepare_for_transmission(file_content, session) when is_binary(file_content) do
    with :ok <- validate_file_size(file_content),
         chunks <- chunk_file(file_content),
         encrypted_chunks <- encrypt_chunks(chunks, session.encryption_key) do
      
      {:ok, %{
        chunks: encrypted_chunks,
        metadata: %{
          total_chunks: length(encrypted_chunks),
          file_size: byte_size(file_content),
          content_hash: calculate_hash(file_content),
          chunk_size: @chunk_size
        }
      }}
    end
  end
  
  @doc """
  Receives and reassembles encrypted file chunks.
  """
  def receive_transmission(encrypted_chunks, expected_hash, session) do
    with {:ok, chunks} <- decrypt_chunks(encrypted_chunks, session.encryption_key),
         file_content <- IO.iodata_to_binary(chunks),
         :ok <- verify_integrity(file_content, expected_hash) do
      {:ok, file_content}
    end
  end
  
  @doc """
  Encrypts a single file with metadata.
  Used for smaller files that don't need chunking.
  """
  def encrypt_file(file_path, file_content, session) do
    metadata = %{
      path: file_path,
      size: byte_size(file_content),
      hash: calculate_hash(file_content),
      encrypted_at: DateTime.utc_now()
    }
    
    encrypted_data = Encryption.encrypt_and_encode(file_content, session.encryption_key)
    
    %{
      path: file_path,
      encryptedContent: encrypted_data.ciphertext,
      encryption: %{
        iv: encrypted_data.iv,
        algorithm: "aes-256-gcm",
        authTag: encrypted_data.auth_tag
      },
      metadata: metadata
    }
  end
  
  @doc """
  Decrypts a file received from the client.
  """
  def decrypt_file(encrypted_file, session) do
    encrypted_data = %{
      ciphertext: encrypted_file["encryptedContent"],
      iv: encrypted_file["encryption"]["iv"],
      auth_tag: encrypted_file["encryption"]["authTag"]
    }
    
    case Encryption.decode_and_decrypt(encrypted_data, session.encryption_key) do
      {:ok, content} ->
        # Verify hash if provided
        if expected_hash = get_in(encrypted_file, ["metadata", "contentHash"]) do
          actual_hash = calculate_hash(content)
          if actual_hash == expected_hash do
            {:ok, content}
          else
            {:error, :integrity_check_failed}
          end
        else
          {:ok, content}
        end
        
      error ->
        error
    end
  end
  
  @doc """
  Streams a large file in encrypted chunks.
  Returns a stream that yields encrypted chunks.
  """
  def stream_file(file_path, session) do
    File.stream!(file_path, @chunk_size)
    |> Stream.map(fn chunk ->
      Encryption.encrypt_and_encode(chunk, session.encryption_key)
    end)
    |> Stream.with_index()
    |> Stream.map(fn {encrypted_chunk, index} ->
      %{
        chunk_index: index,
        data: encrypted_chunk,
        metadata: %{
          chunk_size: @chunk_size
        }
      }
    end)
  end
  
  # Private functions
  
  defp validate_file_size(content) when byte_size(content) <= @max_file_size do
    :ok
  end
  
  defp validate_file_size(content) do
    {:error, "File too large: #{byte_size(content)} bytes (max #{@max_file_size} bytes)"}
  end
  
  defp chunk_file(content) do
    chunk_file(content, [])
  end
  
  defp chunk_file(<<>>, chunks), do: Enum.reverse(chunks)
  
  defp chunk_file(content, chunks) do
    chunk_size = min(byte_size(content), @chunk_size)
    <<chunk::binary-size(chunk_size), rest::binary>> = content
    chunk_file(rest, [chunk | chunks])
  end
  
  defp encrypt_chunks(chunks, key) do
    Enum.map(chunks, fn chunk ->
      Encryption.encrypt_and_encode(chunk, key)
    end)
  end
  
  defp decrypt_chunks(encrypted_chunks, key) do
    results = Enum.map(encrypted_chunks, fn encrypted_chunk ->
      Encryption.decode_and_decrypt(encrypted_chunk, key)
    end)
    
    # Check if all chunks decrypted successfully
    case Enum.find(results, &match?({:error, _}, &1)) do
      nil ->
        chunks = Enum.map(results, fn {:ok, chunk} -> chunk end)
        {:ok, chunks}
      
      {:error, _reason} = error ->
        error
    end
  end
  
  defp calculate_hash(content) do
    :crypto.hash(:sha256, content)
    |> Base.encode16(case: :lower)
  end
  
  defp verify_integrity(content, expected_hash) do
    actual_hash = calculate_hash(content)
    
    if Encryption.secure_compare(actual_hash, expected_hash) do
      :ok
    else
      Logger.error("Integrity check failed: expected #{expected_hash}, got #{actual_hash}")
      {:error, :integrity_check_failed}
    end
  end
end