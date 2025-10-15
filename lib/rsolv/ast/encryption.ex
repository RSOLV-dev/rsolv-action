defmodule Rsolv.AST.Encryption do
  @moduledoc """
  End-to-end encryption for AST service.
  Uses AES-256-GCM for authenticated encryption.

  Security features:
  - 256-bit keys for AES-256
  - Unique IV for each encryption
  - Authentication tags to prevent tampering
  - Secure random generation
  - Base64 encoding for transport
  """

  @aes_key_bytes 32
  @iv_bytes 16
  @auth_tag_bytes 16

  @doc """
  Generates a new 256-bit AES key.
  """
  def generate_key do
    :crypto.strong_rand_bytes(@aes_key_bytes)
  end

  @doc """
  Generates a new key with an associated ID for tracking.
  Returns {key, key_id} tuple.
  """
  def generate_key_with_id do
    key = generate_key()
    key_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
    {key, key_id}
  end

  @doc """
  Encrypts plaintext using AES-256-GCM.
  Returns {ciphertext, iv, auth_tag} tuple.
  """
  def encrypt(plaintext, key) when is_binary(plaintext) and byte_size(key) == @aes_key_bytes do
    # Generate random IV
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    # Encrypt using AES-256-GCM
    {ciphertext, auth_tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv,
        plaintext,
        # No additional authenticated data
        "",
        @auth_tag_bytes,
        # Encrypt mode
        true
      )

    {ciphertext, iv, auth_tag}
  end

  @doc """
  Decrypts ciphertext using AES-256-GCM.
  Returns {:ok, plaintext} or {:error, :decryption_failed}.
  """
  def decrypt(ciphertext, key, iv, auth_tag)
      when is_binary(ciphertext) and
             byte_size(key) == @aes_key_bytes and
             byte_size(iv) == @iv_bytes and
             byte_size(auth_tag) == @auth_tag_bytes do
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           iv,
           ciphertext,
           # No additional authenticated data
           "",
           auth_tag,
           # Decrypt mode
           false
         ) do
      plaintext when is_binary(plaintext) ->
        {:ok, plaintext}

      :error ->
        {:error, :decryption_failed}
    end
  end

  def decrypt(_ciphertext, _key, _iv, _auth_tag) do
    {:error, :decryption_failed}
  end

  @doc """
  Encrypts and encodes data for JSON transport.
  Returns a map with base64-encoded values.
  """
  def encrypt_and_encode(plaintext, key) do
    {ciphertext, iv, auth_tag} = encrypt(plaintext, key)

    %{
      ciphertext: Base.encode64(ciphertext),
      iv: Base.encode64(iv),
      auth_tag: Base.encode64(auth_tag)
    }
  end

  @doc """
  Decodes and decrypts data from JSON transport format.
  Returns {:ok, plaintext} or {:error, reason}.
  """
  def decode_and_decrypt(%{ciphertext: ciphertext_b64, iv: iv_b64, auth_tag: auth_tag_b64}, key) do
    with {:ok, ciphertext} <- Base.decode64(ciphertext_b64),
         {:ok, iv} <- Base.decode64(iv_b64),
         {:ok, auth_tag} <- Base.decode64(auth_tag_b64) do
      decrypt(ciphertext, key, iv, auth_tag)
    else
      :error -> {:error, :invalid_base64}
      error -> error
    end
  end

  def decode_and_decrypt(_invalid_data, _key) do
    {:error, :invalid_format}
  end

  @doc """
  Serializes a key to base64 for storage/transport.
  """
  def serialize_key(key) when byte_size(key) == @aes_key_bytes do
    Base.encode64(key)
  end

  @doc """
  Deserializes a key from base64.
  Returns {:ok, key} or {:error, :invalid_key}.
  """
  def deserialize_key(key_b64) when is_binary(key_b64) do
    case Base.decode64(key_b64) do
      {:ok, key} when byte_size(key) == @aes_key_bytes ->
        {:ok, key}

      {:ok, _wrong_size} ->
        {:error, :invalid_key}

      :error ->
        {:error, :invalid_key}
    end
  end

  def deserialize_key(_) do
    {:error, :invalid_key}
  end

  @doc """
  Securely compares two binaries in constant time.
  Prevents timing attacks.
  """
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    if byte_size(a) == byte_size(b) do
      :crypto.hash_equals(a, b)
    else
      false
    end
  end

  @doc """
  Generates a cryptographically secure random token.
  """
  def generate_token(bytes \\ 32) do
    :crypto.strong_rand_bytes(bytes)
    |> Base.url_encode64(padding: false)
  end
end
