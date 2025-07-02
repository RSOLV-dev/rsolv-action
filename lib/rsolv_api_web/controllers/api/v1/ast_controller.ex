defmodule RSOLVWeb.Api.V1.ASTController do
  @moduledoc """
  Fixed AST controller implementation using client-provided encryption keys.
  
  Security approach:
  1. Client generates AES-256 key using crypto.randomBytes(32)
  2. Client sends key in X-Encryption-Key header (base64 encoded) over HTTPS
  3. Server uses client key for decryption
  4. No custom crypto - uses Erlang's :crypto module (same as Plug.Crypto)
  
  This follows the same pattern as Phoenix.Token but with explicit key exchange.
  """
  
  use RSOLVWeb, :controller
  
  alias RsolvApi.AST.AnalysisService
  alias RsolvApi.AST.SessionManager
  alias RSOLV.Accounts
  alias RSOLV.RateLimiter
  
  require Logger
  
  @max_files 10
  @max_file_size 10 * 1024 * 1024  # 10MB
  @request_timeout 30_000  # 30 seconds
  @encryption_key_size 32  # 256 bits for AES-256
  
  def analyze(conn, params) do
    start_time = System.monotonic_time(:millisecond)
    request_id = params["requestId"] || generate_request_id()
    
    with {:ok, api_key} <- get_api_key(conn),
         {:ok, customer} <- validate_api_key(api_key),
         :ok <- check_rate_limit(customer),
         {:ok, encryption_key} <- get_encryption_key(conn),
         {:ok, request} <- validate_request(params),
         {:ok, session} <- get_or_create_session(request, customer, encryption_key),
         {:ok, decrypted_files, decryption_time} <- decrypt_files_with_timing(request["files"], encryption_key),
         {:ok, results, analysis_time} <- analyze_files_with_timing(decrypted_files, request["options"], session) do
      
      # Clean up decrypted content immediately
      :ok = cleanup_decrypted_files(decrypted_files)
      
      # Calculate timing
      total_time = System.monotonic_time(:millisecond) - start_time
      
      json(conn, %{
        requestId: request_id,
        session: %{
          sessionId: session.id,
          expiresAt: session.expires_at
        },
        results: format_results(results),
        summary: build_summary(results),
        timing: build_timing_detailed(total_time, decryption_time, analysis_time, results)
      })
    else
      {:error, :auth_required} ->
        conn
        |> put_status(401)
        |> json(%{
          error: %{
            code: "AUTH_REQUIRED",
            message: "Authentication required"
          },
          requestId: request_id
        })
        
      {:error, :invalid_api_key} ->
        conn
        |> put_status(401)
        |> json(%{
          error: %{
            code: "INVALID_API_KEY",
            message: "Invalid or expired API key"
          },
          requestId: request_id
        })
        
      {:error, :missing_encryption_key} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "MISSING_ENCRYPTION_KEY",
            message: "X-Encryption-Key header is required"
          },
          requestId: request_id
        })
        
      {:error, :invalid_encryption_key_encoding} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "INVALID_ENCRYPTION_KEY",
            message: "X-Encryption-Key must be valid base64"
          },
          requestId: request_id
        })
        
      {:error, :invalid_encryption_key_size} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "INVALID_ENCRYPTION_KEY",
            message: "Encryption key must be 32 bytes (256 bits) for AES-256"
          },
          requestId: request_id
        })
        
      {:error, :decryption_failed} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "DECRYPTION_FAILED",
            message: "Failed to decrypt content. Ensure encryption key matches"
          },
          requestId: request_id
        })
        
      {:error, {:validation, message}} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "INVALID_REQUEST",
            message: message
          },
          requestId: request_id
        })
        
      {:error, :rate_limited} ->
        conn
        |> put_resp_header("retry-after", "60")
        |> put_status(429)
        |> json(%{
          error: %{
            code: "RATE_LIMITED",
            message: "Rate limit exceeded. Please try again later."
          },
          retryAfter: 60,
          requestId: request_id
        })
        
      {:error, reason} ->
        Logger.error("AST analysis error: #{inspect(reason)}")
        conn
        |> put_status(500)
        |> json(%{
          error: %{
            code: "INTERNAL_ERROR",
            message: "Analysis failed"
          },
          requestId: request_id
        })
    end
  end
  
  # Private functions
  
  defp get_api_key(conn) do
    case get_req_header(conn, "x-api-key") do
      [api_key | _] -> {:ok, api_key}
      [] -> {:error, :auth_required}
    end
  end
  
  defp get_encryption_key(conn) do
    case get_req_header(conn, "x-encryption-key") do
      [key_base64 | _] ->
        case Base.decode64(key_base64) do
          {:ok, key} when byte_size(key) == @encryption_key_size ->
            {:ok, key}
          {:ok, _} ->
            {:error, :invalid_encryption_key_size}
          :error ->
            {:error, :invalid_encryption_key_encoding}
        end
      [] ->
        {:error, :missing_encryption_key}
    end
  end
  
  defp validate_api_key(api_key) do
    case Accounts.get_customer_by_api_key(api_key) do
      nil -> {:error, :invalid_api_key}
      customer -> {:ok, customer}
    end
  end
  
  defp check_rate_limit(customer) do
    RateLimiter.check_rate_limit(customer.id, "ast_analysis")
  end
  
  defp validate_request(params) do
    with :ok <- validate_files(params["files"]),
         :ok <- validate_options(params["options"]) do
      {:ok, params}
    end
  end
  
  defp validate_files(nil), do: {:error, {:validation, "files required"}}
  defp validate_files([]), do: {:error, {:validation, "at least one file required"}}
  defp validate_files(files) when length(files) > @max_files do
    {:error, {:validation, "maximum #{@max_files} files allowed"}}
  end
  defp validate_files(files) when is_list(files) do
    Enum.reduce_while(files, :ok, fn file, :ok ->
      case validate_file(file) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end
  defp validate_files(_), do: {:error, {:validation, "files must be an array"}}
  
  defp validate_file(file) do
    with :ok <- validate_file_fields(file),
         :ok <- validate_encryption_fields(file["encryption"]),
         :ok <- validate_file_size(file["metadata"]) do
      :ok
    end
  end
  
  defp validate_file_fields(file) do
    required = ["path", "encryptedContent", "encryption"]
    missing = required -- Map.keys(file)
    
    if Enum.empty?(missing) do
      :ok
    else
      {:error, {:validation, "missing required fields: #{Enum.join(missing, ", ")}"}}
    end
  end
  
  defp validate_encryption_fields(nil), do: {:error, {:validation, "encryption field required"}}
  defp validate_encryption_fields(encryption) do
    required = ["iv", "authTag", "algorithm"]
    missing = required -- Map.keys(encryption)
    
    cond do
      not Enum.empty?(missing) ->
        {:error, {:validation, "missing encryption fields: #{Enum.join(missing, ", ")}"}}
      encryption["algorithm"] != "aes-256-gcm" ->
        {:error, {:validation, "only aes-256-gcm encryption is supported"}}
      true ->
        :ok
    end
  end
  
  defp validate_file_size(%{"size" => size}) when size > @max_file_size do
    {:error, {:validation, "file too large (max #{@max_file_size} bytes)"}}
  end
  defp validate_file_size(_), do: :ok
  
  defp validate_options(nil), do: {:ok, default_options()}
  defp validate_options(options) do
    pattern_format = options["patternFormat"] || "enhanced"
    if pattern_format in ["standard", "enhanced"] do
      :ok
    else
      {:error, {:validation, "invalid pattern format"}}
    end
  end
  
  defp default_options do
    %{
      "patternFormat" => "enhanced",
      "includeSecurityPatterns" => true
    }
  end
  
  defp get_or_create_session(request, customer, _encryption_key) do
    # For now, use default TTL and don't pass metadata
    # TODO: Add metadata support to SessionManager if needed
    
    case request["sessionId"] do
      nil -> 
        SessionManager.create_session(customer.id)
      session_id ->
        case SessionManager.get_session(session_id, customer.id) do
          {:ok, session} -> {:ok, session}
          {:error, _} -> SessionManager.create_session(customer.id)
        end
    end
  end
  
  defp decrypt_files_with_timing(nil, _), do: {:ok, [], 0}
  defp decrypt_files_with_timing(encrypted_files, encryption_key) when is_list(encrypted_files) do
    decryption_start = System.monotonic_time(:millisecond)
    
    # Decrypt files in parallel
    tasks = Enum.map(encrypted_files, fn file ->
      Task.async(fn ->
        decrypt_file(file, encryption_key)
      end)
    end)
    
    # Wait for all with timeout
    results = Task.await_many(tasks, @request_timeout)
    
    decryption_time = System.monotonic_time(:millisecond) - decryption_start
    
    # Check for any errors
    errors = Enum.filter(results, &match?({:error, _}, &1))
    
    if Enum.empty?(errors) do
      {:ok, Enum.map(results, fn {:ok, file} -> file end), decryption_time}
    else
      # Return first error
      List.first(errors)
    end
  end
  
  defp decrypt_file(file, encryption_key) do
    # Decode base64-encoded values
    with {:ok, encrypted_content} <- Base.decode64(file["encryptedContent"]),
         {:ok, iv} <- Base.decode64(file["encryption"]["iv"]),
         {:ok, auth_tag} <- Base.decode64(file["encryption"]["authTag"]),
         {:ok, content} <- decrypt_content(encrypted_content, encryption_key, iv, auth_tag) do
      {:ok, %{
        path: file["path"],
        content: content,
        language: detect_language(file),
        metadata: file["metadata"]
      }}
    else
      :error -> {:error, :invalid_base64}
      error -> error
    end
  end
  
  defp decrypt_content(ciphertext, key, iv, auth_tag) do
    # Use :crypto directly (same as what Plug.Crypto uses internally)
    case :crypto.crypto_one_time_aead(
      :aes_256_gcm,
      key,
      iv,
      ciphertext,
      "",  # No additional authenticated data
      auth_tag,
      false  # encrypt = false (decrypt mode)
    ) do
      :error -> {:error, :decryption_failed}
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
    end
  end
  
  defp detect_language(file) do
    file["metadata"]["language"] || detect_from_path(file["path"])
  end
  
  defp detect_from_path(path) do
    ext = path |> Path.extname() |> String.trim_leading(".") |> String.downcase()
    
    case ext do
      "js" -> "javascript"
      "jsx" -> "javascript"
      "ts" -> "typescript"
      "tsx" -> "typescript"
      "py" -> "python"
      "rb" -> "ruby"
      "php" -> "php"
      "java" -> "java"
      "go" -> "go"
      "ex" -> "elixir"
      "exs" -> "elixir"
      _ -> nil
    end
  end
  
  defp analyze_files_with_timing(files, options, session) do
    analysis_start = System.monotonic_time(:millisecond)
    
    # Analyze files - returns {:ok, results}
    case AnalysisService.analyze_batch(files, options, session) do
      {:ok, results} ->
        analysis_time = System.monotonic_time(:millisecond) - analysis_start
        {:ok, results, analysis_time}
      error ->
        error
    end
  end
  
  defp cleanup_decrypted_files(_files) do
    # Clear sensitive data from memory
    # In Erlang/Elixir, we can't force immediate GC, but we can 
    # ensure references are dropped
    :ok
  end
  
  defp format_results(results) do
    # Format analysis results for response
    results
  end
  
  defp build_summary(results) do
    # Build summary of findings
    %{
      totalFiles: length(results),
      totalFindings: Enum.reduce(results, 0, fn r, acc -> 
        acc + length(Map.get(r, :findings, []))
      end)
    }
  end
  
  defp build_timing_detailed(total_time, decryption_time, analysis_time, results) do
    %{
      total: total_time,
      decryption: decryption_time,
      analysis: analysis_time,
      perFile: if(length(results) > 0, do: div(analysis_time, length(results)), else: 0)
    }
  end
  
  defp generate_request_id do
    "ast-#{System.system_time(:millisecond)}-#{:rand.uniform(999999)}"
  end
end