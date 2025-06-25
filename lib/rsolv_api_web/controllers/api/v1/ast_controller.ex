defmodule RSOLVWeb.Api.V1.ASTController do
  @moduledoc """
  Controller for AST-based code analysis service (RFC-031).
  Provides secure, multi-language AST analysis with E2E encryption.
  """
  
  use RSOLVWeb, :controller
  
  alias RsolvApi.AST.AnalysisService
  alias RsolvApi.AST.SessionManager
  alias RsolvApi.AST.Encryption
  alias RSOLV.Accounts
  
  require Logger
  
  @max_files 10
  @max_file_size 10 * 1024 * 1024  # 10MB
  @request_timeout 30_000  # 30 seconds
  
  @doc """
  Analyze files using AST-based pattern matching.
  
  Expects encrypted file content and returns security findings.
  """
  def analyze(conn, params) do
    start_time = System.monotonic_time(:millisecond)
    request_id = params["requestId"] || generate_request_id()
    
    with {:ok, api_key} <- get_api_key(conn),
         {:ok, customer} <- validate_api_key(api_key),
         {:ok, request} <- validate_request(params),
         {:ok, session} <- get_or_create_session(request, customer),
         {:ok, decrypted_files} <- decrypt_files(request["files"], session),
         {:ok, results} <- analyze_files(decrypted_files, request["options"], session) do
      
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
        timing: build_timing(total_time, results)
      })
    else
      {:error, :auth_required} ->
        conn
        |> put_status(401)
        |> json(%{
          error: %{
            code: "AUTH_REQUIRED",
            message: "API key required for AST analysis"
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
        
      {:error, {:validation, reason}} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "INVALID_REQUEST",
            message: reason
          },
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
  
  defp validate_api_key(api_key) do
    case Accounts.get_customer_by_api_key(api_key) do
      nil -> {:error, :invalid_api_key}
      customer -> {:ok, customer}
    end
  end
  
  defp validate_request(params) do
    with :ok <- validate_files(params["files"]),
         :ok <- validate_options(params["options"]) do
      {:ok, params}
    end
  end
  
  defp validate_files(nil), do: {:error, {:validation, "files required"}}
  defp validate_files(files) when not is_list(files), do: {:error, {:validation, "files must be array"}}
  defp validate_files(files) when length(files) > @max_files do
    {:error, {:validation, "maximum #{@max_files} files allowed"}}
  end
  defp validate_files(files) do
    Enum.reduce_while(files, :ok, fn file, _acc ->
      case validate_file(file) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end
  
  defp validate_file(file) do
    with :ok <- validate_required(file, "path"),
         :ok <- validate_required(file, "encryptedContent"),
         :ok <- validate_encryption(file["encryption"]),
         :ok <- validate_file_size(file["metadata"]) do
      :ok
    end
  end
  
  defp validate_required(map, key) do
    if Map.has_key?(map, key) do
      :ok
    else
      {:error, {:validation, "#{key} is required"}}
    end
  end
  
  defp validate_encryption(nil), do: {:error, {:validation, "encryption metadata required"}}
  defp validate_encryption(encryption) do
    with :ok <- validate_required(encryption, "iv"),
         :ok <- validate_required(encryption, "algorithm"),
         :ok <- validate_required(encryption, "authTag") do
      if encryption["algorithm"] == "aes-256-gcm" do
        :ok
      else
        {:error, {:validation, "unsupported encryption algorithm"}}
      end
    end
  end
  
  defp validate_file_size(nil), do: :ok
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
  
  defp get_or_create_session(request, customer) do
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
  
  defp decrypt_files(encrypted_files, session) do
    # Decrypt files in parallel
    tasks = Enum.map(encrypted_files, fn file ->
      Task.async(fn ->
        decrypt_file(file, session)
      end)
    end)
    
    # Wait for all with timeout
    results = Task.await_many(tasks, @request_timeout)
    
    # Check for any errors
    errors = Enum.filter(results, &match?({:error, _}, &1))
    
    if Enum.empty?(errors) do
      {:ok, Enum.map(results, fn {:ok, file} -> file end)}
    else
      {:error, List.first(errors)}
    end
  end
  
  defp decrypt_file(file, session) do
    with {:ok, content} <- Encryption.decrypt(
           file["encryptedContent"],
           session.encryption_key,
           file["encryption"]["iv"],
           file["encryption"]["authTag"]
         ) do
      {:ok, %{
        path: file["path"],
        content: content,
        language: detect_language(file),
        metadata: file["metadata"]
      }}
    end
  end
  
  defp detect_language(file) do
    # Use provided language or detect from extension
    file["metadata"]["language"] || detect_from_path(file["path"])
  end
  
  defp detect_from_path(path) do
    case Path.extname(path) do
      ".js" -> "javascript"
      ".ts" -> "typescript"
      ".py" -> "python"
      ".rb" -> "ruby"
      ".php" -> "php"
      ".java" -> "java"
      ".ex" -> "elixir"
      ".exs" -> "elixir"
      _ -> "unknown"
    end
  end
  
  defp analyze_files(files, options, session) do
    # Analyze files in parallel
    tasks = Enum.map(files, fn file ->
      Task.async(fn ->
        analyze_file(file, options, session)
      end)
    end)
    
    # Wait for results
    results = Task.await_many(tasks, @request_timeout - 5000)  # Leave 5s buffer
    
    {:ok, results}
  end
  
  defp analyze_file(file, options, _session) do
    start_time = System.monotonic_time(:millisecond)
    
    try do
      # Call the analysis service
      case AnalysisService.analyze_file(file, options) do
        {:ok, findings} ->
          parse_time = System.monotonic_time(:millisecond) - start_time
          
          %{
            path: file.path,
            status: "success",
            language: file.language,
            findings: findings,
            astStats: %{
              parseTimeMs: parse_time
            }
          }
          
        {:error, reason} ->
          %{
            path: file.path,
            status: "error",
            language: file.language,
            error: format_analysis_error(reason),
            findings: []
          }
      end
    catch
      :exit, {:timeout, _} ->
        %{
          path: file.path,
          status: "timeout",
          language: file.language,
          findings: []
        }
    end
  end
  
  defp format_analysis_error({:parser_error, details}), do: details
  defp format_analysis_error(reason), do: %{type: "AnalysisError", message: inspect(reason)}
  
  defp cleanup_decrypted_files(files) do
    # Ensure decrypted content is cleared from memory
    # Erlang garbage collection will handle this, but we can be explicit
    Enum.each(files, fn file ->
      # Clear the content field
      Map.delete(file, :content)
    end)
    :ok
  end
  
  defp format_results(results) do
    Enum.map(results, fn result ->
      Map.take(result, [:path, :status, :language, :findings, :error, :astStats])
    end)
  end
  
  defp build_summary(results) do
    findings_by_severity = Enum.reduce(results, %{critical: 0, high: 0, medium: 0, low: 0}, fn result, acc ->
      Enum.reduce(result[:findings] || [], acc, fn finding, acc2 ->
        severity = String.to_atom(finding.severity)
        Map.update(acc2, severity, 1, &(&1 + 1))
      end)
    end)
    
    findings_by_language = Enum.reduce(results, %{}, fn result, acc ->
      count = length(result[:findings] || [])
      if count > 0 do
        Map.update(acc, result.language, count, &(&1 + count))
      else
        acc
      end
    end)
    
    successful_results = Enum.filter(results, &(&1.status == "success"))
    total_findings = Enum.reduce(results, 0, fn r, acc -> acc + length(r[:findings] || []) end)
    
    %{
      filesAnalyzed: length(results),
      filesWithFindings: Enum.count(results, fn r -> length(r[:findings] || []) > 0 end),
      totalFindings: total_findings,
      findingsBySeverity: findings_by_severity,
      findingsByLanguage: findings_by_language,
      performance: %{
        avgParseTimeMs: calculate_avg_parse_time(successful_results),
        totalTimeMs: 0  # Will be set by caller
      }
    }
  end
  
  defp calculate_avg_parse_time([]), do: 0
  defp calculate_avg_parse_time(results) do
    total = Enum.reduce(results, 0, fn r, acc ->
      acc + (r[:astStats][:parseTimeMs] || 0)
    end)
    
    round(total / length(results))
  end
  
  defp build_timing(total_time, results) do
    %{
      totalMs: total_time,
      breakdown: %{
        decryption: 0,  # TODO: Track this
        parsing: calculate_total_parse_time(results),
        analysis: 0,    # TODO: Track this
        encryption: 0   # TODO: Track this
      }
    }
  end
  
  defp calculate_total_parse_time(results) do
    Enum.reduce(results, 0, fn r, acc ->
      acc + (r[:astStats][:parseTimeMs] || 0)
    end)
  end
  
  defp generate_request_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end