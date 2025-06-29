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
  alias RSOLV.RateLimiter
  
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
         :ok <- check_rate_limit(customer),
         {:ok, request} <- validate_request(params),
         {:ok, session} <- get_or_create_session(request, customer),
         {:ok, decrypted_files, decryption_time} <- decrypt_files_with_timing(request["files"], session),
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
        
      {:error, :rate_limited} ->
        conn
        |> put_status(429)
        |> put_resp_header("retry-after", "60")
        |> json(%{
          error: %{
            code: "RATE_LIMITED",
            message: "Rate limit exceeded. Please retry after 60 seconds."
          },
          requestId: request_id,
          retryAfter: 60
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
  
  defp check_rate_limit(customer) do
    # Rate limit: 100 AST analysis requests per minute per customer
    RateLimiter.check_rate_limit(customer.id, "ast_analysis")
  end
  
  defp validate_request(params) do
    Logger.info("validate_request called with params: #{inspect(params)}")
    Logger.info("params[\"files\"]: #{inspect(params["files"])}")
    
    result = with :ok <- validate_files(params["files"]),
         :ok <- validate_options(params["options"]) do
      Logger.info("Validation successful, returning params")
      {:ok, params}
    end
    
    Logger.info("validate_request result: #{inspect(result)}")
    result
  end
  
  defp validate_files(nil), do: 
    (Logger.info("validate_files: files is nil"); {:error, {:validation, "files required"}})
  defp validate_files(files) when not is_list(files), do: 
    (Logger.info("validate_files: files is not a list: #{inspect(files)}"); {:error, {:validation, "files must be array"}})
  defp validate_files(files) when length(files) > @max_files do
    Logger.info("validate_files: too many files: #{length(files)}")
    {:error, {:validation, "maximum #{@max_files} files allowed"}}
  end
  defp validate_files(files) do
    Logger.info("validate_files: validating #{length(files)} files")
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
    Logger.info("get_or_create_session called with customer.id: #{customer.id}")
    
    result = case request["sessionId"] do
      nil -> 
        Logger.info("Creating new session for customer #{customer.id}")
        SessionManager.create_session(customer.id)
      session_id ->
        Logger.info("Looking for existing session: #{session_id}")
        case SessionManager.get_session(session_id, customer.id) do
          {:ok, session} -> {:ok, session}
          {:error, reason} -> 
            Logger.info("Session not found (#{inspect(reason)}), creating new one")
            SessionManager.create_session(customer.id)
        end
    end
    
    Logger.info("get_or_create_session result: #{inspect(result)}")
    result
  end
  
  defp decrypt_files_with_timing(nil, _session) do
    Logger.warning("decrypt_files_with_timing called with nil files")
    {:ok, [], 0}
  end
  
  defp decrypt_files_with_timing(encrypted_files, session) when is_list(encrypted_files) do
    decryption_start = System.monotonic_time(:millisecond)
    
    # Decrypt files in parallel
    tasks = Enum.map(encrypted_files, fn file ->
      Task.async(fn ->
        decrypt_file(file, session)
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
      {:error, List.first(errors)}
    end
  end

  
  defp decrypt_file(file, session) do
    # Decode base64-encoded values
    with {:ok, encrypted_content} <- Base.decode64(file["encryptedContent"]),
         {:ok, iv} <- Base.decode64(file["encryption"]["iv"]),
         {:ok, auth_tag} <- Base.decode64(file["encryption"]["authTag"]),
         {:ok, content} <- Encryption.decrypt(
           encrypted_content,
           session.encryption_key,
           iv,
           auth_tag
         ) do
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
  
  defp analyze_files_with_timing(files, options, session) do
    analysis_start = System.monotonic_time(:millisecond)
    
    # Analyze files in parallel
    tasks = Enum.map(files, fn file ->
      Task.async(fn ->
        analyze_file(file, options, session)
      end)
    end)
    
    # Wait for results
    results = Task.await_many(tasks, @request_timeout - 5000)  # Leave 5s buffer
    
    analysis_time = System.monotonic_time(:millisecond) - analysis_start
    
    {:ok, results, analysis_time}
  end

  
  defp analyze_file(file, options, _session) do
    start_time = System.monotonic_time(:millisecond)
    
    try do
      # Call the analysis service with metrics
      case AnalysisService.analyze_file_with_metrics(file, options) do
        {:ok, findings, metrics} ->
          total_time = System.monotonic_time(:millisecond) - start_time
          
          %{
            path: file.path,
            status: "success",
            language: file.language,
            findings: findings,
            astStats: %{
              parseTimeMs: total_time,
              astParseTime: metrics.ast_parse_time || 0,
              patternMatchTime: metrics.pattern_match_time || 0,
              cacheHit: metrics.cache_hit || false,
              nodeCount: metrics.node_count || 0
            }
          }
          
        {:error, reason} ->
          total_time = System.monotonic_time(:millisecond) - start_time
          
          %{
            path: file.path,
            status: "error",
            language: file.language,
            error: format_analysis_error(reason),
            findings: [],
            astStats: %{
              parseTimeMs: total_time,
              astParseTime: 0,
              patternMatchTime: 0,
              cacheHit: false,
              nodeCount: 0
            }
          }
      end
    catch
      :exit, {:timeout, _} ->
        total_time = System.monotonic_time(:millisecond) - start_time
        
        %{
          path: file.path,
          status: "timeout",
          language: file.language,
          findings: [],
          astStats: %{
            parseTimeMs: total_time,
            astParseTime: 0,
            patternMatchTime: 0,
            cacheHit: false,
            nodeCount: 0
          }
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
  
  defp build_timing_detailed(total_time, decryption_time, analysis_time, results) do
    parse_time = calculate_total_parse_time(results)
    pattern_match_time = calculate_total_pattern_match_time(results)
    overhead_time = total_time - decryption_time - analysis_time
    
    %{
      totalMs: total_time,
      breakdown: %{
        decryption: decryption_time,
        parsing: parse_time,
        patternMatching: pattern_match_time,
        analysis: analysis_time,
        overhead: max(0, overhead_time)  # Time for validation, session management, etc.
      },
      performance: %{
        avgDecryptionPerFile: safe_divide(decryption_time, length(results)),
        avgParsePerFile: safe_divide(parse_time, length(results)),
        avgPatternMatchPerFile: safe_divide(pattern_match_time, length(results)),
        totalFilesProcessed: length(results),
        parallelEfficiency: calculate_parallel_efficiency(analysis_time, parse_time)
      }
    }
  end

  
  defp calculate_total_parse_time(results) do
    Enum.reduce(results, 0, fn r, acc ->
      acc + (r[:astStats][:astParseTime] || r[:astStats][:parseTimeMs] || 0)
    end)
  end

  defp calculate_total_pattern_match_time(results) do
    Enum.reduce(results, 0, fn r, acc ->
      acc + (r[:astStats][:patternMatchTime] || 0)
    end)
  end

  defp safe_divide(_numerator, 0), do: 0
  defp safe_divide(numerator, denominator), do: round(numerator / denominator)

  defp calculate_parallel_efficiency(analysis_time, parse_time) do
    # Calculate how much time we saved through parallelization
    # Perfect efficiency would be parse_time / analysis_time approaching number of files
    if analysis_time > 0 do
      efficiency = min(1.0, parse_time / analysis_time)
      round(efficiency * 100)
    else
      0
    end
  end
  
  defp generate_request_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end