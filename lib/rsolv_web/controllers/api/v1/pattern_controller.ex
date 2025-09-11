defmodule RsolvWeb.Api.V1.PatternController do
  use RsolvWeb, :controller
  require Logger

  alias Rsolv.Security.ASTPattern
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.DemoPatterns
  alias Rsolv.Security.Patterns.JSONSerializer
  alias Rsolv.Accounts

  @doc """
  Get security patterns for a language.

  Query params:
  - language: javascript, python, ruby, etc.
  - format: standard (default) or enhanced (with AST rules)

  Access model:
  - With valid API key: Access to all 170+ patterns
  - Without API key: Access to 5 demo patterns per language
  - With invalid API key: Returns 401 Unauthorized

  ## Examples

      # No API key - returns demo patterns (200 OK)
      iex> conn = build_conn() |> get("/api/v1/patterns?language=javascript")
      iex> conn.status
      200
      iex> json_response(conn, 200)["metadata"]["access_level"]
      "demo"

      # Valid API key - returns all patterns (200 OK)
      iex> conn = build_conn()
      ...> |> put_req_header("authorization", "Bearer valid_key_123")
      ...> |> get("/api/v1/patterns?language=javascript")
      iex> conn.status
      200
      iex> json_response(conn, 200)["metadata"]["access_level"]
      "full"

      # Invalid API key - returns 401 Unauthorized
      iex> conn = build_conn()
      ...> |> put_req_header("authorization", "Bearer invalid_key_456")
      ...> |> get("/api/v1/patterns?language=javascript")
      iex> conn.status
      401
      iex> json_response(conn, 401)
      %{"error" => "Unauthorized", "message" => "Invalid API key"}

  """
  def index(conn, params) do
    try do
      Logger.info("Pattern API called with params: #{inspect(params)}")

      language = params["language"] || "javascript"

      format =
        case params["format"] do
          "enhanced" -> :enhanced
          _ -> :standard
        end

      include_metadata = params["include_metadata"] == "true"

      Logger.info("Language: #{language}, Format: #{format}")

      # Check API key status
      api_key_status = check_api_key_status(conn)
      Logger.info("API key status: #{inspect(api_key_status)}")

      # Handle invalid API key immediately
      if api_key_status == :invalid do
        Logger.warning("Invalid API key provided")

        conn
        |> put_status(:unauthorized)
        |> json(%{
          error: "Unauthorized",
          message: "Invalid API key"
        })
        |> halt()
      else
        # Get patterns based on authentication status
        {patterns, is_demo} =
          case api_key_status do
            :valid ->
              # Return all patterns for the language
              Logger.info("Getting enhanced patterns for #{language}")
              {ASTPattern.get_all_patterns_for_language(language, format), false}

            :none ->
              # No API key provided - return demo patterns
              Logger.info("Getting demo patterns for #{language}")
              {DemoPatterns.get_demo_patterns(language), true}
          end

        Logger.info("Retrieved #{length(patterns)} patterns")

        # Convert patterns to API format (removing tier information)
        formatted_patterns =
          Enum.map(patterns, fn pattern ->
            Logger.debug("Formatting pattern: #{inspect(pattern.id)}")
            # Demo patterns should never have enhanced format
            effective_format = if is_demo, do: :standard, else: format
            formatted = format_pattern_without_tier(pattern, effective_format)
            Logger.debug("Formatted pattern keys: #{inspect(Map.keys(formatted))}")

            # Add vulnerability metadata if requested
            if include_metadata do
              add_vulnerability_metadata(formatted, pattern)
            else
              formatted
            end
          end)

        # Build metadata without tier information
        metadata = %{
          language: language,
          format: to_string(format),
          count: length(formatted_patterns),
          enhanced: format == :enhanced,
          access_level: if(api_key_status == :valid, do: "full", else: "demo")
        }

        # Prepare the response data for JSON encoding
        response_data = %{
          patterns: formatted_patterns,
          metadata: metadata
        }

        # Use JSONSerializer for enhanced format to handle regex objects
        json_data =
          if format == :enhanced do
            JSONSerializer.encode!(response_data)
          else
            # Standard format doesn't have regex, so native JSON is fine
            JSON.encode!(response_data)
          end

        conn
        |> put_resp_header("x-pattern-version", "2.0")
        |> put_resp_header("content-type", "application/json")
        |> send_resp(200, json_data)
      end
    rescue
      e ->
        # Log the error for debugging
        Logger.error("Pattern API error: #{inspect(e)}")
        Logger.error(Exception.format_stacktrace())

        # Return proper 500 error response
        error_data =
          JSON.encode!(%{
            error: "Internal server error",
            message: "An error occurred while processing patterns"
          })

        conn
        |> put_status(:internal_server_error)
        |> put_resp_header("content-type", "application/json")
        |> send_resp(500, error_data)
    end
  end

  @doc """
  Get pattern statistics across all languages.
  """
  def stats(conn, _params) do
    try do
      # Get stats from PatternServer
      stats = Rsolv.Security.PatternServer.get_stats()

      response_data = %{
        total_patterns: stats.total,
        by_language: stats.by_language,
        loaded_at: stats.loaded_at,
        access_model: %{
          demo: "5 patterns per language",
          full: "All #{stats.total} patterns with API key"
        }
      }

      json_data = JSON.encode!(response_data)

      conn
      |> put_resp_header("content-type", "application/json")
      |> send_resp(200, json_data)
    rescue
      e ->
        Logger.error("Pattern stats error: #{inspect(e)}")

        error_data =
          JSON.encode!(%{
            error: "Internal server error",
            message: "An error occurred while retrieving pattern statistics"
          })

        conn
        |> put_status(:internal_server_error)
        |> put_resp_header("content-type", "application/json")
        |> send_resp(500, error_data)
    end
  end

  @doc """
  Get security patterns for a specific language.
  """
  def by_language(conn, %{"language" => language} = params) do
    # Add language to params and delegate to index
    enhanced_params = Map.put(params, "language", language)
    index(conn, enhanced_params)
  end

  @doc """
  V2 API endpoint - returns enhanced format by default.
  """
  def index_v2(conn, params) do
    # Force enhanced format for v2 API
    enhanced_params = Map.put(params, "format", "enhanced")
    index(conn, enhanced_params)
  end

  # Check the status of the API key provided in the request.
  # Returns :valid, :invalid, or :none
  defp check_api_key_status(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        # API key was provided - check if it's valid
        case Accounts.get_customer_by_api_key(api_key) do
          # API key provided but doesn't exist
          nil -> :invalid
          # API key exists and is valid
          _customer -> :valid
        end

      _ ->
        # No API key provided at all
        :none
    end
  end

  # Handle ASTPattern structs (returned by enhanced format)
  defp format_pattern_without_tier(%Rsolv.Security.ASTPattern{} = ast_pattern, :enhanced) do
    # Convert ASTPattern to API format with camelCase for enhanced fields
    %{
      "id" => ast_pattern.id,
      "name" => ast_pattern.name,
      "type" => ast_pattern.type,
      "severity" => ast_pattern.severity,
      "description" => ast_pattern.description,
      "regex" => ast_pattern.regex,
      "regexPatterns" => if(ast_pattern.regex, do: [ast_pattern.regex], else: []),
      "languages" => ast_pattern.languages,
      "frameworks" => ast_pattern.frameworks,
      "cweId" => ast_pattern.cwe_id,
      "owaspCategory" => ast_pattern.owasp_category,
      "recommendation" => ast_pattern.recommendation,
      "examples" => Map.get(ast_pattern, :examples, %{safe: [], vulnerable: []}),
      "supportsAst" => true,
      # Include enhanced fields in camelCase
      "astRules" => ast_pattern.ast_rules,
      "contextRules" => ast_pattern.context_rules,
      "confidenceRules" => ast_pattern.confidence_rules,
      "minConfidence" => ast_pattern.min_confidence
    }
  end

  # Handle regular Pattern structs
  defp format_pattern_without_tier(%Pattern{} = pattern, format) do
    base_format = Pattern.to_api_format(pattern)

    # Convert to camelCase string keys
    formatted = %{
      "id" => base_format.id,
      "name" => base_format.name,
      "type" => base_format.type,
      "severity" => base_format.severity,
      "description" => base_format.description,
      "regex" => base_format.regex_patterns,
      "regexPatterns" => base_format.regex_patterns || [],
      "languages" => base_format.languages,
      "frameworks" => Map.get(base_format, :frameworks, []),
      "cweId" => base_format.cwe_id,
      "owaspCategory" => base_format.owasp_category,
      "recommendation" => base_format.recommendation,
      "examples" => base_format.examples || [],
      "supportsAst" => Map.get(base_format, :supports_ast, false)
    }

    # Add enhanced fields if requested
    if format == :enhanced do
      # Get the pattern module from pattern ID
      pattern_module = pattern_id_to_module(pattern.id)

      # Check if module has ast_enhancement/0
      if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
        try do
          # Get enhancement data from the pattern module
          enhancement = apply(pattern_module, :ast_enhancement, [])

          # Add enhancement fields directly to the pattern
          # Normalize different structures - PHP patterns only have ast_rules and min_confidence
          formatted
          |> Map.put("astRules", enhancement[:ast_rules] || enhancement[:rules] || [])
          |> Map.put("contextRules", Map.get(enhancement, :context_rules, %{}))
          |> Map.put("confidenceRules", Map.get(enhancement, :confidence_rules, %{}))
          |> Map.put("minConfidence", enhancement[:min_confidence] || 0.7)
        rescue
          _ -> formatted
        end
      else
        # No module found - use ASTPattern.enhance for demo patterns
        try do
          Logger.debug("No module found for pattern #{pattern.id}, using ASTPattern.enhance")

          ast_pattern = Rsolv.Security.ASTPattern.enhance(pattern)

          formatted
          |> Map.put("astRules", ast_pattern.ast_rules)
          |> Map.put("contextRules", ast_pattern.context_rules || %{})
          |> Map.put("confidenceRules", ast_pattern.confidence_rules)
          |> Map.put("minConfidence", ast_pattern.min_confidence)
        rescue
          e ->
            Logger.debug("Failed to enhance pattern #{pattern.id}: #{inspect(e)}")
            formatted
        end
      end
    else
      formatted
    end
  end

  defp pattern_id_to_module(pattern_id) do
    # Convert pattern ID to module name
    # e.g., "js-xss-dom-manipulation" -> Rsolv.Security.Patterns.Javascript.XssDomManipulation
    parts = String.split(pattern_id, "-")

    if length(parts) >= 2 do
      [lang | rest] = parts

      language =
        case lang do
          "js" -> "Javascript"
          "ts" -> "Typescript"
          "py" -> "Python"
          "rb" -> "Ruby"
          "php" -> "Php"
          "go" -> "Go"
          "java" -> "Java"
          _ -> String.capitalize(lang)
        end

      pattern_name =
        rest
        |> Enum.map(&String.capitalize/1)
        |> Enum.join("")

      module_name =
        Module.concat([
          Rsolv.Security.Patterns,
          language,
          pattern_name
        ])

      if Code.ensure_loaded?(module_name) do
        module_name
      else
        nil
      end
    else
      nil
    end
  end

  defp add_vulnerability_metadata(formatted_pattern, _original_pattern) do
    # Try to get metadata from the pattern module first
    pattern_module = pattern_id_to_module(formatted_pattern[:id] || formatted_pattern["id"])

    metadata =
      if pattern_module && function_exported?(pattern_module, :vulnerability_metadata, 0) do
        try do
          apply(pattern_module, :vulnerability_metadata, [])
        rescue
          _ -> %{}
        end
      else
        %{}
      end

    # Add the metadata to the pattern
    vulnerability_metadata =
      Map.merge(metadata, %{
        pattern_id: formatted_pattern[:id] || formatted_pattern["id"]
      })

    Map.put(formatted_pattern, "vulnerability_metadata", vulnerability_metadata)
  end
  
  def metadata(conn, %{"id" => pattern_id}) do
    # Check if pattern exists and has metadata
    case get_pattern_metadata(pattern_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pattern not found"})
      
      metadata ->
        json(conn, metadata)
    end
  end
  
  defp get_pattern_metadata("js-sql-injection-concat") do
    %{
      pattern_id: "js-sql-injection-concat",
      description: "SQL injection vulnerability through string concatenation",
      references: [
        %{
          type: "cwe",
          id: "CWE-89",
          url: "https://cwe.mitre.org/data/definitions/89.html"
        }
      ],
      attack_vectors: [
        "Direct concatenation of user input into SQL queries",
        "String interpolation without proper escaping"
      ],
      cve_examples: []
    }
  end
  
  defp get_pattern_metadata("js-sql-injection-interpolation") do
    %{
      pattern_id: "js-sql-injection-interpolation",
      description: "SQL injection through template literal interpolation",
      references: [
        %{
          type: "cwe",
          id: "CWE-89",
          url: "https://cwe.mitre.org/data/definitions/89.html"
        },
        %{
          type: "owasp",
          id: "A03:2021",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: "article",
          id: "sql-injection-prevention",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: "nist",
          id: "SI-10",
          url: "https://nvd.nist.gov/800-53/Rev4/control/SI-10"
        },
        %{
          type: "sans",
          id: "CWE-89",
          url: "https://www.sans.org/top25-software-errors/"
        },
        %{
          type: "stackoverflow",
          id: "sql-injection-es6",
          url: "https://stackoverflow.com/questions/tagged/sql-injection+javascript"
        }
      ],
      attack_vectors: [
        "Template literal interpolation ${} without parameterization"
      ],
      cve_examples: [],
      additional_context: %{
        "common_mistakes" => [
          "Using template literals to build SQL queries",
          "Not using parameterized queries"
        ]
      }
    }
  end
  
  defp get_pattern_metadata("js-xss-document-write") do
    %{
      pattern_id: "js-xss-document-write",
      description: "DOM XSS sink vulnerability through document.write with user input",
      references: [
        %{
          type: "cwe",
          id: "CWE-79",
          url: "https://cwe.mitre.org/data/definitions/79.html"
        },
        %{
          type: "owasp",
          id: "A03:2021",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: "article",
          id: "dom-xss-prevention",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
        },
        %{
          type: "mdn",
          id: "document-write",
          url: "https://developer.mozilla.org/en-US/docs/Web/API/Document/write"
        },
        %{
          type: "sans",
          id: "CWE-79",
          url: "https://www.sans.org/top25-software-errors/"
        },
        %{
          type: "google",
          id: "web-security",
          url: "https://developers.google.com/web/fundamentals/security/csp"
        }
      ],
      attack_vectors: [
        "Direct document.write with unsanitized user input containing script tags",
        "Injection of onerror handlers and other event attributes"
      ],
      cve_examples: [],
      additional_context: %{
        "parser_blocking" => [
          "document.write can block HTML parser",
          "Synchronous execution can cause performance issues"
        ]
      }
    }
  end
  
  defp get_pattern_metadata("js-xss-innerhtml") do
    %{
      pattern_id: "js-xss-innerhtml",
      description: "XSS vulnerability through innerHTML with user input",
      references: [
        %{
          type: "cwe",
          id: "CWE-79",
          url: "https://cwe.mitre.org/data/definitions/79.html"
        }
      ],
      attack_vectors: [
        "Direct innerHTML assignment with unsanitized user input"
      ],
      cve_examples: []
    }
  end
  
  defp get_pattern_metadata("js-command-injection-exec") do
    %{
      pattern_id: "js-command-injection-exec",
      description: "Command injection vulnerability through exec/spawn",
      references: [
        %{
          type: "cwe",
          id: "CWE-78",
          url: "https://cwe.mitre.org/data/definitions/78.html"
        }
      ],
      attack_vectors: [
        "Unsanitized user input passed to exec/spawn functions"
      ],
      cve_examples: [],
      safe_alternatives: [
        "Use execFile with argument arrays instead of exec",
        "Validate and sanitize user input"
      ]
    }
  end
  
  defp get_pattern_metadata("js-xss-dom"), do: nil
  defp get_pattern_metadata(_), do: nil
end
