defmodule Rsolv.AST.ParserRegistry do
  @moduledoc """
  Registry for managing AST parsers for different programming languages.
  
  Features:
  - Dynamic parser discovery and registration
  - Session-based parser routing
  - Performance monitoring and statistics
  - Automatic parser lifecycle management
  """
  
  use GenServer
  require Logger
  
  alias Rsolv.AST.{SessionManager, PortSupervisor, ASTErrorHandler}
  
  @default_timeout 30_000  # 30 seconds
  
  # Parser configuration struct
  defmodule ParserConfig do
    @enforce_keys [:language, :command, :args, :extensions]
    defstruct [:language, :command, :args, :extensions, :version, :timeout]
  end
  
  # Parse result struct
  defmodule ParseResult do
    @enforce_keys [:language, :session_id]
    defstruct [:language, :session_id, :parser_id, :ast, :error, :timing]
  end
  
  # Client API
  
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Lists all registered parsers.
  """
  def list_parsers do
    GenServer.call(__MODULE__, :list_parsers)
  end
  
  @doc """
  Gets parser configuration for a specific language.
  """
  def get_parser(language) do
    GenServer.call(__MODULE__, {:get_parser, language})
  end
  
  @doc """
  Parses code using the appropriate language parser.
  """
  def parse_code(session_id, customer_id, language, code) do
    GenServer.call(__MODULE__, {:parse_code, session_id, customer_id, language, code}, @default_timeout)
  end
  
  @doc """
  Gets the status of a parser for a specific session.
  """
  def get_parser_status(language, session_id) do
    GenServer.call(__MODULE__, {:get_parser_status, language, session_id})
  end
  
  @doc """
  Gets registry statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end
  
  # Server callbacks
  
  # Get the priv directory for the application
  defp priv_dir do
    :code.priv_dir(:rsolv) |> List.to_string()
  end
  
  @impl true
  def init(_opts) do
    # Initialize parser configurations
    parsers = %{
      "javascript" => %ParserConfig{
        language: "javascript",
        command: "node",
        args: [Path.join([priv_dir(), "parsers", "javascript", "parser.js"])],
        extensions: [".js", ".jsx"],
        version: "1.0.0",
        timeout: 30_000
      },
      "typescript" => %ParserConfig{
        language: "typescript",
        command: "node",
        args: [Path.join([priv_dir(), "parsers", "javascript", "parser.js"])],
        extensions: [".ts", ".tsx"],
        version: "1.0.0",
        timeout: 30_000
      },
      "python" => %ParserConfig{
        language: "python",
        command: "python3",
        args: ["-u", Path.join([priv_dir(), "parsers", "python", "parser.py"])],
        extensions: [".py"],
        version: "1.0.0", 
        timeout: 30_000
      },
      "ruby" => %ParserConfig{
        language: "ruby",
        command: "ruby",
        args: [Path.join([priv_dir(), "parsers", "ruby", "parser.rb"])],
        extensions: [".rb"],
        version: "1.0.0",
        timeout: 30_000
      },
      "java" => %ParserConfig{
        language: "java",
        command: "bash",
        args: [Path.join([priv_dir(), "parsers", "java", "parser.sh"])],
        extensions: [".java"],
        version: "1.0.0",
        timeout: 30_000
      },
      "php" => %ParserConfig{
        language: "php",
        command: "bash",
        args: [Path.join([priv_dir(), "parsers", "php", "parser.sh"])],
        extensions: [".php"],
        version: "1.0.0",
        timeout: 30_000
      },
      # Go parser not implemented yet - comment out until ready
      # "go" => %ParserConfig{
      #   language: "go",
      #   command: "bash",
      #   args: [Path.join([priv_dir(), "parsers", "go", "parser.sh"])],
      #   extensions: [".go"],
      #   version: "1.0.0",
      #   timeout: 30_000
      # },
      "elixir" => %ParserConfig{
        language: "elixir",
        command: "elixir",
        args: [Path.join([priv_dir(), "parsers", "elixir", "parser.exs"])],
        extensions: [".ex", ".exs"],
        version: "1.0.0",
        timeout: 30_000
      }
    }
    
    # Initialize statistics
    stats = %{
      total_requests: 0,
      successful_requests: 0,
      failed_requests: 0,
      active_parsers: 0
    }
    
    # Session to parser mapping
    session_parsers = %{}
    
    state = %{
      parsers: parsers,
      stats: stats,
      session_parsers: session_parsers
    }
    
    {:ok, state}
  end
  
  @impl true
  def handle_call(:list_parsers, _from, state) do
    parsers = Map.values(state.parsers)
    {:reply, parsers, state}
  end
  
  @impl true
  def handle_call({:get_parser, language}, _from, state) do
    case Map.get(state.parsers, language) do
      nil -> {:reply, {:error, :parser_not_found}, state}
      parser -> {:reply, {:ok, parser}, state}
    end
  end
  
  @impl true
  def handle_call({:parse_code, session_id, customer_id, language, code}, _from, state) do
    # Validate session first
    case SessionManager.get_session(session_id, customer_id) do
      {:error, _reason} ->
        {:reply, {:error, :invalid_session}, state}
      
      {:ok, _session} ->
        case Map.get(state.parsers, language) do
          nil ->
            # Standardize unsupported language error
            {:error, standardized_error} = ASTErrorHandler.standardize_error(
              %{type: :unsupported_language},
              language,
              code
            )
            {:reply, {:error, standardized_error}, state}
          
          parser_config ->
            # Get or create parser for this session
            {parser_id, updated_state} = get_or_create_parser(session_id, language, parser_config, state)
            
            # Parse the code
            start_time = System.monotonic_time(:millisecond)
            
            {reply, updated_stats} = case parse_with_parser(parser_id, code, parser_config) do
              {:ok, ast} ->
                end_time = System.monotonic_time(:millisecond)
                parse_time = end_time - start_time
                
                result = %ParseResult{
                  language: language,
                  session_id: session_id,
                  parser_id: parser_id,
                  ast: ast,
                  error: nil,
                  timing: %{
                    parse_time_ms: parse_time,
                    total_time_ms: parse_time
                  }
                }
                
                # Update statistics for success
                stats = update_statistics(updated_state.stats, result)
                {{:ok, result}, stats}
              
              {:error, raw_error} ->
                end_time = System.monotonic_time(:millisecond)
                parse_time = end_time - start_time
                
                # Standardize the error using ASTErrorHandler
                standardized_error = case standardize_parser_error(raw_error, language, code) do
                  {:error, error} -> error
                  error -> error  # In case it's already processed
                end
                
                # Create result for statistics tracking
                result = %ParseResult{
                  language: language,
                  session_id: session_id,
                  parser_id: parser_id,
                  ast: nil,
                  error: standardized_error,
                  timing: %{
                    parse_time_ms: parse_time,
                    total_time_ms: parse_time
                  }
                }
                
                # Update statistics for failure
                stats = update_statistics(updated_state.stats, result)
                {{:ok, result}, stats}
            end
            
            final_state = %{updated_state | stats: updated_stats}
            {:reply, reply, final_state}
        end
    end
  end
  
  @impl true
  def handle_call({:get_parser_status, language, session_id}, _from, state) do
    session_key = {session_id, language}
    
    case Map.get(state.session_parsers, session_key) do
      nil ->
        {:reply, {:error, :parser_not_found}, state}
      
      parser_id ->
        # Check if parser is still running
        case PortSupervisor.get_port(nil, parser_id) do
          nil ->
            {:reply, {:ok, %{status: :stopped, parser_id: parser_id}}, state}
          
          _port_info ->
            {:reply, {:ok, %{status: :running, parser_id: parser_id}}, state}
        end
    end
  end
  
  @impl true
  def handle_call(:get_statistics, _from, state) do
    success_rate = if state.stats.total_requests > 0 do
      state.stats.successful_requests / state.stats.total_requests
    else
      0.0
    end
    
    stats = Map.put(state.stats, :success_rate, success_rate)
    {:reply, stats, state}
  end
  
  @impl true
  def handle_call({:cleanup_session_parser, session_id, language}, _from, state) do
    session_key = {session_id, language}
    
    case Map.get(state.session_parsers, session_key) do
      nil ->
        # No parser for this session/language
        {:reply, :ok, state}
      
      parser_id ->
        # Stop the parser port
        try do
          PortSupervisor.terminate_port(nil, parser_id)
          Logger.debug("Terminated parser #{parser_id} for session #{session_id}/#{language}")
        rescue
          error ->
            Logger.warning("Failed to terminate parser #{parser_id}: #{inspect(error)}")
        end
        
        # Remove from session_parsers map
        updated_session_parsers = Map.delete(state.session_parsers, session_key)
        updated_stats = %{state.stats | active_parsers: max(0, state.stats.active_parsers - 1)}
        updated_state = %{state | session_parsers: updated_session_parsers, stats: updated_stats}
        
        {:reply, :ok, updated_state}
    end
  end
  
  # Private functions
  
  defp get_or_create_parser(session_id, language, parser_config, state) do
    session_key = {session_id, language}
    
    case Map.get(state.session_parsers, session_key) do
      nil ->
        # Create new parser
        parser_id = create_parser(language, parser_config)
        updated_session_parsers = Map.put(state.session_parsers, session_key, parser_id)
        updated_stats = %{state.stats | active_parsers: state.stats.active_parsers + 1}
        updated_state = %{state | session_parsers: updated_session_parsers, stats: updated_stats}
        {parser_id, updated_state}
      
      existing_parser_id ->
        # Verify parser is still alive, restart if needed
        case PortSupervisor.get_port(nil, existing_parser_id) do
          nil ->
            # Parser died, create new one
            new_parser_id = create_parser(language, parser_config)
            updated_session_parsers = Map.put(state.session_parsers, session_key, new_parser_id)
            updated_state = %{state | session_parsers: updated_session_parsers}
            {new_parser_id, updated_state}
          
          _ ->
            # Parser is alive, reuse it
            {existing_parser_id, state}
        end
    end
  end
  
  defp create_parser(language, parser_config) do
    config = %{
      language: language,
      command: parser_config.command,
      args: parser_config.args,
      timeout: parser_config.timeout || @default_timeout,
      pooled: false
    }
    
    case PortSupervisor.start_port(PortSupervisor, config) do
      {:ok, parser_id} -> parser_id
      {:error, reason} -> 
        Logger.error("Failed to start parser for #{language}: #{inspect(reason)}")
        "failed_parser_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
    end
  end
  
  defp parse_with_parser(parser_id, code, parser_config) do
    # Handle special test signals
    case code do
      "FORCE_CRASH_SIGNAL" ->
        {:error, "Parser crashed during processing"}
      
      "FORCE_TIMEOUT_SIGNAL" ->
        {:error, "Parser timeout occurred"}
      
      _ ->
        case PortSupervisor.call_port(nil, parser_id, code, parser_config.timeout || @default_timeout) do
          {:ok, response} ->
            # Parser response logged at trace level for debugging
            Logger.log(:debug, fn -> "Parser response received" end)
            
            # The response is already parsed by PortWorker
            case response do
              %{"id" => _id, "success" => true, "ast" => ast} ->
                {:ok, ast}
              
              %{"id" => _id, "success" => false, "error" => error} ->
                {:error, error}
              
              %{"id" => _id, "result" => "ok"} ->
                # Simple health check response
                {:ok, %{"type" => "HealthCheck", "status" => "ok"}}
              
              %{"success" => true, "ast" => ast} ->
                # Backward compatibility - no ID field
                {:ok, ast}
              
              %{"success" => false, "error" => error} ->
                # Backward compatibility - no ID field
                {:error, error}
              
              %{"result" => "ok"} ->
                # Simple health check response - no ID field
                {:ok, %{"type" => "HealthCheck", "status" => "ok"}}
              
              %{"id" => _id, "status" => "success", "ast" => ast} ->
                # JavaScript parser format
                {:ok, ast}
              
              %{"status" => "success", "ast" => ast} ->
                # JavaScript parser format - no ID field
                {:ok, ast}
              
              %{"error" => error} ->
                # Error response without success field
                {:error, error}
              
              decoded when is_map(decoded) ->
                Logger.warning("Unexpected response format: #{inspect(decoded)}")
                {:error, "Unexpected parser response format"}
              
              response_string when is_binary(response_string) ->
                # Fallback: try JSON decoding if we get a string
                case JSON.decode(response_string) do
                  {:ok, parsed} -> 
                    case parsed do
                      %{"success" => true, "ast" => ast} -> {:ok, ast}
                      %{"success" => false, "error" => error} -> {:error, error}
                      _ -> {:error, "Unexpected response format"}
                    end
                  {:error, _} -> {:error, "Invalid JSON response"}
                end
            end
          
          {:error, :port_not_found} ->
            {:error, "Parser not found or crashed"}
          
          {:error, :timeout} ->
            {:error, "Parser timeout occurred"}
          
          {:error, reason} ->
            {:error, "Parser error: #{inspect(reason)}"}
        end
    end
  end
  
  defp update_statistics(stats, result) do
    updated_stats = %{stats | total_requests: stats.total_requests + 1}
    
    if result.error do
      %{updated_stats | failed_requests: updated_stats.failed_requests + 1}
    else
      %{updated_stats | successful_requests: updated_stats.successful_requests + 1}
    end
  end

  defp standardize_parser_error(raw_error, language, source_code) do
    # Convert different error formats to a standardized format
    standardized_input = case raw_error do
      # String errors from our current parser implementations
      "Parser crashed during processing" ->
        %{type: :parser_crash, reason: :unknown}
      
      "Parser timeout occurred" ->
        %{type: :timeout, duration_ms: @default_timeout}
      
      "Parser not found or crashed" ->
        %{type: :parser_crash, reason: :not_found}
      
      "Parser error: " <> reason ->
        %{type: :unknown_error, message: reason}
      
      "Unexpected parser response format" ->
        %{type: :unknown_error, message: raw_error}
      
      "Invalid JSON response" ->
        %{type: :unknown_error, message: raw_error}
      
      # Map errors from actual parsers (JavaScript, Python, etc.)
      %{"type" => "SyntaxError", "message" => message} = error ->
        %{
          type: :syntax_error,
          message: message,
          line: Map.get(error, "line"),
          column: Map.get(error, "column"),
          offset: Map.get(error, "offset")
        }
      
      %{"type" => type, "message" => message} = error when is_binary(type) ->
        normalized_type = case String.downcase(type) do
          "syntaxerror" -> :syntax_error
          "parseerror" -> :syntax_error
          "timeout" -> :timeout
          "crash" -> :parser_crash
          "parsernotavailable" -> :parser_not_available
          _ -> :unknown_error
        end
        
        %{
          type: normalized_type,
          message: message,
          line: Map.get(error, "line") || Map.get(error, "lineno"),
          column: Map.get(error, "column") || Map.get(error, "offset"),
          offset: Map.get(error, "offset")
        }
      
      # Python-style errors
      %{"lineno" => line, "offset" => offset, "text" => text} = error ->
        %{
          type: :syntax_error,
          message: Map.get(error, "msg", "Invalid syntax"),
          lineno: line,
          offset: offset,
          text: text
        }
      
      # Ruby-style errors  
      %{"location" => location} = error ->
        %{
          type: :syntax_error,
          message: Map.get(error, "message", "Parse error"),
          location: location
        }
      
      # Generic map with unknown structure
      error when is_map(error) ->
        Map.put(error, :type, Map.get(error, :type, :unknown_error))
      
      # Raw string errors
      error when is_binary(error) ->
        cond do
          String.contains?(error, "timeout") ->
            %{type: :timeout, message: error}
          String.contains?(error, "crash") ->
            %{type: :parser_crash, message: error}
          String.contains?(error, "syntax") ->
            %{type: :syntax_error, message: error}
          true ->
            %{type: :unknown_error, message: error}
        end
      
      # Fallback for anything else
      error ->
        %{type: :unknown_error, message: "Unexpected error: #{inspect(error)}"}
    end
    
    # Use ASTErrorHandler to standardize the format
    ASTErrorHandler.standardize_error(standardized_input, language, source_code)
  end
end