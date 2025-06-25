defmodule RsolvApi.AST.PortSupervisor do
  @moduledoc """
  Supervises parser Port processes with automatic restart and resource limits.
  Manages a pool of parser processes for each supported language.
  """

  use GenServer
  require Logger

  @supported_languages ~w(python ruby php java javascript elixir)
  @parser_timeout 30_000  # 30 seconds max per parse
  @max_file_size 10 * 1024 * 1024  # 10MB

  defmodule ParserPort do
    @moduledoc false
    defstruct [:port, :language, :busy, :created_at, :request_count]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Parse code using the appropriate language parser.
  Returns {:ok, ast} or {:error, reason}
  """
  def parse(language, code, options \\ %{}) when language in @supported_languages do
    if byte_size(code) > @max_file_size do
      {:error, "File too large (max 10MB)"}
    else
      GenServer.call(__MODULE__, {:parse, language, code, options}, @parser_timeout + 1000)
    end
  end

  @doc """
  Get status of all parser ports
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Trap exits to handle port crashes
    Process.flag(:trap_exit, true)
    
    state = %{
      ports: %{},  # language => [%ParserPort{}]
      stats: %{},  # language => %{total_requests: 0, errors: 0}
    }
    
    {:ok, state}
  end

  @impl true
  def handle_call({:parse, language, code, options}, _from, state) do
    case get_available_port(language, state) do
      {nil, state} ->
        # No available port, create one
        case create_parser_port(language) do
          {:ok, port_info} ->
            # Mark as busy and send request
            port_info = %{port_info | busy: true}
            updated_state = add_port(state, language, port_info)
            
            case do_parse(port_info.port, code, options) do
              {:ok, result} ->
                # Mark as available again
                final_state = mark_port_available(updated_state, language, port_info.port)
                {:reply, {:ok, result}, final_state}
              
              {:error, reason} = error ->
                # Remove failed port
                final_state = remove_port(updated_state, language, port_info.port)
                {:reply, error, final_state}
            end
          
          {:error, reason} = error ->
            {:reply, error, state}
        end
      
      {port_info, state} ->
        # Use existing available port
        port_info = %{port_info | busy: true, request_count: port_info.request_count + 1}
        updated_state = update_port(state, language, port_info)
        
        case do_parse(port_info.port, code, options) do
          {:ok, result} ->
            # Check if port should be recycled (after N requests)
            final_state = if port_info.request_count >= 100 do
              Logger.info("Recycling #{language} parser after 100 requests")
              remove_port(updated_state, language, port_info.port)
            else
              mark_port_available(updated_state, language, port_info.port)
            end
            
            {:reply, {:ok, result}, final_state}
          
          {:error, reason} = error ->
            # Remove failed port
            final_state = remove_port(updated_state, language, port_info.port)
            {:reply, error, final_state}
        end
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = Enum.map(state.ports, fn {language, ports} ->
      {language, %{
        active_ports: length(ports),
        busy_ports: Enum.count(ports, & &1.busy),
        total_requests: Enum.sum(Enum.map(ports, & &1.request_count))
      }}
    end)
    
    {:reply, status, state}
  end

  @impl true
  def handle_info({:EXIT, port, reason}, state) do
    # Port crashed, remove it from all languages
    Logger.warn("Parser port exited: #{inspect(reason)}")
    
    updated_state = Enum.reduce(state.ports, state, fn {language, ports}, acc ->
      if Enum.any?(ports, &(&1.port == port)) do
        remove_port(acc, language, port)
      else
        acc
      end
    end)
    
    {:noreply, updated_state}
  end

  @impl true
  def handle_info({port, {:data, _data}}, state) when is_port(port) do
    # Ignore unexpected data from ports
    {:noreply, state}
  end

  # Private functions

  defp get_available_port(language, state) do
    ports = Map.get(state.ports, language, [])
    available = Enum.find(ports, &(not &1.busy))
    
    if available do
      {available, state}
    else
      {nil, state}
    end
  end

  defp create_parser_port(language) do
    parser_path = get_parser_path(language)
    
    if File.exists?(parser_path) do
      try do
        port = Port.open({:spawn_executable, parser_path}, [
          :binary,
          :exit_status,
          {:line, 65536},
          {:env, [{~c"PARSER_LANGUAGE", String.to_charlist(language)}]}
        ])
        
        port_info = %ParserPort{
          port: port,
          language: language,
          busy: false,
          created_at: DateTime.utc_now(),
          request_count: 0
        }
        
        {:ok, port_info}
      catch
        :error, reason ->
          {:error, "Failed to spawn parser: #{inspect(reason)}"}
      end
    else
      {:error, "Parser not found: #{parser_path}"}
    end
  end

  defp do_parse(port, code, options) do
    request_id = generate_request_id()
    
    request = %{
      "action" => "parse",
      "id" => request_id,
      "code" => code,
      "options" => options
    }
    
    # Send request
    json = JSON.encode!(request)
    Port.command(port, json <> "\n")
    
    # Wait for response with timeout
    receive do
      {^port, {:data, {:eol, response_data}}} ->
        case JSON.decode(response_data) do
          {:ok, %{"status" => "success", "ast" => ast}} ->
            {:ok, ast}
          
          {:ok, %{"status" => "error", "error" => error}} ->
            {:error, format_error(error)}
          
          {:error, _} ->
            {:error, "Invalid JSON response from parser"}
        end
      
      {^port, {:exit_status, status}} ->
        {:error, "Parser exited with status: #{status}"}
    after
      @parser_timeout ->
        # Kill the port if it's taking too long
        Port.close(port)
        {:error, "Parser timeout"}
    end
  end

  defp get_parser_path(language) do
    base_dir = Path.join([Application.app_dir(:rsolv_api), "priv", "parsers"])
    
    case language do
      "python" -> Path.join([base_dir, "python", "parser.py"])
      "ruby" -> Path.join([base_dir, "ruby", "parser.rb"])
      "php" -> Path.join([base_dir, "php", "parser.php"])
      "java" -> Path.join([base_dir, "java", "parser.sh"])  # Shell wrapper for Java
      "javascript" -> Path.join([base_dir, "javascript", "parser.js"])
      "elixir" -> Path.join([base_dir, "elixir", "parser.exs"])
    end
  end

  defp add_port(state, language, port_info) do
    ports = Map.get(state.ports, language, [])
    %{state | ports: Map.put(state.ports, language, [port_info | ports])}
  end

  defp update_port(state, language, updated_port_info) do
    ports = Map.get(state.ports, language, [])
    updated_ports = Enum.map(ports, fn port_info ->
      if port_info.port == updated_port_info.port do
        updated_port_info
      else
        port_info
      end
    end)
    
    %{state | ports: Map.put(state.ports, language, updated_ports)}
  end

  defp mark_port_available(state, language, port) do
    ports = Map.get(state.ports, language, [])
    updated_ports = Enum.map(ports, fn port_info ->
      if port_info.port == port do
        %{port_info | busy: false}
      else
        port_info
      end
    end)
    
    %{state | ports: Map.put(state.ports, language, updated_ports)}
  end

  defp remove_port(state, language, port) do
    # Close the port
    if Process.alive?(port) do
      Port.close(port)
    end
    
    ports = Map.get(state.ports, language, [])
    updated_ports = Enum.reject(ports, &(&1.port == port))
    
    %{state | ports: Map.put(state.ports, language, updated_ports)}
  end

  defp generate_request_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp format_error(%{"type" => type, "message" => message} = error) do
    location = case error do
      %{"line" => line, "column" => col} -> " at line #{line}, column #{col}"
      %{"line" => line} -> " at line #{line}"
      _ -> ""
    end
    
    "#{type}: #{message}#{location}"
  end
  
  defp format_error(error), do: inspect(error)
end