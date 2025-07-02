#!/usr/bin/env elixir

# Elixir AST Parser for RSOLV
# Uses Elixir's native AST parsing capabilities

defmodule ElixirParser do
  @moduledoc """
  Parser for Elixir code that outputs AST in a format compatible with
  RSOLV's AST normalization layer.
  """

  def main(_args) do
    # Set up IO to use raw mode for proper JSON communication
    :io.setopts(:standard_io, [:binary, encoding: :utf8])
    
    loop()
  end

  defp loop do
    case IO.gets(:stdio, "") do
      :eof -> :ok
      {:error, _reason} -> :ok
      line ->
        line
        |> String.trim()
        |> process_request()
        
        loop()
    end
  end

  defp process_request("") do
    # Ignore empty lines
    :ok
  end

  defp process_request(line) do
    case JSON.decode(line) do
      {:ok, request} ->
        cond do
          # Health check formats
          Map.get(request, "action") == "health" ->
            send_response(%{
              "status" => "healthy",
              "parser" => "elixir",
              "version" => System.version()
            })
            
          Map.get(request, "command") == "HEALTH_CHECK" ->
            id = Map.get(request, "id")
            response = %{"result" => "ok"}
            response = if id, do: Map.put(response, "id", id), else: response
            send_response(response)
            
          # Parse with action field
          Map.get(request, "action") == "parse" && Map.has_key?(request, "code") ->
            handle_parse_request(request)
            
          # Standard format without action field
          Map.has_key?(request, "code") ->
            handle_parse_request(request)
            
          # Command-based format (from PortWorker)
          Map.has_key?(request, "command") && Map.get(request, "command") != "HEALTH_CHECK" ->
            # Treat command as code to parse
            request_with_code = Map.put(request, "code", Map.get(request, "command"))
            handle_parse_request(request_with_code)
            
          true ->
            send_response(%{
              "success" => false,
              "error" => "Invalid request format"
            })
        end
        
      {:error, _} ->
        send_response(%{
          "success" => false,
          "error" => "Invalid JSON"
        })
    end
  end
  
  defp handle_parse_request(request) do
    id = Map.get(request, "id")
    code = Map.get(request, "code")
    
    result = parse_code(code)
    
    response = case result do
      {:ok, ast} ->
        base = %{
          "success" => true,
          "ast" => normalize_ast(ast)
        }
        if id, do: Map.put(base, "id", id), else: base
        
      {:error, error} ->
        base = %{
          "success" => false,
          "error" => format_error(error)
        }
        if id, do: Map.put(base, "id", id), else: base
    end
    
    send_response(response)
  end

  defp parse_code(code) do
    try do
      case Code.string_to_quoted(code) do
        {:ok, ast} -> {:ok, ast}
        {:error, {line, message, _}} -> 
          {:error, "Syntax error on line #{line}: #{message}"}
      end
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp normalize_ast(ast) do
    # Convert Elixir AST to RSOLV's normalized format
    do_normalize(ast)
  end

  defp do_normalize(atom) when is_atom(atom) do
    %{
      "type" => "atom",
      "value" => to_string(atom)
    }
  end

  defp do_normalize(number) when is_number(number) do
    %{
      "type" => "literal",
      "value" => number
    }
  end

  defp do_normalize(string) when is_binary(string) do
    %{
      "type" => "string",
      "value" => string
    }
  end

  defp do_normalize(list) when is_list(list) do
    %{
      "type" => "list",
      "elements" => Enum.map(list, &do_normalize/1)
    }
  end

  defp do_normalize({:__block__, _meta, children}) do
    %{
      "type" => "block",
      "children" => Enum.map(children, &do_normalize/1)
    }
  end

  defp do_normalize({:def, meta, [{name, _name_meta, args}, body]}) do
    %{
      "type" => "function_definition",
      "name" => to_string(name),
      "line" => Keyword.get(meta, :line, 0),
      "arguments" => normalize_args(args),
      "body" => do_normalize(body)
    }
  end

  defp do_normalize({:defmodule, meta, [{:__aliases__, _, module_parts}, [do: body]]}) do
    %{
      "type" => "module_definition",
      "name" => Enum.join(module_parts, "."),
      "line" => Keyword.get(meta, :line, 0),
      "body" => do_normalize(body)
    }
  end

  defp do_normalize({{:., _, [module, function]}, meta, args}) when is_atom(function) do
    # Module function call like System.cmd
    %{
      "type" => "module_call",
      "module" => normalize_module(module),
      "function" => to_string(function),
      "line" => Keyword.get(meta, :line, 0),
      "arguments" => normalize_args(args)
    }
  end

  defp do_normalize({function, meta, args}) when is_atom(function) and is_list(args) do
    # Regular function call
    %{
      "type" => "function_call",
      "name" => to_string(function),
      "line" => Keyword.get(meta, :line, 0),
      "arguments" => normalize_args(args)
    }
  end

  defp do_normalize({:|>, _meta, [left, right]}) do
    # Pipe operator
    %{
      "type" => "pipe",
      "left" => do_normalize(left),
      "right" => do_normalize(right)
    }
  end

  defp do_normalize({op, _meta, [left, right]}) when op in [:+, :-, :*, :/, :<>] do
    # Binary operators
    %{
      "type" => "binary_operation",
      "operator" => to_string(op),
      "left" => do_normalize(left),
      "right" => do_normalize(right)
    }
  end

  defp do_normalize({var, _meta, context}) when is_atom(var) and is_atom(context) do
    # Variable reference
    %{
      "type" => "variable",
      "name" => to_string(var)
    }
  end

  defp do_normalize(other) do
    # Fallback for unhandled AST nodes
    %{
      "type" => "unknown",
      "raw" => inspect(other)
    }
  end

  defp normalize_args(nil), do: []
  defp normalize_args(args) when is_list(args), do: Enum.map(args, &do_normalize/1)

  defp normalize_module({:__aliases__, _, parts}) do
    Enum.join(parts, ".")
  end
  defp normalize_module(module) when is_atom(module) do
    to_string(module)
  end
  defp normalize_module(other) do
    inspect(other)
  end

  defp format_error(error) when is_binary(error), do: error
  defp format_error(error), do: inspect(error)

  defp send_response(response) do
    json = JSON.encode!(response)
    IO.puts(json)
    # Force flush is automatic with IO.puts
  end
end

# No external dependencies needed - using Elixir's built-in JSON module

# Run the parser
ElixirParser.main(System.argv())