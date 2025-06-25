defmodule RsolvApi.AST.PortPoc do
  @moduledoc """
  Proof of Concept for Port-based parser communication.
  Demonstrates JSON-based communication with external parser processes.
  """

  require Logger

  @doc """
  Test Port communication with a simple echo script
  """
  def test_echo do
    # Create a simple echo script for testing
    echo_script = """
    #!/usr/bin/env python3
    import sys
    import json

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            data = json.loads(line)
            response = {"echo": data, "status": "success"}
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            error = {"status": "error", "message": str(e)}
            print(json.dumps(error))
            sys.stdout.flush()
    """

    # Write script to temp file
    script_path = Path.join(System.tmp_dir!(), "echo_parser.py")
    File.write!(script_path, echo_script)
    File.chmod!(script_path, 0o755)

    # Open port
    port = Port.open({:spawn_executable, script_path}, [
      :binary,
      :exit_status,
      {:line, 65536}
    ])

    # Send test message
    test_msg = %{action: "parse", code: "def hello(): pass"}
    send_json(port, test_msg)

    # Receive response
    receive do
      {^port, {:data, {:eol, response}}} ->
        {:ok, JSON.decode!(response)}
      {^port, {:exit_status, status}} ->
        {:error, "Port exited with status: #{status}"}
    after
      5000 ->
        Port.close(port)
        {:error, "Timeout"}
    end
  end

  @doc """
  Spawn a Python parser process and communicate via JSON
  """
  def test_python_parser do
    parser_script = """
    #!/usr/bin/env python3
    import sys
    import json
    import ast
    import time

    def node_to_dict(node):
        if isinstance(node, ast.AST):
            fields = {}
            for field, value in ast.iter_fields(node):
                fields[field] = node_to_dict(value)
            return {
                '_type': node.__class__.__name__,
                '_lineno': getattr(node, 'lineno', None),
                '_col_offset': getattr(node, 'col_offset', None),
                **fields
            }
        elif isinstance(node, list):
            return [node_to_dict(item) for item in node]
        else:
            return node

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        
        try:
            request = json.loads(line.strip())
            
            if request.get('action') == 'parse':
                start_time = time.time()
                code = request.get('code', '')
                
                # Parse the code
                tree = ast.parse(code)
                ast_dict = node_to_dict(tree)
                
                parse_time_ms = int((time.time() - start_time) * 1000)
                
                response = {
                    'id': request.get('id', 'unknown'),
                    'status': 'success',
                    'ast': ast_dict,
                    'metadata': {
                        'parser_version': '1.0.0',
                        'language_version': sys.version.split()[0],
                        'parse_time_ms': parse_time_ms
                    }
                }
            else:
                response = {
                    'id': request.get('id', 'unknown'),
                    'status': 'error',
                    'error': {
                        'type': 'InvalidAction',
                        'message': f"Unknown action: {request.get('action')}"
                    }
                }
                
        except SyntaxError as e:
            response = {
                'id': request.get('id', 'unknown'),
                'status': 'error',
                'error': {
                    'type': 'SyntaxError',
                    'message': str(e),
                    'line': e.lineno,
                    'offset': e.offset
                }
            }
        except Exception as e:
            response = {
                'id': request.get('id', 'unknown'),
                'status': 'error',
                'error': {
                    'type': type(e).__name__,
                    'message': str(e)
                }
            }
        
        print(json.dumps(response))
        sys.stdout.flush()
    """

    # Write parser script
    parser_path = Path.join(System.tmp_dir!(), "python_parser_poc.py")
    File.write!(parser_path, parser_script)
    File.chmod!(parser_path, 0o755)

    # Test cases
    test_cases = [
      %{"id" => "1", "action" => "parse", "code" => "def hello():\n    return 'world'"},
      %{"id" => "2", "action" => "parse", "code" => "invalid syntax here"},
      %{"id" => "3", "action" => "unknown", "code" => "test"}
    ]

    # Open port
    port = Port.open({:spawn_executable, parser_path}, [
      :binary,
      :exit_status,
      {:line, 65536}
    ])

    # Test each case
    results = Enum.map(test_cases, fn test_case ->
      send_json(port, test_case)
      
      receive do
        {^port, {:data, {:eol, response}}} ->
          JSON.decode!(response)
        {^port, {:exit_status, status}} ->
          %{"error" => "Port exited with status: #{status}"}
      after
        1000 ->
          %{"error" => "Timeout"}
      end
    end)

    Port.close(port)
    results
  end

  @doc """
  Test Ruby parser integration
  """
  def test_ruby_parser do
    parser_script = ~S"""
    #!/usr/bin/env ruby
    require 'json'
    require 'parser/current'

    def ast_to_hash(node)
      return nil if node.nil?
      
      if node.is_a?(Parser::AST::Node)
        {
          type: node.type,
          children: node.children.map { |child| ast_to_hash(child) },
          location: node.location ? {
            line: node.location.line,
            column: node.location.column
          } : nil
        }
      else
        node
      end
    end

    STDOUT.sync = true

    while line = gets
      begin
        request = JSON.parse(line.strip)
        
        if request['action'] == 'parse'
          start_time = Time.now
          code = request['code'] || ''
          
          ast = Parser::CurrentRuby.parse(code)
          ast_hash = ast_to_hash(ast)
          
          parse_time_ms = ((Time.now - start_time) * 1000).to_i
          
          response = {
            'id' => request['id'] || 'unknown',
            'status' => 'success',
            'ast' => ast_hash,
            'metadata' => {
              'parser_version' => '1.0.0',
              'language_version' => RUBY_VERSION,
              'parse_time_ms' => parse_time_ms
            }
          }
        else
          response = {
            'id' => request['id'] || 'unknown',
            'status' => 'error',
            'error' => {
              'type' => 'InvalidAction',
              'message' => "Unknown action: #{request['action']}"
            }
          }
        end
        
      rescue Parser::SyntaxError => e
        response = {
          'id' => request['id'] || 'unknown',
          'status' => 'error',
          'error' => {
            'type' => 'SyntaxError',
            'message' => e.message
          }
        }
      rescue => e
        response = {
          'id' => request['id'] || 'unknown',
          'status' => 'error',
          'error' => {
            'type' => e.class.name,
            'message' => e.message
          }
        }
      end
      
      puts JSON.generate(response)
    end
    """

    # Write parser script
    parser_path = Path.join(System.tmp_dir!(), "ruby_parser_poc.rb")
    File.write!(parser_path, parser_script)
    File.chmod!(parser_path, 0o755)

    # Test with Ruby code
    port = Port.open({:spawn_executable, parser_path}, [
      :binary,
      :exit_status,
      {:line, 65536}
    ])

    test_case = %{
      "id" => "ruby-1",
      "action" => "parse",
      "code" => "class Hello\n  def world\n    'Hello, world!'\n  end\nend"
    }

    send_json(port, test_case)
    
    result = receive do
      {^port, {:data, {:eol, response}}} ->
        JSON.decode!(response)
      {^port, {:exit_status, status}} ->
        %{"error" => "Port exited with status: #{status}"}
    after
      2000 ->
        %{"error" => "Timeout"}
    end

    Port.close(port)
    result
  end

  # Helper to send JSON to port
  defp send_json(port, data) do
    json = JSON.encode!(data)
    Port.command(port, json <> "\n")
  end
end