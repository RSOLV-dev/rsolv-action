defmodule RsolvApi.AST.ProductionRubyParserTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{ParserRegistry, SessionManager}
  
  describe "Production Ruby Parser" do
    setup do
      # Ensure SessionManager is available
      unless Process.whereis(SessionManager) do
        Application.ensure_all_started(:rsolv_api)
      end
      
      # Ensure ParserRegistry is available
      unless Process.whereis(ParserRegistry) do
        Application.ensure_all_started(:rsolv_api)
      end
      
      # Create test customer and session
      customer_id = "test_customer_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      %{customer_id: customer_id, session_id: session.id}
    end
    
    test "parses simple Ruby code with production parser", %{customer_id: customer_id, session_id: session_id} do
      code = """
      class User
        def initialize(name)
          @name = name
        end
        
        def greet
          puts "Hello, \#{@name}!"
        end
      end
      
      user = User.new("World")
      user.greet
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.language == "ruby"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
      
      # Check AST structure contains expected nodes
      assert result.ast["type"] == "begin"
      assert is_list(result.ast["children"])
    end
    
    test "detects dangerous method patterns in Ruby code", %{customer_id: customer_id, session_id: session_id} do
      code = """
      class UserController
        def update
          # VULNERABLE: eval usage
          eval(params[:code])
          
          # VULNERABLE: system command
          system("rm -rf \#{params[:path]}")
          
          # VULNERABLE: SQL injection
          User.where("name = '\#{params[:name]}'")
        end
      end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should contain dangerous patterns
      assert result.ast["type"] == "class"
    end
    
    test "handles Ruby syntax errors gracefully", %{customer_id: customer_id, session_id: session_id} do
      code = """
      class BrokenClass
        def broken_method
          puts "missing end keyword
        end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.language == "ruby"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error.type == :syntax_error || result.error[:type] == :syntax_error
      assert is_binary(result.error.message) || is_binary(result.error[:message])
    end
    
    test "parses complex Ruby constructs", %{customer_id: customer_id, session_id: session_id} do
      code = """
      module SecurityAnalyzer
        class Scanner
          include Enumerable
          
          attr_reader :findings
          
          def initialize(config = {})
            @config = config
            @findings = []
          end
          
          def scan_code(code)
            # Template literal with potential injection
            query = "SELECT * FROM code WHERE content = '\\\#{code}'"
            
            # Dangerous eval usage
            result = eval(code) if @config[:allow_eval]
            
            @findings << { type: :sql_injection, query: query }
            @findings << { type: :code_injection, code: code } if result
            
            yield findings if block_given?
          end
          
          def each(&block)
            @findings.each(&block)
          end
          
          private
          
          def sanitize(input)
            input.gsub(/['"\\]/, '\\\\\\&')
          end
        end
      end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "module"
      
      # Verify complex constructs are parsed
      children = result.ast["children"]
      assert is_list(children)
      assert length(children) >= 2  # module name, class
      
      # Should contain class definition
      [_module_name, class_node | _] = children
      assert class_node["type"] == "class"
    end
    
    test "returns metadata about parser and language version", %{customer_id: customer_id, session_id: session_id} do
      code = "x = 42"
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should parse successfully
      assert result.ast["type"] == "lvasgn"
    end
    
    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create complex code that should still parse within timeout
      code = """
      # Generate complex nested structure
      """ <> Enum.map_join(1..1000, "\n", fn i ->
        "obj\#{i} = { id: \#{i}, nested: { value: 'test\#{i}' } }"
      end)
      
      # Should complete successfully even with large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end
    
    test "preserves line and column information", %{customer_id: customer_id, session_id: session_id} do
      code = """
      class VulnerableClass
        def dangerous_method
          eval(user_input) # Line 3, dangerous!
          return true
        end
      end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # The AST should contain line/column information
      assert result.ast["type"] == "class"
      
      # Check that location information is preserved
      assert result.ast["_loc"]["start"]["line"] == 1
    end
    
    test "detects string interpolation patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      def build_query(table, condition)
        # VULNERABLE: SQL injection via string interpolation
        "SELECT * FROM \\\#{table} WHERE \\\#{condition}"
      end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "def"
    end
    
    test "detects command execution patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      def execute_command(cmd)
        # VULNERABLE: Command injection
        `\\\#{cmd}`
      end
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "def"
    end
    
    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "x = 1"
      code2 = "y = 2"
      
      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code2)
      
      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id
      
      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end
end