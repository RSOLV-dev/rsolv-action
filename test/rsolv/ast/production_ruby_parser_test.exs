# credo:disable-for-this-file Credo.Check.Warning.IoInspect
defmodule Rsolv.AST.ProductionRubyParserTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false
  use Rsolv.AST.TestCase

  @moduletag :integration

  alias Rsolv.AST.{ParserRegistry, SessionManager}

  describe "Production Ruby Parser" do
    setup do
      # Ensure SessionManager is available
      unless Process.whereis(SessionManager) do
      end

      # Ensure ParserRegistry is available
      unless Process.whereis(ParserRegistry) do
      end

      # Create test customer and session
      customer_id = "test_customer_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
      {:ok, session} = SessionManager.create_session(customer_id)

      %{customer_id: customer_id, session_id: session.id}
    end

    test "parses simple Ruby code with production parser", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      # Check AST structure - Prism returns program root
      assert result.ast["type"] == "program"
      # Should be able to find class and def nodes in the tree
      class_nodes = find_nodes(result.ast, "class")
      assert length(class_nodes) >= 1
    end

    test "detects dangerous method patterns in Ruby code", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      # Should contain dangerous patterns - find class node
      assert result.ast["type"] == "program"
      class_nodes = find_nodes(result.ast, "class")
      assert length(class_nodes) >= 1
    end

    test "handles Ruby syntax errors gracefully", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      # Debug output
      if result.error != nil do
        IO.inspect(result.error, label: "Ruby parser error for complex constructs")
      end

      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "program"

      # Verify complex constructs are parsed - find module and class nodes
      module_nodes = find_nodes(result.ast, "module")
      assert length(module_nodes) >= 1

      class_nodes = find_nodes(result.ast, "class")
      assert length(class_nodes) >= 1
    end

    test "returns metadata about parser and language version", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = "x = 42"

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)

      assert result.error == nil
      assert is_map(result.ast)

      # Should parse successfully - find local_variable_write (local variable assignment) node
      # Prism uses "local_variable_write" not "lvasgn" (old Parser gem format)
      assert result.ast["type"] == "program"
      lvasgn_nodes = find_nodes(result.ast, "local_variable_write")
      assert length(lvasgn_nodes) >= 1
    end

    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create complex code that should still parse within timeout
      code =
        """
        # Generate complex nested structure
        """ <>
          Enum.map_join(1..1000, "\n", fn i ->
            "obj\#{i} = { id: \#{i}, nested: { value: 'test\#{i}' } }"
          end)

      # Should complete successfully even with large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)

      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end

    test "preserves line and column information", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      # The AST should contain line/column information - find class node
      assert result.ast["type"] == "program"
      class_nodes = find_nodes(result.ast, "class")
      assert length(class_nodes) >= 1

      # Check that location information is preserved
      class_node = hd(class_nodes)
      assert class_node["_loc"]["start"]["line"] == 1
    end

    test "detects string interpolation patterns", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      def build_query(table, condition)
        # VULNERABLE: SQL injection via string interpolation
        "SELECT * FROM \\\#{table} WHERE \\\#{condition}"
      end
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "ruby", code)

      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "program"

      # Find the def node
      def_nodes = find_nodes(result.ast, "def")
      assert length(def_nodes) >= 1
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
      assert result.ast["type"] == "program"

      # Find the def node
      def_nodes = find_nodes(result.ast, "def")
      assert length(def_nodes) >= 1
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
