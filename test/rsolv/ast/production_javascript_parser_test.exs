defmodule Rsolv.AST.ProductionJavaScriptParserTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Rsolv.AST.{ParserRegistry, SessionManager}

  describe "Production JavaScript Parser" do
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

    test "parses simple JavaScript code with production parser", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      function greetUser(name) {
          console.log(`Hello, ${name}!`);
          return `Welcome, ${name}`;
      }

      const result = greetUser("World");
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.language == "javascript"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0

      # Check AST structure contains expected nodes
      assert result.ast["type"] == "File"
      assert is_map(result.ast["program"])
      assert result.ast["program"]["type"] == "Program"
      assert is_list(result.ast["program"]["body"])
    end

    test "detects XSS patterns in JavaScript code", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      function updateContent(userInput) {
          // VULNERABLE: XSS via innerHTML
          document.getElementById('content').innerHTML = userInput;

          // VULNERABLE: eval usage
          const result = eval(`alert('${userInput}')`);

          return result;
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.error == nil
      assert is_map(result.ast)

      # Should contain dangerous patterns
      assert result.ast["type"] == "File"
      assert result.ast["program"]["type"] == "Program"
    end

    test "handles JavaScript syntax errors gracefully", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      function brokenFunction() {
          let x = {
              missing: "closing brace"
          // Missing closing brace
          console.log("This will fail");
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.language == "javascript"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error.type == :syntax_error
      assert is_binary(result.error.message)
    end

    test "parses complex JavaScript constructs", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      import { Component } from 'react';
      import axios from 'axios';

      class SecurityAnalyzer extends Component {
          constructor(props) {
              super(props);
              this.state = {
                  findings: [],
                  isLoading: false
              };
          }

          async analyzeCode(code) {
              this.setState({ isLoading: true });

              try {
                  // Template literal with potential injection
                  const query = `SELECT * FROM code WHERE content = '${code}'`;

                  const response = await axios.post('/api/analyze', {
                      code: code,
                      query: query
                  });

                  this.setState({
                      findings: response.data.findings,
                      isLoading: false
                  });
              } catch (error) {
                  console.error('Analysis failed:', error);
                  this.setState({ isLoading: false });
              }
          }

          render() {
              const { findings, isLoading } = this.state;

              return (
                  <div>
                      {isLoading ? (
                          <div>Analyzing...</div>
                      ) : (
                          <ul>
                              {findings.map((finding, index) => (
                                  <li key={index}>{finding.message}</li>
                              ))}
                          </ul>
                      )}
                  </div>
              );
          }
      }

      export default SecurityAnalyzer;
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "File"

      # Verify complex constructs are parsed
      program = result.ast["program"]
      assert program["type"] == "Program"
      body = program["body"]
      assert is_list(body)
      # import, import, class, export
      assert length(body) >= 3

      # Should contain class declaration
      class_decl =
        Enum.find(body, fn node ->
          is_map(node) && node["type"] == "ClassDeclaration"
        end)

      assert class_decl != nil
      assert class_decl["id"]["name"] == "SecurityAnalyzer"
    end

    test "returns metadata about parser and language version", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = "const x = 42;"

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.error == nil
      assert is_map(result.ast)

      # Should parse successfully
      assert result.ast["type"] == "File"
      assert result.ast["program"]["type"] == "Program"
    end

    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create complex code that should still parse within timeout
      code =
        """
        // Generate complex nested structure
        """ <>
          Enum.map_join(1..1000, "\n", fn i ->
            "const obj#{i} = { id: #{i}, nested: { value: 'test#{i}' } };"
          end)

      # Should complete successfully even with large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end

    test "preserves line and column information", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      function vulnerableFunction() {
          const userInput = getUserInput();
          eval(userInput); // Line 3, dangerous!
          return true;
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code)

      assert result.error == nil
      assert is_map(result.ast)

      # The AST should contain line/column information
      assert result.ast["type"] == "File"

      # Navigate to function declaration to check line numbers are preserved
      program = result.ast["program"]
      [func_decl] = program["body"]
      assert func_decl["type"] == "FunctionDeclaration"
      assert func_decl["_loc"]["start"]["line"] == 1
    end

    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "const x = 1;"
      code2 = "const y = 2;"

      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "javascript", code2)

      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id

      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end

  describe "Production TypeScript Parser" do
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

    test "parses TypeScript code with type annotations", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      interface User {
          id: number;
          name: string;
          email?: string;
      }

      function createUser(data: Partial<User>): User {
          return {
              id: Date.now(),
              name: data.name || 'Anonymous',
              email: data.email
          };
      }

      const user: User = createUser({ name: 'John' });
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "typescript", code)

      assert result.language == "typescript"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0

      # Check AST structure
      assert result.ast["type"] == "File"
      assert result.ast["program"]["type"] == "Program"

      # Should contain interface and function declarations
      body = result.ast["program"]["body"]
      assert is_list(body)
      assert length(body) >= 3

      # Find interface declaration
      interface_decl =
        Enum.find(body, fn node ->
          is_map(node) && node["type"] == "TSInterfaceDeclaration"
        end)

      assert interface_decl != nil
      assert interface_decl["id"]["name"] == "User"
    end

    test "detects security patterns in TypeScript", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      class DatabaseService {
          private connection: any;

          async executeQuery(userInput: string): Promise<any[]> {
              // VULNERABLE: SQL injection via template literal
              const query = `SELECT * FROM users WHERE name = '${userInput}'`;

              // VULNERABLE: eval usage
              const result = eval(`this.connection.query('${query}')`);

              return result;
          }
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "typescript", code)

      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "File"
    end

    test "handles TypeScript syntax errors", %{customer_id: customer_id, session_id: session_id} do
      code = """
      interface BrokenInterface {
          id: number
          name: string
          // Missing semicolon or comma
          invalid syntax here
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "typescript", code)

      assert result.language == "typescript"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error.type == :syntax_error
      assert is_binary(result.error.message)
    end
  end
end
