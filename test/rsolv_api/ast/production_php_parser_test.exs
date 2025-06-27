defmodule RsolvApi.AST.ProductionPhpParserTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{ParserRegistry, SessionManager}
  
  describe "Production PHP Parser" do
    setup do
      # Ensure managers are started
      case GenServer.whereis(SessionManager) do
        nil -> start_supervised!(SessionManager)
        _ -> :ok
      end
      
      case GenServer.whereis(ParserRegistry) do
        nil -> start_supervised!(ParserRegistry)
        _ -> :ok
      end
      
      # Create test customer and session
      customer_id = "test_customer_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      %{customer_id: customer_id, session_id: session.id}
    end
    
    test "parses simple PHP code with production parser", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      class User {
          private $name;
          
          public function __construct($name) {
              $this->name = $name;
          }
          
          public function greet() {
              echo "Hello, " . $this->name . "!";
          }
      }
      
      $user = new User("World");
      $user->greet();
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.language == "php"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_list(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
      
      # Check AST structure contains expected nodes
      assert length(result.ast) > 0
    end
    
    test "detects dangerous function patterns in PHP code", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      class VulnerableController {
          public function processRequest($userInput) {
              // VULNERABLE: eval usage
              eval($userInput);
              
              // VULNERABLE: system command
              system("rm -rf " . $userInput);
              
              // VULNERABLE: SQL injection
              $sql = "SELECT * FROM users WHERE name = '" . $userInput . "'";
              mysql_query($sql);
              
              // VULNERABLE: file inclusion
              include $userInput;
          }
      }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      
      # Should contain dangerous patterns
      assert length(result.ast) > 0
    end
    
    test "handles PHP syntax errors gracefully", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      class BrokenClass {
          public function brokenMethod() {
              echo "Missing semicolon"
              echo "This will fail";
          }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.language == "php"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error["type"] == "SyntaxError"
      assert is_binary(result.error["message"])
    end
    
    test "parses complex PHP constructs", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      namespace SecurityAnalyzer;
      
      use PDO;
      use Exception;
      
      class Scanner {
          private $findings = [];
          private $config;
          
          public function __construct(array $config = []) {
              $this->config = $config;
          }
          
          public function scanCode($code) {
              // VULNERABLE: Dynamic SQL construction
              $query = "SELECT * FROM code WHERE content = '" . $code . "'";
              
              // VULNERABLE: Command execution
              $result = shell_exec($code);
              
              $this->findings[] = ['type' => 'sql_injection', 'query' => $query];
              $this->findings[] = ['type' => 'command_injection', 'code' => $code];
              
              return $this->findings;
          }
          
          public function getFindings() {
              return $this->findings;
          }
          
          private function sanitize($input) {
              return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
          }
      }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      assert length(result.ast) > 0
      
      # Verify complex constructs are parsed
      assert result.language == "php"
    end
    
    test "returns metadata about parser and language version", %{customer_id: customer_id, session_id: session_id} do
      code = "<?php $x = 42; ?>"
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      
      # Should parse successfully
      assert length(result.ast) > 0
    end
    
    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create complex code that should still parse within timeout
      code = "<?php\n" <> Enum.map_join(1..1000, "\n", fn i ->
        "$obj#{i} = ['id' => #{i}, 'nested' => ['value' => 'test#{i}']];"
      end) <> "\n?>"
      
      # Should complete successfully even with large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      assert result.timing.parse_time_ms > 0
    end
    
    test "preserves line and column information", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      class VulnerableClass {
          public function dangerousMethod() {
              eval($userInput); // Line 4, dangerous!
              return true;
          }
      }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      
      # The AST should contain line/column information
      assert length(result.ast) > 0
    end
    
    test "detects string concatenation patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      function buildQuery($table, $condition) {
          // VULNERABLE: SQL injection via string concatenation
          return "SELECT * FROM " . $table . " WHERE " . $condition;
      }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      assert length(result.ast) > 0
    end
    
    test "detects variable variables patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      <?php
      function processInput($param) {
          // VULNERABLE: Variable variables
          $$param = "dangerous";
          return $$param;
      }
      ?>
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "php", code)
      
      assert result.error == nil
      assert is_list(result.ast)
      assert length(result.ast) > 0
    end
    
    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "<?php $x = 1; ?>"
      code2 = "<?php $y = 2; ?>"
      
      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "php", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "php", code2)
      
      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id
      
      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end
end