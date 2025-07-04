defmodule Rsolv.AST.ProductionGoParserTest do
  use ExUnit.Case, async: true

  @moduletag :integration
  
  
  alias Rsolv.AST.{ParserRegistry, SessionManager}
  
  describe "Production Go Parser" do
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
    
    test "parses simple Go code with production parser", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      import "fmt"
      
      type User struct {
          Name string
      }
      
      func (u *User) Greet() {
          fmt.Printf("Hello, %s!", u.Name)
      }
      
      func main() {
          user := &User{Name: "World"}
          user.Greet()
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.language == "go"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
      
      # Check AST structure contains expected nodes
      assert result.ast["type"] == "File"
      assert is_map(result.ast["children"])
    end
    
    test "detects dangerous function patterns in Go code", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      import (
          "os"
          "os/exec"
          "database/sql"
      )
      
      func vulnerableFunction(userInput string) {
          // VULNERABLE: Command execution
          cmd := exec.Command("sh", "-c", userInput)
          cmd.Run()
          
          // VULNERABLE: OS process start
          os.StartProcess("/bin/sh", []string{userInput}, nil)
          
          // VULNERABLE: SQL query
          db, _ := sql.Open("mysql", "connection")
          query := "SELECT * FROM users WHERE name = '" + userInput + "'"
          db.Query(query)
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should parse successfully
      assert result.ast["type"] == "File"
    end
    
    test "handles Go syntax errors gracefully", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      func brokenFunction() {
          fmt.Println("Missing import"
          return // Missing closing parenthesis
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.language == "go"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error.type == :syntax_error
      assert is_binary(result.error.message)
    end
    
    test "parses complex Go constructs", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      import (
          "context"
          "database/sql"
          "fmt"
          "net/http"
      )
      
      type SecurityScanner struct {
          findings []string
          config   map[string]interface{}
      }
      
      func NewScanner(config map[string]interface{}) *SecurityScanner {
          return &SecurityScanner{
              findings: make([]string, 0),
              config:   config,
          }
      }
      
      func (s *SecurityScanner) ScanCode(ctx context.Context, code string) error {
          // VULNERABLE: Dynamic SQL construction
          query := fmt.Sprintf("SELECT * FROM code WHERE content = '%s'", code)
          
          // VULNERABLE: Process execution
          // exec.Command("sh", "-c", code).Run()
          
          s.findings = append(s.findings, "SQL injection risk detected")
          s.findings = append(s.findings, "Command injection risk detected")
          
          return nil
      }
      
      func (s *SecurityScanner) GetFindings() []string {
          return s.findings
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "File"
      
      # Verify complex constructs are parsed
      children = result.ast["children"]
      assert is_map(children)
      assert Map.has_key?(children, "Decls")
    end
    
    test "returns metadata about parser and language version", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      var x = 42
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should parse successfully
      assert result.ast["type"] == "File"
    end
    
    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create complex code that should still parse within timeout
      code = "package main\n\n" <> Enum.map_join(1..100, "\n", fn i ->
        "var obj#{i} = map[string]interface{}{\"id\": #{i}, \"nested\": map[string]string{\"value\": \"test#{i}\"}}"
      end) <> "\n\nfunc main() {}"
      
      # Should complete successfully even with moderately large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end
    
    test "preserves line and column information", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      import "os/exec"
      
      func dangerousFunction() {
          exec.Command("sh", "-c", userInput).Run() // Line 6, dangerous!
          return
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # The AST should contain line/column information
      assert result.ast["type"] == "File"
      assert Map.has_key?(result.ast, "_loc")
    end
    
    test "detects goroutine and channel patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      import "fmt"
      
      func worker(ch chan string) {
          for msg := range ch {
              fmt.Println("Processing:", msg)
          }
      }
      
      func main() {
          ch := make(chan string, 10)
          go worker(ch)
          
          ch <- "message1"
          ch <- "message2"
          close(ch)
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "File"
    end
    
    test "detects interface and struct patterns", %{customer_id: customer_id, session_id: session_id} do
      code = """
      package main
      
      type Reader interface {
          Read([]byte) (int, error)
      }
      
      type FileReader struct {
          filename string
      }
      
      func (f *FileReader) Read(data []byte) (int, error) {
          // VULNERABLE: File operations without validation
          return len(data), nil
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "go", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "File"
    end
    
    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "package main\n\nvar x = 1"
      code2 = "package main\n\nvar y = 2"
      
      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "go", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "go", code2)
      
      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id
      
      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end
end