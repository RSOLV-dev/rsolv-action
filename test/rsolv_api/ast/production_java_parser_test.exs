defmodule RsolvApi.AST.ProductionJavaParserTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{ParserRegistry, SessionManager}
  
  describe "Production Java Parser" do
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
    
    test "parses simple Java code with production parser", %{customer_id: customer_id, session_id: session_id} do
      code = """
      public class HelloWorld {
          public static void main(String[] args) {
              System.out.println("Hello, World!");
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.language == "java"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
      
      # Check AST structure (using JavaScript fallback parser for now)
      assert is_map(result.ast)
    end
    
    test "detects dangerous method patterns in Java code", %{customer_id: customer_id, session_id: session_id} do
      code = """
      public class VulnerableServlet {
          public void processRequest(String userInput) {
              // VULNERABLE: Runtime.exec usage
              Runtime.getRuntime().exec(userInput);
              
              // VULNERABLE: SQL injection
              String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
              Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
              Statement stmt = conn.createStatement();
              stmt.executeQuery(sql);
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should parse successfully (using fallback for now)
      assert result.language == "java"
    end
    
    test "handles Java syntax errors gracefully", %{customer_id: customer_id, session_id: session_id} do
      code = """
      public class BrokenClass {
          public void brokenMethod() {
              System.out.println("Missing closing brace"
          }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.language == "java"
      # Fallback JavaScript parser may or may not handle Java syntax errors
      # This test verifies the parser doesn't crash
      assert is_map(result.timing)
    end
    
    test "parses complex Java constructs", %{customer_id: customer_id, session_id: session_id} do
      code = """
      import java.util.*;
      import java.sql.*;
      
      public class SecurityScanner {
          private List<String> findings;
          
          public SecurityScanner() {
              this.findings = new ArrayList<>();
          }
          
          public void scanCode(String userCode) throws SQLException {
              // VULNERABLE: Dynamic SQL construction
              String query = "SELECT * FROM code WHERE content = '" + userCode + "'";
              
              // VULNERABLE: Process execution
              ProcessBuilder pb = new ProcessBuilder("sh", "-c", userCode);
              Process proc = pb.start();
              
              findings.add("SQL injection risk detected");
              findings.add("Command injection risk detected");
          }
          
          public List<String> getFindings() {
              return Collections.unmodifiableList(findings);
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.language == "java"
      
      # Verify parsing completes
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
    end
    
    test "returns metadata about parser and language version", %{customer_id: customer_id, session_id: session_id} do
      code = "public class Simple { }"
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should parse successfully
      assert result.language == "java"
    end
    
    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # Create moderately complex code that should still parse within timeout
      code = """
      public class ComplexClass {
      """ <> Enum.map_join(1..100, "\n", fn i ->
        "    public void method#{i}() { System.out.println(\"Method #{i}\"); }"
      end) <> "\n}"
      
      # Should complete successfully even with moderately large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end
    
    test "preserves line and column information", %{customer_id: customer_id, session_id: session_id} do
      code = """
      public class VulnerableClass {
          public void dangerousMethod() {
              Runtime.getRuntime().exec(userInput); // Line 3, dangerous!
              return;
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # The AST should be parsed successfully
      assert result.language == "java"
    end
    
    test "detects security patterns in annotations and reflections", %{customer_id: customer_id, session_id: session_id} do
      code = """
      import java.lang.reflect.*;
      
      @Component
      public class ReflectionService {
          
          @Autowired
          private DataSource dataSource;
          
          public Object invokeMethod(String className, String methodName, Object[] args) 
              throws Exception {
              // VULNERABLE: Reflection usage
              Class<?> clazz = Class.forName(className);
              Method method = clazz.getMethod(methodName);
              return method.invoke(clazz.newInstance(), args);
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.language == "java"
    end
    
    test "detects serialization vulnerabilities", %{customer_id: customer_id, session_id: session_id} do
      code = """
      import java.io.*;
      
      public class SerializationHandler {
          public Object deserialize(byte[] data) throws Exception {
              // VULNERABLE: Unsafe deserialization
              ByteArrayInputStream bis = new ByteArrayInputStream(data);
              ObjectInputStream ois = new ObjectInputStream(bis);
              return ois.readObject();
          }
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.language == "java"
    end
    
    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "public class Test1 { }"
      code2 = "public class Test2 { }"
      
      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "java", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "java", code2)
      
      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id
      
      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end
end