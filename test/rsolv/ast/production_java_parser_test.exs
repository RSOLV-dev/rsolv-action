defmodule Rsolv.AST.ProductionJavaParserTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Rsolv.AST.{ParserRegistry, SessionManager}

  describe "Production Java Parser" do
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

    test "returns ParserNotAvailable error for Java code", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert result.error.message =~ "Java parser not built"
      assert result.error.message =~ "requires Maven installation"
      assert is_nil(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
    end

    test "returns ParserNotAvailable error for dangerous Java patterns", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
    end

    test "returns ParserNotAvailable error for Java syntax errors", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      public class BrokenClass {
          public void brokenMethod() {
              System.out.println("Missing closing brace"
          }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_map(result.timing)
    end

    test "returns ParserNotAvailable error for complex Java constructs", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)

      # Verify timing is still tracked
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
    end

    test "returns ParserNotAvailable error with metadata", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = "public class Simple { }"

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
    end

    test "returns ParserNotAvailable error for timeout scenarios", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      # Create moderately complex code that should still parse within timeout
      code =
        """
        public class ComplexClass {
        """ <>
          Enum.map_join(1..100, "\n", fn i ->
            "    public void method#{i}() { System.out.println(\"Method #{i}\"); }"
          end) <> "\n}"

      # Should return parser not available error
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
      assert result.timing.parse_time_ms > 0
    end

    test "returns ParserNotAvailable error when checking line/column info", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code = """
      public class VulnerableClass {
          public void dangerousMethod() {
              Runtime.getRuntime().exec(userInput); // Line 3, dangerous!
              return;
          }
      }
      """

      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "java", code)

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
    end

    test "returns ParserNotAvailable error for security pattern detection", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
    end

    test "returns ParserNotAvailable error for serialization checks", %{
      customer_id: customer_id,
      session_id: session_id
    } do
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

      assert result.language == "java"
      assert result.error != nil
      assert result.error.type == :parser_not_available
      assert is_nil(result.ast)
    end

    test "reuses parser instance even with errors", %{
      customer_id: customer_id,
      session_id: session_id
    } do
      code1 = "public class Test1 { }"
      code2 = "public class Test2 { }"

      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "java", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "java", code2)

      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id

      # Both should have the same parser not available error
      assert result1.error != nil
      assert result1.error.type == :parser_not_available
      assert result2.error != nil
      assert result2.error.type == :parser_not_available
    end
  end
end
