defmodule Rsolv.AST.TestCase do
  @moduledoc """
  Shared test case for AST-related tests.
  Provides common helpers and test data for multi-language parsing.
  """
  
  use ExUnit.CaseTemplate
  
  using do
    quote do
      import Rsolv.AST.TestCase
      alias Rsolv.AST.PortSupervisor
    end
  end
  
  setup do
    # Ensure the application is started for tests
    Application.ensure_all_started(:rsolv)
    
    # Create a test session
    {:ok, session} = Rsolv.AST.SessionManager.create_session("test-customer")
    
    on_exit(fn ->
      # Clean up session after test
      Rsolv.AST.SessionManager.delete_session(session.id, "test-customer")
    end)
    
    {:ok, session_id: session.id, session: session}
  end
  
  # Test fixtures for different languages
  
  @doc "Get test code samples for a specific language"
  def test_code(language, type \\ :simple)
  
  # Python test cases
  # Elixir test code
  def test_code("elixir", :simple) do
    """
    defmodule Example do
      def hello do
        "world"
      end
    end
    """
  end

  def test_code("elixir", :command_injection_vulnerable) do
    """
    defmodule Vulnerable do
      def run_command(user_input) do
        # VULNERABLE: System.cmd with user input
        System.cmd("sh", ["-c", user_input])
      end
      
      def another_command(input) do
        # Also vulnerable
        Port.open({:spawn, input}, [:binary])
      end
    end
    """
  end

  def test_code("python", :simple) do
    """
    def hello():
        return "Hello, World!"
    """
  end
  
  def test_code("python", :sql_injection_vulnerable) do
    """
    import sqlite3
    
    def get_user(user_id):
        conn = sqlite3.connect('users.db')
        # VULNERABLE: Direct string interpolation
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor = conn.execute(query)
        return cursor.fetchone()
    """
  end
  
  def test_code("python", :sql_injection_safe) do
    """
    import sqlite3
    
    def get_user(user_id):
        conn = sqlite3.connect('users.db')
        # SAFE: Parameterized query
        query = "SELECT * FROM users WHERE id = ?"
        cursor = conn.execute(query, (user_id,))
        return cursor.fetchone()
    """
  end
  
  def test_code("python", :command_injection_vulnerable) do
    """
    import os
    
    def process_file(filename):
        # VULNERABLE: os.system with user input
        os.system(f"cat {filename}")
    """
  end
  
  def test_code("python", :syntax_error) do
    """
    def broken(:
        return "This won't parse"
    """
  end
  
  # Ruby test cases
  def test_code("ruby", :simple) do
    """
    def hello
      "Hello, World!"
    end
    """
  end
  
  def test_code("ruby", :sql_injection_vulnerable) do
    ~S"""
    class User < ActiveRecord::Base
      def self.find_by_name(name)
        # VULNERABLE: String interpolation in query
        where("name = '#{name}'")
      end
    end
    """
  end
  
  def test_code("ruby", :sql_injection_safe) do
    """
    class User < ActiveRecord::Base
      def self.find_by_name(name)
        # SAFE: Parameterized query
        where("name = ?", name)
      end
    end
    """
  end
  
  def test_code("ruby", :command_injection_vulnerable) do
    ~S"""
    def process_file(filename)
      # VULNERABLE: backticks with interpolation
      `cat #{filename}`
    end
    """
  end
  
  def test_code("ruby", :syntax_error) do
    """
    def broken
      "Missing end
    """
  end
  
  # PHP test cases
  def test_code("php", :simple) do
    """
    <?php
    function hello() {
        return "Hello, World!";
    }
    ?>
    """
  end
  
  def test_code("php", :sql_injection_vulnerable) do
    """
    <?php
    function getUser($id) {
        $conn = new mysqli("localhost", "user", "pass", "db");
        // VULNERABLE: Direct concatenation
        $query = "SELECT * FROM users WHERE id = " . $id;
        $result = $conn->query($query);
        return $result->fetch_assoc();
    }
    ?>
    """
  end
  
  def test_code("php", :sql_injection_safe) do
    """
    <?php
    function getUser($id) {
        $conn = new mysqli("localhost", "user", "pass", "db");
        // SAFE: Prepared statement
        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    ?>
    """
  end
  
  def test_code("php", :xss_vulnerable) do
    """
    <?php
    $name = $_GET['name'];
    // VULNERABLE: Direct echo without escaping
    echo "Hello, " . $name;
    ?>
    """
  end
  
  def test_code("php", :xss_safe) do
    """
    <?php
    $name = $_GET['name'];
    // SAFE: Properly escaped
    echo "Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    ?>
    """
  end
  
  # Java test cases
  def test_code("java", :simple) do
    """
    public class Hello {
        public static String hello() {
            return "Hello, World!";
        }
    }
    """
  end
  
  def test_code("java", :sql_injection_vulnerable) do
    """
    import java.sql.*;
    
    public class UserDao {
        public User getUser(String id) throws SQLException {
            Connection conn = getConnection();
            // VULNERABLE: String concatenation
            String query = "SELECT * FROM users WHERE id = " + id;
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            return parseUser(rs);
        }
    }
    """
  end
  
  def test_code("java", :sql_injection_safe) do
    """
    import java.sql.*;
    
    public class UserDao {
        public User getUser(String id) throws SQLException {
            Connection conn = getConnection();
            // SAFE: Prepared statement
            String query = "SELECT * FROM users WHERE id = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, id);
            ResultSet rs = pstmt.executeQuery();
            return parseUser(rs);
        }
    }
    """
  end
  
  def test_code("java", :command_injection_vulnerable) do
    """
    import java.io.*;
    
    public class FileProcessor {
        public void processFile(String filename) throws IOException {
            // VULNERABLE: Runtime.exec with user input
            Runtime.getRuntime().exec("cat " + filename);
        }
    }
    """
  end
  
  # JavaScript test cases
  def test_code("javascript", :simple) do
    """
    function hello() {
        return "Hello, World!";
    }
    """
  end
  
  def test_code("javascript", :sql_injection_vulnerable) do
    """
    const mysql = require('mysql');
    
    function getUser(userId) {
        const connection = mysql.createConnection({host: 'localhost'});
        // VULNERABLE: String concatenation
        const query = `SELECT * FROM users WHERE id = ${userId}`;
        return connection.query(query);
    }
    """
  end
  
  def test_code("javascript", :sql_injection_safe) do
    """
    const mysql = require('mysql');
    
    function getUser(userId) {
        const connection = mysql.createConnection({host: 'localhost'});
        // SAFE: Parameterized query
        const query = 'SELECT * FROM users WHERE id = ?';
        return connection.query(query, [userId]);
    }
    """
  end
  
  
  # Helper to get expected vulnerabilities
  def expected_vulnerabilities(language, code_type) do
    case {language, code_type} do
      {_, :simple} -> []
      {_, :syntax_error} -> [:syntax_error]
      
      {"python", :sql_injection_vulnerable} -> 
        [%{type: :sql_injection, severity: "high", line: 6}]
      {"python", :command_injection_vulnerable} -> 
        [%{type: :command_injection, severity: "critical", line: 5}]
      
      {"ruby", :sql_injection_vulnerable} -> 
        [%{type: :sql_injection, severity: "high", line: 4}]
      {"ruby", :command_injection_vulnerable} -> 
        [%{type: :command_injection, severity: "critical", line: 3}]
      
      {"php", :sql_injection_vulnerable} -> 
        [%{type: :sql_injection, severity: "high", line: 5}]
      {"php", :xss_vulnerable} -> 
        [%{type: :xss, severity: "medium", line: 4}]
      
      {"java", :sql_injection_vulnerable} -> 
        [%{type: :sql_injection, severity: "high", line: 7}]
      {"java", :command_injection_vulnerable} -> 
        [%{type: :command_injection, severity: "critical", line: 6}]
      
      {"javascript", :sql_injection_vulnerable} -> 
        [%{type: :sql_injection, severity: "high", line: 6}]
      
      {"elixir", :command_injection_vulnerable} -> 
        [%{type: :command_injection, severity: "critical", line: 4}]
      
      {_, _} -> []
    end
  end
  
  # Helper to create temporary test files
  def with_temp_file(content, extension, fun) do
    dir = System.tmp_dir!()
    filename = "test_#{:rand.uniform(100000)}.#{extension}"
    path = Path.join(dir, filename)
    
    try do
      File.write!(path, content)
      fun.(path)
    after
      File.rm(path)
    end
  end
  
  # Helper to assert AST structure
  def assert_ast_node(ast, expected_type) when is_map(ast) do
    assert ast["_type"] == expected_type
  end
  
  def assert_ast_node(ast, expected_type) when is_binary(expected_type) do
    assert ast[:type] == expected_type || ast["type"] == expected_type
  end
  
  # Helper to find nodes in AST
  def find_nodes(ast, node_type) when is_map(ast) do
    nodes = if ast["_type"] == node_type or ast["type"] == node_type or ast[:type] == node_type do
      [ast]
    else
      []
    end
    
    # Recursively search children
    Enum.reduce(ast, nodes, fn {_key, value}, acc ->
      case value do
        %{} -> acc ++ find_nodes(value, node_type)
        list when is_list(list) ->
          Enum.reduce(list, acc, fn item, acc2 ->
            if is_map(item) do
              acc2 ++ find_nodes(item, node_type)
            else
              acc2
            end
          end)
        _ -> acc
      end
    end)
  end
  
  def find_nodes(_, _), do: []
  
  # Helper to run parser and get AST
  def parse_code(language, code) do
    case language do
      lang when lang in ["python", "ruby"] ->
        # Direct parsing removed - use PortSupervisor.parse instead
        {:error, "Use PortSupervisor.parse instead"}
        
      _ ->
        {:error, "Parser not implemented for #{language}"}
    end
  end
end