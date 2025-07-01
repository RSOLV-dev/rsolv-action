defmodule RSOLVWeb.Api.V1.ASTControllerTest do
  use RSOLVWeb.ConnCase, async: true
  
  alias RsolvApi.AST.SessionManager
  alias RsolvApi.AST.Encryption
  
  setup do
    # Ensure SessionManager is started
    case GenServer.whereis(SessionManager) do
      _ -> :ok
    end
    
    # Ensure RateLimiter is started and clear any rate limit data
    case GenServer.whereis(RSOLV.RateLimiter) do
      nil -> 
        start_supervised!(RSOLV.RateLimiter)
        :timer.sleep(100) # Give it time to initialize ETS table
      _ -> 
        :ok
    end
    
    # Clear rate limit data for test customer
    if :ets.whereis(:rsolv_rate_limiter) != :undefined do
      :ets.delete_all_objects(:rsolv_rate_limiter)
    end
    
    # Use a predefined test API key from Accounts module
    customer = %{
      id: "test_customer_1",
      name: "Test Customer",
      email: "test@example.com",
      api_key: "rsolv_test_abc123",
      tier: "enterprise",
      flags: ["ai_access", "enterprise_access"],
      monthly_limit: 100,
      current_usage: 15,
      active: true,
      trial: true,
      created_at: DateTime.utc_now()
    }
    
    {:ok, customer: customer}
  end
  
  describe "analyze/2" do
    test "requires API key authentication", %{conn: conn} do
      conn = post(conn, "/api/v1/ast/analyze", %{})
      
      response = json_response(conn, 401)
      assert response["error"]["code"] == "AUTH_REQUIRED"
      assert response["error"]["message"] == "API key required for AST analysis"
      assert response["requestId"]
    end
    
    test "validates API key", %{conn: conn} do
      conn = conn
      |> put_req_header("x-api-key", "invalid-key")
      |> post("/api/v1/ast/analyze", %{})
      
      response = json_response(conn, 401)
      assert response["error"]["code"] == "INVALID_API_KEY"
      assert response["error"]["message"] == "Invalid or expired API key"
      assert response["requestId"]
    end
    
    test "requires files in request", %{conn: conn, customer: customer} do
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", %{})
      
      response = json_response(conn, 400)
      assert response["error"]["code"] == "INVALID_REQUEST"
      assert response["error"]["message"] == "files required"
      assert response["requestId"]
    end
    
    test "analyzes encrypted files successfully", %{conn: conn, customer: customer} do
      # First, make a request without a session to get one created
      initial_request = %{
        "requestId" => "test-request-123",
        "files" => [],
        "options" => %{
          "patternFormat" => "enhanced",
          "includeSecurityPatterns" => true
        }
      }
      
      # This will create a session for us
      conn1 = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", initial_request)
      
      # Get the session from the response  
      _initial_response = json_response(conn1, 200) # Empty files is OK
      
      # Create a proper session to get encryption key
      {:ok, session} = SessionManager.create_session(customer.id)
      
      # Encrypt test file content
      content = """
      function test() {
        const query = "SELECT * FROM users WHERE id = " + userId;
        db.query(query);
      }
      """
      
      {encrypted_content, iv, auth_tag} = Encryption.encrypt(
        content, 
        session.encryption_key
      )
      
      request = %{
        "requestId" => "test-request-123",
        "sessionId" => session.id,  # Use the session we created
        "files" => [
          %{
            "path" => "test.js",
            "encryptedContent" => Base.encode64(encrypted_content),
            "encryption" => %{
              "iv" => Base.encode64(iv),
              "algorithm" => "aes-256-gcm",
              "authTag" => Base.encode64(auth_tag)
            },
            "metadata" => %{
              "language" => "javascript",
              "size" => byte_size(content),
              "contentHash" => :crypto.hash(:sha256, content) |> Base.encode16()
            }
          }
        ],
        "options" => %{
          "patternFormat" => "enhanced",
          "includeSecurityPatterns" => true
        }
      }
      
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", request)
      
      response = json_response(conn, 200)
      
      assert response["requestId"] == "test-request-123"
      assert response["session"]["sessionId"]
      assert response["session"]["expiresAt"]
      
      assert length(response["results"]) == 1
      result = hd(response["results"])
      
      assert result["path"] == "test.js"
      assert result["status"] == "success"
      assert result["language"] == "javascript"
      assert length(result["findings"]) > 0
      
      # Should find SQL injection
      sql_finding = Enum.find(result["findings"], &(&1["type"] == "sql_injection"))
      assert sql_finding
      assert sql_finding["severity"] in ["high", "critical"]
      
      # Check summary
      assert response["summary"]["filesAnalyzed"] == 1
      assert response["summary"]["filesWithFindings"] == 1
      assert response["summary"]["totalFindings"] > 0
    end
    
    test "handles multiple files in batch", %{conn: conn, customer: customer} do
      # Create a session to get encryption key
      {:ok, session} = SessionManager.create_session(customer.id)
      
      # Encrypt multiple test files
      files = [
        %{
          content: "const x = 1;",
          path: "safe.js",
          language: "javascript"
        },
        %{
          content: """
          import os
          def run(user_input):
              os.system("echo " + user_input)
          """,
          path: "unsafe.py",
          language: "python"
        }
      ]
      
      encrypted_files = Enum.map(files, fn file ->
        {encrypted_content, iv, auth_tag} = Encryption.encrypt(
          file.content, 
          session.encryption_key
        )
        
        %{
          "path" => file.path,
          "encryptedContent" => Base.encode64(encrypted_content),
          "encryption" => %{
            "iv" => Base.encode64(iv),
            "algorithm" => "aes-256-gcm",
            "authTag" => Base.encode64(auth_tag)
          },
          "metadata" => %{
            "language" => file.language,
            "size" => byte_size(file.content),
            "contentHash" => :crypto.hash(:sha256, file.content) |> Base.encode16()
          }
        }
      end)
      
      request = %{
        "sessionId" => session.id,
        "files" => encrypted_files,
        "options" => %{
          "patternFormat" => "enhanced",
          "includeSecurityPatterns" => true
        }
      }
      
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", request)
      
      response = json_response(conn, 200)
      
      assert length(response["results"]) == 2
      
      safe_result = Enum.find(response["results"], &(&1["path"] == "safe.js"))
      assert safe_result["status"] == "success"
      assert safe_result["findings"] == []
      
      unsafe_result = Enum.find(response["results"], &(&1["path"] == "unsafe.py"))
      assert unsafe_result["status"] == "success"
      assert length(unsafe_result["findings"]) > 0
      
      # Should find command injection
      cmd_finding = Enum.find(unsafe_result["findings"], &(&1["type"] == "command_injection"))
      assert cmd_finding
    end
    
    test "enforces file size limits", %{conn: conn, customer: customer} do
      # Create a session to get encryption key
      {:ok, session} = SessionManager.create_session(customer.id)
      
      # Create content that claims to be too large
      content = "const x = 1;"
      {encrypted_content, iv, auth_tag} = Encryption.encrypt(
        content, 
        session.encryption_key
      )
      
      request = %{
        "sessionId" => session.id,
        "files" => [
          %{
            "path" => "large.js",
            "encryptedContent" => Base.encode64(encrypted_content),
            "encryption" => %{
              "iv" => Base.encode64(iv),
              "algorithm" => "aes-256-gcm",
              "authTag" => Base.encode64(auth_tag)
            },
            "metadata" => %{
              "language" => "javascript",
              "size" => 11 * 1024 * 1024, # 11MB (over limit)
              "contentHash" => :crypto.hash(:sha256, content) |> Base.encode16()
            }
          }
        ],
        "options" => %{}
      }
      
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", request)
      
      response = json_response(conn, 400)
      assert response["error"]["code"] == "INVALID_REQUEST"
      assert response["error"]["message"] == "file too large (max 10485760 bytes)"
      assert response["requestId"]
    end
    
    test "enforces rate limiting", %{conn: conn, customer: customer} do
      
      # Create a session to get encryption key
      {:ok, session} = SessionManager.create_session(customer.id)
      
      # Create a valid request
      content = "const x = 1;"
      {encrypted_content, iv, auth_tag} = Encryption.encrypt(
        content, 
        session.encryption_key
      )
      
      request = %{
        "sessionId" => session.id,
        "files" => [
          %{
            "path" => "test.js",
            "encryptedContent" => Base.encode64(encrypted_content),
            "encryption" => %{
              "iv" => Base.encode64(iv),
              "algorithm" => "aes-256-gcm",
              "authTag" => Base.encode64(auth_tag)
            },
            "metadata" => %{
              "language" => "javascript",
              "size" => byte_size(content),
              "contentHash" => :crypto.hash(:sha256, content) |> Base.encode16()
            }
          }
        ],
        "options" => %{}
      }
      
      # Simulate hitting rate limit by setting counter
      :ets.insert(:rsolv_rate_limiter, {{customer.id, "ast_analysis"}, 100, System.system_time(:second)})
      
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", request)
      
      response = json_response(conn, 429)
      assert response["error"]["code"] == "RATE_LIMITED"
      assert response["error"]["message"] =~ "Rate limit exceeded"
      assert response["retryAfter"] == 60
      assert get_resp_header(conn, "retry-after") == ["60"]
    end
    
    test "enforces maximum files limit", %{conn: conn, customer: customer} do
      # Create a session to get encryption key
      {:ok, session} = SessionManager.create_session(customer.id)
      
      # Create 11 files (over limit)
      files = Enum.map(1..11, fn i ->
        content = "const x = #{i};"
        {encrypted_content, iv, auth_tag} = Encryption.encrypt(
          content, 
          session.encryption_key
        )
        
        %{
          "path" => "file#{i}.js",
          "encryptedContent" => Base.encode64(encrypted_content),
          "encryption" => %{
            "iv" => Base.encode64(iv),
            "algorithm" => "aes-256-gcm",
            "authTag" => Base.encode64(auth_tag)
          },
          "metadata" => %{
            "language" => "javascript",
            "size" => byte_size(content),
            "contentHash" => :crypto.hash(:sha256, content) |> Base.encode16()
          }
        }
      end)
      
      request = %{
        "sessionId" => session.id,
        "files" => files,
        "options" => %{}
      }
      
      conn = conn
      |> put_req_header("x-api-key", customer.api_key)
      |> post("/api/v1/ast/analyze", request)
      
      response = json_response(conn, 400)
      assert response["error"]["code"] == "INVALID_REQUEST"
      assert response["error"]["message"] == "maximum 10 files allowed"
      assert response["requestId"]
    end
  end
end