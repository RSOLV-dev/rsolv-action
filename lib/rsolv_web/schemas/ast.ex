defmodule RsolvWeb.Schemas.AST do
  @moduledoc """
  OpenAPI schemas for AST analysis endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule ASTAnalyzeRequest do
    @moduledoc "AST analysis request with encrypted files"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ASTAnalyzeRequest",
      description: "Request to analyze encrypted source code files using AST patterns",
      type: :object,
      properties: %{
        requestId: %Schema{
          type: :string,
          description: "Optional request identifier for tracking",
          nullable: true,
          example: "ast-req-12345"
        },
        sessionId: %Schema{
          type: :string,
          description: "Optional session ID to continue previous analysis session",
          nullable: true,
          example: "sess-abc123"
        },
        files: %Schema{
          type: :array,
          description: "Array of encrypted source code files to analyze",
          items: %Schema{
            type: :object,
            properties: %{
              path: %Schema{
                type: :string,
                description: "File path",
                example: "src/controllers/userController.js"
              },
              encryptedContent: %Schema{
                type: :string,
                description: "Base64-encoded encrypted file content",
                example: "YWJjZGVmZ2hpams..."
              },
              encryption: %Schema{
                type: :object,
                description: "Encryption metadata (AES-256-GCM)",
                properties: %{
                  algorithm: %Schema{
                    type: :string,
                    description: "Encryption algorithm (must be aes-256-gcm)",
                    example: "aes-256-gcm"
                  },
                  iv: %Schema{
                    type: :string,
                    description: "Base64-encoded initialization vector",
                    example: "MTIzNDU2Nzg5MGFi"
                  },
                  authTag: %Schema{
                    type: :string,
                    description: "Base64-encoded authentication tag",
                    example: "YXV0aFRhZw=="
                  }
                },
                required: [:algorithm, :iv, :authTag]
              },
              metadata: %Schema{
                type: :object,
                description: "Optional file metadata",
                properties: %{
                  language: %Schema{type: :string, example: "javascript"},
                  size: %Schema{type: :integer, example: 1024}
                }
              }
            },
            required: [:path, :encryptedContent, :encryption]
          },
          minItems: 1,
          maxItems: 10
        },
        options: %Schema{
          type: :object,
          description: "Analysis options",
          properties: %{
            patternFormat: %Schema{
              type: :string,
              enum: ["standard", "enhanced"],
              description: "Pattern format to use",
              example: "enhanced"
            },
            includeSecurityPatterns: %Schema{
              type: :boolean,
              description: "Include security-specific patterns",
              example: true
            }
          }
        }
      },
      required: [:files],
      example: %{
        "requestId" => "ast-req-12345",
        "files" => [
          %{
            "path" => "src/controllers/userController.js",
            "encryptedContent" => "YWJjZGVmZ2hpams...",
            "encryption" => %{
              "algorithm" => "aes-256-gcm",
              "iv" => "MTIzNDU2Nzg5MGFi",
              "authTag" => "YXV0aFRhZw=="
            },
            "metadata" => %{
              "language" => "javascript",
              "size" => 1024
            }
          }
        ],
        "options" => %{
          "patternFormat" => "enhanced",
          "includeSecurityPatterns" => true
        }
      }
    })
  end

  defmodule ASTAnalyzeResponse do
    @moduledoc "AST analysis response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ASTAnalyzeResponse",
      description: "Results from AST-based code analysis with timing information",
      type: :object,
      properties: %{
        requestId: %Schema{
          type: :string,
          description: "Request identifier",
          example: "ast-req-12345"
        },
        session: %Schema{
          type: :object,
          description: "Session information",
          properties: %{
            sessionId: %Schema{type: :string, example: "sess-abc123"},
            expiresAt: %Schema{
              type: :string,
              format: :"date-time",
              example: "2025-10-14T13:00:00Z"
            }
          }
        },
        results: %Schema{
          type: :array,
          description: "Analysis results per file",
          items: %Schema{
            type: :object,
            properties: %{
              path: %Schema{type: :string},
              findings: %Schema{
                type: :array,
                items: %Schema{
                  type: :object,
                  properties: %{
                    pattern_id: %Schema{type: :string},
                    pattern_name: %Schema{type: :string},
                    type: %Schema{type: :string},
                    severity: %Schema{type: :string},
                    confidence: %Schema{type: :number, format: :float},
                    line: %Schema{type: :integer},
                    column: %Schema{type: :integer},
                    end_line: %Schema{type: :integer, nullable: true},
                    end_column: %Schema{type: :integer, nullable: true},
                    message: %Schema{type: :string},
                    recommendation: %Schema{type: :string},
                    code_snippet: %Schema{type: :string}
                  }
                }
              }
            }
          }
        },
        summary: %Schema{
          type: :object,
          description: "Summary of findings",
          properties: %{
            totalFiles: %Schema{type: :integer, example: 5},
            totalFindings: %Schema{type: :integer, example: 12}
          }
        },
        timing: %Schema{
          type: :object,
          description: "Performance timing information (milliseconds)",
          properties: %{
            total: %Schema{type: :integer, description: "Total request time"},
            decryption: %Schema{type: :integer, description: "Time spent decrypting"},
            analysis: %Schema{type: :integer, description: "Time spent analyzing"},
            perFile: %Schema{type: :integer, description: "Average time per file"}
          }
        }
      },
      required: [:requestId, :session, :results, :summary, :timing],
      example: %{
        "requestId" => "ast-req-12345",
        "session" => %{
          "sessionId" => "sess-abc123",
          "expiresAt" => "2025-10-14T13:00:00Z"
        },
        "results" => [
          %{
            "path" => "src/controllers/userController.js",
            "findings" => [
              %{
                "pattern_id" => "js-sql-injection-concat",
                "pattern_name" => "SQL Injection via String Concatenation",
                "type" => "sql_injection",
                "severity" => "high",
                "confidence" => 0.95,
                "line" => 42,
                "column" => 10,
                "message" => "SQL query built using string concatenation with user input",
                "recommendation" => "Use parameterized queries or prepared statements",
                "code_snippet" => "const query = 'SELECT * FROM users WHERE id = ' + userId;"
              }
            ]
          }
        ],
        "summary" => %{
          "totalFiles" => 1,
          "totalFindings" => 1
        },
        "timing" => %{
          "total" => 450,
          "decryption" => 50,
          "analysis" => 380,
          "perFile" => 380
        }
      }
    })
  end
end
