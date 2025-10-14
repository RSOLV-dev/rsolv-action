defmodule RsolvWeb.Schemas.AST do
  @moduledoc """
  OpenAPI schemas for AST analysis endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule ASTAnalyzeRequest do
    @moduledoc """
    AST analysis request with encrypted files

    ## Examples

    ### Single JavaScript File Analysis
    ```json
    {
      "requestId": "ast-req-js-001",
      "files": [{
        "path": "src/auth/login.js",
        "encryptedContent": "YWJjZGVmZ2hpams...",
        "encryption": {
          "algorithm": "aes-256-gcm",
          "iv": "MTIzNDU2Nzg5MGFi",
          "authTag": "YXV0aFRhZw=="
        },
        "metadata": {
          "language": "javascript",
          "size": 1024
        }
      }],
      "options": {
        "patternFormat": "enhanced",
        "includeSecurityPatterns": true
      }
    }
    ```

    ### Multi-File Python Analysis
    ```json
    {
      "requestId": "ast-req-py-002",
      "files": [
        {
          "path": "app/views.py",
          "encryptedContent": "ZGVmIGxvZ2luKHJl...",
          "encryption": {
            "algorithm": "aes-256-gcm",
            "iv": "cHl0aG9uaXZhYmM=",
            "authTag": "cHl0YWc="
          },
          "metadata": {
            "language": "python",
            "size": 2048
          }
        },
        {
          "path": "app/models.py",
          "encryptedContent": "Y2xhc3MgVXNlcig=...",
          "encryption": {
            "algorithm": "aes-256-gcm",
            "iv": "bW9kZWxpdmFiYw==",
            "authTag": "bW9kYXV0aA=="
          },
          "metadata": {
            "language": "python",
            "size": 3072
          }
        }
      ],
      "options": {
        "patternFormat": "enhanced",
        "includeSecurityPatterns": true
      }
    }
    ```

    ### Ruby on Rails Analysis
    ```json
    {
      "requestId": "ast-req-rb-003",
      "files": [{
        "path": "app/controllers/users_controller.rb",
        "encryptedContent": "Y2xhc3MgVXNlcnND...",
        "encryption": {
          "algorithm": "aes-256-gcm",
          "iv": "cnVieWl2YWJjZGU=",
          "authTag": "cnVieWF1dGg="
        },
        "metadata": {
          "language": "ruby",
          "size": 1536
        }
      }],
      "options": {
        "patternFormat": "enhanced"
      }
    }
    ```

    ### Session Continuation
    ```json
    {
      "requestId": "ast-req-continue-001",
      "sessionId": "sess-abc123-from-previous",
      "files": [{
        "path": "src/utils/validation.js",
        "encryptedContent": "ZnVuY3Rpb24gdmFs...",
        "encryption": {
          "algorithm": "aes-256-gcm",
          "iv": "dmFsaWRhdGlvbml2",
          "authTag": "dmFsaWRhdXRo"
        }
      }]
    }
    ```

    ## Client Code Examples

    ### JavaScript (Node.js)
    ```javascript
    const crypto = require('crypto');
    const axios = require('axios');

    // Encrypt file content
    function encryptFile(content, key) {
      const algorithm = 'aes-256-gcm';
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);

      let encrypted = cipher.update(content, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      const authTag = cipher.getAuthTag();

      return {
        encryptedContent: encrypted,
        encryption: {
          algorithm: algorithm,
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64')
        }
      };
    }

    // Analyze code
    async function analyzeCode(files, apiKey, encryptionKey) {
      const encryptedFiles = files.map(file => ({
        path: file.path,
        ...encryptFile(file.content, encryptionKey),
        metadata: {
          language: file.language,
          size: file.content.length
        }
      }));

      const response = await axios.post(
        'https://api.rsolv.dev/api/v1/ast/analyze',
        {
          requestId: `ast-req-${Date.now()}`,
          files: encryptedFiles,
          options: {
            patternFormat: 'enhanced',
            includeSecurityPatterns: true
          }
        },
        {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      return response.data;
    }
    ```

    ### Python
    ```python
    import base64
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import requests

    def encrypt_file(content, key):
        aesgcm = AESGCM(bytes.fromhex(key))
        iv = os.urandom(12)

        encrypted = aesgcm.encrypt(iv, content.encode('utf-8'), None)
        ciphertext = encrypted[:-16]
        auth_tag = encrypted[-16:]

        return {
            'encryptedContent': base64.b64encode(ciphertext).decode('utf-8'),
            'encryption': {
                'algorithm': 'aes-256-gcm',
                'iv': base64.b64encode(iv).decode('utf-8'),
                'authTag': base64.b64encode(auth_tag).decode('utf-8')
            }
        }

    def analyze_code(files, api_key, encryption_key):
        encrypted_files = []
        for file in files:
            encrypted = encrypt_file(file['content'], encryption_key)
            encrypted_files.append({
                'path': file['path'],
                **encrypted,
                'metadata': {
                    'language': file['language'],
                    'size': len(file['content'])
                }
            })

        response = requests.post(
            'https://api.rsolv.dev/api/v1/ast/analyze',
            json={
                'requestId': f'ast-req-{int(time.time())}',
                'files': encrypted_files,
                'options': {
                    'patternFormat': 'enhanced',
                    'includeSecurityPatterns': True
                }
            },
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
        )

        return response.json()
    ```

    ### cURL
    ```bash
    # Encrypt file first (example using openssl)
    echo "const userId = req.params.id;" | openssl enc -aes-256-gcm -K $ENCRYPTION_KEY -iv $IV > encrypted.bin

    # Analyze (with pre-encrypted content)
    curl -X POST https://api.rsolv.dev/api/v1/ast/analyze \\
      -H "Authorization: Bearer $API_KEY" \\
      -H "Content-Type: application/json" \\
      -d '{
        "requestId": "ast-req-001",
        "files": [{
          "path": "src/user.js",
          "encryptedContent": "'"$(base64 < encrypted.bin)"'",
          "encryption": {
            "algorithm": "aes-256-gcm",
            "iv": "'"$(echo $IV | base64)"'",
            "authTag": "'"$(echo $AUTH_TAG | base64)"'"
          },
          "metadata": {
            "language": "javascript",
            "size": 1024
          }
        }],
        "options": {
          "patternFormat": "enhanced",
          "includeSecurityPatterns": true
        }
      }'
    ```
    """
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
