defmodule RsolvWeb.Schemas.Pattern do
  @moduledoc """
  OpenAPI schemas for security pattern-related endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule Pattern do
    @moduledoc "Security pattern schema"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "Pattern",
      description: "A security vulnerability detection pattern",
      type: :object,
      properties: %{
        id: %Schema{
          type: :string,
          description: "Unique pattern identifier",
          example: "js-sql-injection-concat"
        },
        name: %Schema{
          type: :string,
          description: "Human-readable pattern name",
          example: "SQL Injection via String Concatenation"
        },
        type: %Schema{
          type: :string,
          description: "Vulnerability type",
          enum: [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "hardcoded_secret",
            "insecure_crypto",
            "csrf",
            "xxe",
            "ssrf",
            "deserialization",
            "logging",
            "remote_code_execution"
          ],
          example: "sql_injection"
        },
        severity: %Schema{
          type: :string,
          description: "Severity level",
          enum: ["critical", "high", "medium", "low"],
          example: "high"
        },
        description: %Schema{
          type: :string,
          description: "Detailed description of the vulnerability",
          example: "Detects SQL injection through string concatenation in database queries"
        },
        regex: %Schema{
          type: :string,
          description: "Regular expression pattern for detection (legacy field)",
          nullable: true,
          example: "SELECT.*FROM.*WHERE.*\\+\\s*[a-zA-Z_][a-zA-Z0-9_]*"
        },
        regexPatterns: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Array of regex patterns for detection",
          example: ["SELECT.*FROM.*WHERE.*\\+\\s*[a-zA-Z_][a-zA-Z0-9_]*"]
        },
        languages: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Applicable programming languages",
          example: ["javascript", "typescript"]
        },
        frameworks: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Specific frameworks (if applicable)",
          example: ["express", "sequelize"]
        },
        cweId: %Schema{
          type: :string,
          description: "CWE identifier",
          pattern: "^CWE-\\d+$",
          example: "CWE-89"
        },
        owaspCategory: %Schema{
          type: :string,
          description: "OWASP Top 10 category",
          example: "A03:2021"
        },
        recommendation: %Schema{
          type: :string,
          description: "Remediation recommendation",
          example: "Use parameterized queries or prepared statements instead of string concatenation"
        },
        examples: %Schema{
          type: :array,
          items: %Schema{type: :object},
          description: "Example vulnerable and safe code snippets"
        },
        supportsAst: %Schema{
          type: :boolean,
          description: "Whether this pattern supports AST-based analysis",
          example: true
        },
        astRules: %Schema{
          type: :array,
          items: %Schema{type: :object},
          description: "AST analysis rules (enhanced format only)",
          nullable: true
        },
        contextRules: %Schema{
          type: :object,
          description: "Context validation rules (enhanced format only)",
          nullable: true
        },
        confidenceRules: %Schema{
          type: :object,
          description: "Confidence scoring rules (enhanced format only)",
          nullable: true
        },
        minConfidence: %Schema{
          type: :number,
          format: :float,
          description: "Minimum confidence threshold (enhanced format only)",
          example: 0.7,
          nullable: true
        }
      },
      required: [
        :id,
        :name,
        :type,
        :severity,
        :description,
        :languages,
        :recommendation
      ]
    })
  end

  defmodule PatternResponse do
    @moduledoc "Pattern API response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PatternResponse",
      description: "Response containing security patterns and metadata",
      type: :object,
      properties: %{
        patterns: %Schema{
          type: :array,
          items: Pattern,
          description: "Array of security patterns"
        },
        metadata: %Schema{
          type: :object,
          description: "Response metadata",
          properties: %{
            language: %Schema{type: :string, description: "Requested language"},
            format: %Schema{
              type: :string,
              enum: ["standard", "enhanced"],
              description: "Response format"
            },
            count: %Schema{type: :integer, description: "Number of patterns returned"},
            enhanced: %Schema{
              type: :boolean,
              description: "Whether enhanced AST data is included"
            },
            access_level: %Schema{
              type: :string,
              enum: ["demo", "full"],
              description: "Access level (demo without API key, full with valid API key)"
            }
          }
        }
      },
      required: [:patterns, :metadata],
      example: %{
        "patterns" => [
          %{
            "id" => "js-sql-injection-concat",
            "name" => "SQL Injection via String Concatenation",
            "type" => "sql_injection",
            "severity" => "high",
            "description" => "Detects SQL injection through string concatenation",
            "languages" => ["javascript", "typescript"],
            "cweId" => "CWE-89",
            "owaspCategory" => "A03:2021",
            "recommendation" => "Use parameterized queries"
          }
        ],
        "metadata" => %{
          "language" => "javascript",
          "format" => "standard",
          "count" => 1,
          "enhanced" => false,
          "access_level" => "demo"
        }
      }
    })
  end

  defmodule PatternStatsResponse do
    @moduledoc "Pattern statistics response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PatternStatsResponse",
      description: "Statistics about available patterns",
      type: :object,
      properties: %{
        total_patterns: %Schema{
          type: :integer,
          description: "Total number of patterns available",
          example: 448
        },
        by_language: %Schema{
          type: :object,
          description: "Pattern count by programming language",
          additionalProperties: %Schema{type: :integer},
          example: %{
            "javascript" => 123,
            "python" => 89,
            "ruby" => 72
          }
        },
        loaded_at: %Schema{
          type: :string,
          format: :"date-time",
          description: "When patterns were loaded",
          example: "2025-10-14T12:00:00Z"
        },
        access_model: %Schema{
          type: :object,
          description: "Access model information",
          properties: %{
            demo: %Schema{type: :string},
            full: %Schema{type: :string}
          }
        }
      },
      required: [:total_patterns, :by_language],
      example: %{
        "total_patterns" => 448,
        "by_language" => %{
          "javascript" => 123,
          "python" => 89,
          "ruby" => 72,
          "java" => 64
        },
        "loaded_at" => "2025-10-14T12:00:00Z",
        "access_model" => %{
          "demo" => "5 patterns per language",
          "full" => "All 448 patterns with API key"
        }
      }
    })
  end

  defmodule PatternMetadataResponse do
    @moduledoc "Detailed pattern metadata response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PatternMetadataResponse",
      description: "Detailed metadata for a specific pattern",
      type: :object,
      properties: %{
        pattern_id: %Schema{type: :string, description: "Pattern identifier"},
        description: %Schema{type: :string, description: "Detailed description"},
        references: %Schema{
          type: :array,
          items: %Schema{
            type: :object,
            properties: %{
              type: %Schema{
                type: :string,
                enum: ["cwe", "owasp", "cve", "nist", "sans", "article", "mdn", "stackoverflow"]
              },
              id: %Schema{type: :string},
              url: %Schema{type: :string, format: :uri}
            }
          },
          description: "External references"
        },
        attack_vectors: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Common attack vectors"
        },
        cve_examples: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Related CVE examples"
        },
        safe_alternatives: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Safe coding alternatives",
          nullable: true
        }
      }
    })
  end
end
