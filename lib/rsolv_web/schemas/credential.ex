defmodule RsolvWeb.Schemas.Credential do
  @moduledoc """
  OpenAPI schemas for credential exchange endpoints (GitHub Actions integration).
  """

  alias OpenApiSpex.Schema

  defmodule CredentialExchangeRequest do
    @moduledoc "Credential exchange request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CredentialExchangeRequest",
      description: "Request to exchange API key for temporary AI provider credentials",
      type: :object,
      properties: %{
        providers: %Schema{
          type: :array,
          items: %Schema{type: :string, enum: ["anthropic", "openai", "openrouter", "ollama"]},
          description: "List of AI providers to generate credentials for",
          example: ["anthropic", "openai"]
        },
        ttl_minutes: %Schema{
          type: :integer,
          description: "Time-to-live in minutes (max 240 = 4 hours)",
          minimum: 1,
          maximum: 240,
          example: 60
        }
      },
      required: [:providers],
      example: %{
        "providers" => ["anthropic", "openai"],
        "ttl_minutes" => 60
      }
    })
  end

  defmodule CredentialExchangeResponse do
    @moduledoc "Credential exchange response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CredentialExchangeResponse",
      description: "Temporary AI provider credentials with usage information",
      type: :object,
      properties: %{
        credentials: %Schema{
          type: :object,
          description: "Map of provider names to credential objects",
          additionalProperties: %Schema{
            type: :object,
            properties: %{
              api_key: %Schema{type: :string, description: "Temporary API key"},
              expires_at: %Schema{
                type: :string,
                format: :"date-time",
                description: "ISO 8601 expiration timestamp"
              }
            }
          },
          example: %{
            "anthropic" => %{
              "api_key" => "sk-ant-api03-...",
              "expires_at" => "2025-10-14T13:00:00Z"
            },
            "openai" => %{
              "api_key" => "sk-proj-...",
              "expires_at" => "2025-10-14T13:00:00Z"
            }
          }
        },
        usage: %Schema{
          type: :object,
          description: "Customer usage information",
          properties: %{
            remaining_fixes: %Schema{
              type: :integer,
              description: "Remaining fix quota this month"
            },
            reset_at: %Schema{
              type: :string,
              format: :"date-time",
              description: "When quota resets (first day of next month)"
            }
          }
        }
      },
      required: [:credentials, :usage],
      example: %{
        "credentials" => %{
          "anthropic" => %{
            "api_key" => "sk-ant-api03-...",
            "expires_at" => "2025-10-14T13:00:00Z"
          }
        },
        "usage" => %{
          "remaining_fixes" => 42,
          "reset_at" => "2025-11-01T00:00:00Z"
        }
      }
    })
  end

  defmodule CredentialRefreshRequest do
    @moduledoc "Credential refresh request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CredentialRefreshRequest",
      description: "Request to refresh temporary credentials that are about to expire",
      type: :object,
      properties: %{
        credential_id: %Schema{
          type: :string,
          description: "Credential identifier to refresh",
          example: "cred_abc123"
        }
      },
      required: [:credential_id],
      example: %{
        "credential_id" => "cred_abc123"
      }
    })
  end

  defmodule UsageReportRequest do
    @moduledoc "Usage reporting request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UsageReportRequest",
      description: "Report API usage for billing and quota tracking",
      type: :object,
      properties: %{
        provider: %Schema{
          type: :string,
          description: "AI provider",
          enum: ["anthropic", "openai", "openrouter", "ollama"],
          example: "anthropic"
        },
        tokens_used: %Schema{
          type: :integer,
          description: "Number of tokens consumed",
          example: 5000
        },
        request_count: %Schema{
          type: :integer,
          description: "Number of API requests made",
          example: 3
        },
        job_id: %Schema{
          type: :string,
          description: "Optional job identifier for tracking",
          nullable: true,
          example: "job_12345"
        }
      },
      required: [:provider, :tokens_used, :request_count],
      example: %{
        "provider" => "anthropic",
        "tokens_used" => 5000,
        "request_count" => 3,
        "job_id" => "job_12345"
      }
    })
  end

  defmodule UsageReportResponse do
    @moduledoc "Usage reporting response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UsageReportResponse",
      description: "Confirmation of usage recording",
      type: :object,
      properties: %{
        status: %Schema{
          type: :string,
          description: "Status of the recording",
          example: "recorded"
        }
      },
      required: [:status],
      example: %{
        "status" => "recorded"
      }
    })
  end
end
