defmodule RsolvWeb.Schemas.Credential do
  @moduledoc """
  OpenAPI schemas for credential exchange endpoints (GitHub Actions integration).
  """

  alias OpenApiSpex.Schema

  defmodule CredentialExchangeRequest do
    @moduledoc """
    Credential exchange request

    ## Examples

    ### Single Provider (Anthropic Only)
    ```json
    {
      "providers": ["anthropic"],
      "ttl_minutes": 60
    }
    ```

    ### Multiple Providers
    ```json
    {
      "providers": ["anthropic", "openai"],
      "ttl_minutes": 120
    }
    ```

    ### Maximum TTL (4 hours for long-running jobs)
    ```json
    {
      "providers": ["anthropic", "openai", "openrouter"],
      "ttl_minutes": 240
    }
    ```

    ### Ollama (Local Model) + Cloud Fallback
    ```json
    {
      "providers": ["ollama", "anthropic"],
      "ttl_minutes": 180
    }
    ```

    ## GitHub Actions Integration

    ### Complete Workflow Example
    ```yaml
    name: RSOLV Security Scan

    on:
      push:
        branches: [main, develop]
      pull_request:
        branches: [main]

    jobs:
      security-scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: Exchange for AI Credentials
            id: rsolv-creds
            run: |
              response=$(curl -X POST https://api.rsolv.dev/api/v1/credentials/exchange \\
                -H "Authorization: Bearer $RSOLV_API_KEY" \\
                -H "Content-Type: application/json" \\
                -d '{
                  "providers": ["anthropic", "openai"],
                  "ttl_minutes": 120
                }')

              # Extract credentials
              anthropic_key=$(echo "$response" | jq -r '.credentials.anthropic.api_key')
              openai_key=$(echo "$response" | jq -r '.credentials.openai.api_key')
              remaining=$(echo "$response" | jq -r '.usage.remaining_fixes')

              # Set as outputs (masked)
              echo "::add-mask::$anthropic_key"
              echo "::add-mask::$openai_key"
              echo "anthropic_key=$anthropic_key" >> $GITHUB_OUTPUT
              echo "openai_key=$openai_key" >> $GITHUB_OUTPUT
              echo "remaining_fixes=$remaining" >> $GITHUB_OUTPUT
            env:
              RSOLV_API_KEY: ${{ secrets.RSOLV_API_KEY }}

          - name: Run RSOLV Security Analysis
            run: |
              # Use temporary credentials
              npx @rsolv/action scan \\
                --anthropic-key "$ANTHROPIC_KEY" \\
                --openai-key "$OPENAI_KEY" \\
                --report-path ./security-report.json
            env:
              ANTHROPIC_KEY: ${{ steps.rsolv-creds.outputs.anthropic_key }}
              OPENAI_KEY: ${{ steps.rsolv-creds.outputs.openai_key }}

          - name: Check Remaining Quota
            run: |
              echo "Remaining fixes this month: ${{ steps.rsolv-creds.outputs.remaining_fixes }}"
    ```

    ### Using RSOLV GitHub Action (Simplified)
    ```yaml
    name: RSOLV Security Scan (Action)

    on: [push, pull_request]

    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: RSOLV Security Scan
            uses: rsolv-dev/rsolv-action@v3
            with:
              api-key: ${{ secrets.RSOLV_API_KEY }}
              providers: 'anthropic,openai'
              ttl-minutes: 120
              scan-path: './src'
    ```

    ## Client Code Examples

    ### JavaScript (GitHub Actions Context)
    ```javascript
    const axios = require('axios');
    const core = require('@actions/core');

    async function getCredentials(apiKey, providers, ttlMinutes) {
      try {
        const response = await axios.post(
          'https://api.rsolv.dev/api/v1/credentials/exchange',
          {
            providers: providers,
            ttl_minutes: ttlMinutes
          },
          {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
              'X-GitHub-Workflow': process.env.GITHUB_WORKFLOW || '',
              'X-GitHub-Repository': process.env.GITHUB_REPOSITORY || '',
              'X-GitHub-Run-ID': process.env.GITHUB_RUN_ID || ''
            }
          }
        );

        // Mask credentials in logs
        Object.values(response.data.credentials).forEach(cred => {
          core.setSecret(cred.api_key);
        });

        return response.data;
      } catch (error) {
        core.setFailed(`Failed to exchange credentials: ${error.message}`);
        throw error;
      }
    }

    // Usage
    const result = await getCredentials(
      process.env.RSOLV_API_KEY,
      ['anthropic', 'openai'],
      120
    );

    console.log(`Got credentials for: ${Object.keys(result.credentials).join(', ')}`);
    console.log(`Remaining fixes: ${result.usage.remaining_fixes}`);
    console.log(`Quota resets: ${result.usage.reset_at}`);
    ```

    ### Python (Generic)
    ```python
    import requests
    import os
    from datetime import datetime

    def exchange_credentials(api_key, providers, ttl_minutes=60):
        response = requests.post(
            'https://api.rsolv.dev/api/v1/credentials/exchange',
            json={
                'providers': providers,
                'ttl_minutes': ttl_minutes
            },
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
        )

        response.raise_for_status()
        data = response.json()

        # Check quota
        remaining = data['usage']['remaining_fixes']
        if remaining == 0:
            reset_at = datetime.fromisoformat(data['usage']['reset_at'].replace('Z', '+00:00'))
            raise Exception(f'No remaining fixes. Quota resets at {reset_at}')

        return data

    # Usage
    result = exchange_credentials(
        os.environ['RSOLV_API_KEY'],
        ['anthropic', 'openai'],
        ttl_minutes=120
    )

    # Extract credentials
    anthropic_key = result['credentials']['anthropic']['api_key']
    openai_key = result['credentials']['openai']['api_key']

    print(f"Credentials expire at: {result['credentials']['anthropic']['expires_at']}")
    print(f"Remaining quota: {result['usage']['remaining_fixes']}")
    ```

    ### cURL (Direct)
    ```bash
    # Exchange credentials
    curl -X POST https://api.rsolv.dev/api/v1/credentials/exchange \\
      -H "Authorization: Bearer $RSOLV_API_KEY" \\
      -H "Content-Type: application/json" \\
      -H "X-GitHub-Workflow: security-scan" \\
      -H "X-GitHub-Repository: myorg/myrepo" \\
      -d '{
        "providers": ["anthropic", "openai"],
        "ttl_minutes": 120
      }' | jq '.'

    # Expected response:
    # {
    #   "credentials": {
    #     "anthropic": {
    #       "api_key": "sk-ant-api03-...",
    #       "expires_at": "2025-10-14T15:00:00Z"
    #     },
    #     "openai": {
    #       "api_key": "sk-proj-...",
    #       "expires_at": "2025-10-14T15:00:00Z"
    #     }
    #   },
    #   "usage": {
    #     "remaining_fixes": 42,
    #     "reset_at": "2025-11-01T00:00:00Z"
    #   }
    # }
    ```

    ## Token Refresh Flow

    When credentials are about to expire (within 10 minutes), you can refresh them:

    ```bash
    # First exchange
    response=$(curl -X POST https://api.rsolv.dev/api/v1/credentials/exchange \\
      -H "Authorization: Bearer $API_KEY" \\
      -d '{"providers": ["anthropic"], "ttl_minutes": 60}')

    cred_id=$(echo "$response" | jq -r '.credentials.anthropic.credential_id')

    # Later, refresh before expiration
    curl -X POST https://api.rsolv.dev/api/v1/credentials/refresh \\
      -H "Authorization: Bearer $API_KEY" \\
      -d "{\"credential_id\": \"$cred_id\"}"
    ```
    """
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
