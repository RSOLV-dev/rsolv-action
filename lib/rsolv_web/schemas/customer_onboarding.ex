defmodule RsolvWeb.Schemas.CustomerOnboarding do
  @moduledoc """
  OpenAPI schemas for customer onboarding endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule OnboardingRequest do
    @moduledoc "Customer onboarding request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "OnboardingRequest",
      type: :object,
      properties: %{
        name: %Schema{
          type: :string,
          description: "Customer name or company name",
          example: "Acme Corp"
        },
        email: %Schema{
          type: :string,
          format: :email,
          description: "Customer email address",
          example: "admin@acme.com"
        }
      },
      required: [:name, :email],
      example: %{
        "name" => "Acme Corp",
        "email" => "admin@acme.com"
      }
    })
  end

  defmodule OnboardingResponse do
    @moduledoc "Customer onboarding response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "OnboardingResponse",
      type: :object,
      properties: %{
        customer: %Schema{
          type: :object,
          properties: %{
            id: %Schema{type: :integer, description: "Customer ID"},
            name: %Schema{type: :string, description: "Customer name"},
            email: %Schema{type: :string, format: :email, description: "Customer email"},
            trial_fixes_limit: %Schema{type: :integer, description: "Trial fixes limit"},
            trial_fixes_used: %Schema{type: :integer, description: "Trial fixes used"},
            subscription_plan: %Schema{type: :string, description: "Subscription plan"}
          }
        },
        api_key: %Schema{
          type: :string,
          description: "API key (returned only once, store securely)",
          example: "rsolv_abc123..."
        }
      },
      required: [:customer, :api_key],
      example: %{
        "customer" => %{
          "id" => 123,
          "name" => "Acme Corp",
          "email" => "admin@acme.com",
          "trial_fixes_limit" => 5,
          "trial_fixes_used" => 0,
          "subscription_plan" => "trial"
        },
        "api_key" => "rsolv_GD5KyzSXvKzaztds23HijV5HFnD7ZZs8cbF1UX5ks_8"
      }
    })
  end
end
