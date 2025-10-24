defmodule RsolvWeb.Api.V1.CustomerOnboardingController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Rsolv.CustomerOnboarding
  alias RsolvWeb.Schemas.CustomerOnboarding.{OnboardingRequest, OnboardingResponse}
  alias RsolvWeb.Schemas.Error.ErrorResponse

  tags ["Customer Onboarding"]

  operation(:onboard,
    summary: "Provision a new customer account",
    description: """
    Creates a new customer account with automatic provisioning.

    **Features:**
    - Creates customer record with trial credits (5 fixes)
    - Generates secure API key (returned only once)
    - Sets up billing defaults
    - Initializes onboarding wizard preference

    **Trial Credits:**
    - 5 fixes on signup
    - +5 fixes (total 10) when payment method added
    - After 10 fixes → Pay-as-you-go at $29/fix

    **Rate Limiting:** 10 requests per IP per hour (planned - not yet implemented)
    """,
    request_body: {"Onboarding request", "application/json", OnboardingRequest},
    responses: [
      created: {"Customer created successfully", "application/json", OnboardingResponse},
      bad_request: {"Invalid request", "application/json", ErrorResponse},
      unprocessable_entity: {"Validation failed", "application/json", ErrorResponse},
      too_many_requests: {"Rate limit exceeded", "application/json", ErrorResponse}
    ]
  )

  def onboard(conn, params) do
    case CustomerOnboarding.provision_customer(params) do
      {:ok, %{customer: customer, api_key: api_key}} ->
        conn
        |> put_status(:created)
        |> json(%{
          customer: %{
            id: customer.id,
            name: customer.name,
            email: customer.email,
            trial_fixes_limit: customer.trial_fixes_limit,
            trial_fixes_used: customer.trial_fixes_used,
            subscription_plan: customer.subscription_plan
          },
          api_key: api_key
        })

      {:error, {:validation_failed, changeset}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: %{
            message: format_changeset_errors(changeset),
            code: "VALIDATION_FAILED"
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: %{
            message: "Failed to provision customer: #{inspect(reason)}",
            code: "PROVISIONING_FAILED"
          }
        })
    end
  end

  # Format Ecto changeset errors into a human-readable string
  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} ->
      "#{field} #{Enum.join(errors, ", ")}"
    end)
    |> Enum.join("; ")
  end
end
