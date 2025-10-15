defmodule RsolvWeb.FallbackController do
  @moduledoc """
  Translates controller action results into valid `Plug.Conn` responses.

  See `Phoenix.Controller.action_fallback/1` for more details.
  """
  use RsolvWeb, :controller

  # This clause handles errors returned by Ecto's insert/update/delete.
  def call(conn, {:error, %Ecto.Changeset{} = changeset}) do
    conn
    |> put_status(:unprocessable_entity)
    |> put_view(json: RsolvWeb.ChangesetJSON)
    |> render(:error, changeset: changeset)
  end

  # This clause handles errors returned when not found.
  def call(conn, {:error, :not_found}) do
    conn
    |> put_status(:not_found)
    |> put_view(json: RsolvWeb.ErrorJSON)
    |> render(:"404")
  end

  # This clause handles unauthorized namespace access
  def call(conn, {:error, :unauthorized}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Unauthorized: no access to namespace"})
  end

  # This clause handles forbidden errors.
  def call(conn, {:error, :forbidden}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: RsolvWeb.ErrorJSON)
    |> render(:"403")
  end

  # This clause handles missing API key errors.
  def call(conn, {:error, :missing_api_key}) do
    conn
    |> put_status(:unauthorized)
    |> json(%{error: "API key required"})
  end

  # This clause handles phase-specific errors
  def call(conn, {:error, :phase_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Phase is required"})
  end

  def call(conn, {:error, :repo_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Repository is required"})
  end

  def call(conn, {:error, :commit_sha_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Commit SHA is required"})
  end

  def call(conn, {:error, :issue_number_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Issue number is required for validation and mitigation phases"})
  end

  def call(conn, {:error, :invalid_phase}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Invalid phase. Must be 'scan', 'validation', or 'mitigation'"})
  end

  def call(conn, {:error, :issue_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Issue number is required"})
  end

  def call(conn, {:error, :commit_required}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Commit SHA is required"})
  end

  def call(conn, {:error, :invalid_issue_number}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Invalid issue number format"})
  end

  def call(conn, {:error, :forge_not_verified}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Forge account not verified"})
  end

  # This clause handles invalid API key errors.
  def call(conn, {:error, :invalid_api_key}) do
    conn
    |> put_status(:unauthorized)
    |> json(%{error: "Invalid API key"})
  end

  # This clause handles AI access denied errors.
  def call(conn, {:error, :ai_access_denied}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "AI pattern access not enabled for this account"})
  end

  # This clause handles enterprise access denied errors.
  def call(conn, {:error, :enterprise_access_denied}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Enterprise tier required"})
  end

  # This clause handles public patterns disabled errors.
  def call(conn, {:error, :public_patterns_disabled}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Public patterns are currently disabled"})
  end

  # Catch-all clause for other errors
  def call(conn, {:error, message}) when is_binary(message) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: message})
  end
end
