defmodule Rsolv.EarlyAccess do
  @moduledoc """
  The EarlyAccess context for managing early access signups.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.EarlyAccess.Signup

  @doc """
  Creates a signup.
  """
  def create_signup(attrs \\ %{}) do
    result =
      %Signup{}
      |> Signup.changeset(attrs)
      |> Repo.insert()

    case result do
      {:ok, signup} ->
        # Trigger celebration metrics for Prometheus
        increment_signup_metrics(signup)
        {:ok, signup}

      error ->
        error
    end
  end

  # Increment Prometheus metrics for signup alerts
  defp increment_signup_metrics(signup) do
    alias RsolvWeb.Services.Metrics

    # Track standard signup metrics
    Metrics.count_signup()
    Metrics.count_signup_by_source(signup.utm_source || "direct")

    # Track celebration metrics
    Metrics.track_signup_event("new_signup")
    Metrics.track_signup_by_domain(signup.email)

    # Check if this is a milestone signup
    total = count_signups()

    if rem(total, 10) == 0 do
      Metrics.track_signup_event("milestone")
      Metrics.update_signup_milestone(total)
    end

    # Track high-value domains
    if is_high_value_domain?(signup.email) do
      Metrics.track_signup_event("high_value_signup")
    end
  end

  defp is_high_value_domain?(email) do
    high_value_domains = [
      "gitlab.com",
      "github.com",
      "microsoft.com",
      "google.com",
      "amazon.com",
      "meta.com",
      "netflix.com",
      "spotify.com"
    ]

    domain = get_email_domain(email)
    Enum.member?(high_value_domains, domain)
  end

  defp get_email_domain(email) do
    case String.split(email, "@") do
      [_, domain] -> domain
      _ -> "unknown"
    end
  end

  @doc """
  Gets a signup by email.
  """
  def get_signup_by_email(email) do
    Repo.get_by(Signup, email: email)
  end

  @doc """
  Returns the list of signups.
  """
  def list_signups do
    Repo.all(from s in Signup, order_by: [desc: s.inserted_at])
  end

  @doc """
  Returns the count of all signups.
  """
  def count_signups do
    Repo.aggregate(Signup, :count, :id)
  end

  @doc """
  Lists signups by referral source.
  """
  def list_signups_by_source(source) do
    Signup
    |> where([s], s.referral_source == ^source)
    |> order_by([s], desc: s.inserted_at)
    |> Repo.all()
  end

  @doc """
  Exports all signups to CSV format.
  """
  def export_to_csv do
    signups = list_signups()

    header =
      "email,name,company,referral_source,utm_source,utm_medium,utm_campaign,signed_up_at\n"

    rows =
      Enum.map(signups, fn signup ->
        ~s("#{signup.email}","#{signup.name || ""}","#{signup.company || ""}","#{signup.referral_source || ""}","#{signup.utm_source || ""}","#{signup.utm_medium || ""}","#{signup.utm_campaign || ""}","#{signup.inserted_at}")
      end)

    header <> Enum.join(rows, "\n")
  end

  @doc """
  Imports signups from CSV data.
  """
  def import_from_csv(csv_data) do
    lines = String.split(csv_data, "\n", trim: true)
    [_header | rows] = lines

    results =
      Enum.reduce(rows, %{imported: 0, errors: 0, details: []}, fn row, acc ->
        case parse_csv_row(row) do
          {:ok, attrs} ->
            case create_signup(attrs) do
              {:ok, _signup} ->
                %{acc | imported: acc.imported + 1}

              {:error, changeset} ->
                %{
                  acc
                  | errors: acc.errors + 1,
                    details: [format_error(attrs, changeset) | acc.details]
                }
            end

          {:error, reason} ->
            %{acc | errors: acc.errors + 1, details: [reason | acc.details]}
        end
      end)

    {:ok, results}
  end

  defp parse_csv_row(row) do
    # Use NimbleCSV or just split on commas for now
    fields = String.split(row, ",")

    case fields do
      [email, name, company, referral_source, utm_source, utm_medium, utm_campaign | _] ->
        {:ok,
         %{
           email: clean_csv_field(email),
           name: clean_csv_field(name),
           company: clean_csv_field(company),
           referral_source: clean_csv_field(referral_source),
           utm_source: clean_csv_field(utm_source),
           utm_medium: clean_csv_field(utm_medium),
           utm_campaign: clean_csv_field(utm_campaign)
         }}

      _ ->
        {:error, "Invalid CSV row: #{row}"}
    end
  end

  defp clean_csv_field(field) do
    field
    |> String.trim()
    |> String.trim("\"")
    |> case do
      "" -> nil
      value -> value
    end
  end

  defp format_error(attrs, changeset) do
    errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
    "Failed to import #{attrs.email}: #{inspect(errors)}"
  end

  @doc """
  Checks if an email already exists in the early access signups.
  """
  def email_exists?(email) do
    Signup
    |> where([s], s.email == ^email)
    |> Repo.exists?()
  end
end
