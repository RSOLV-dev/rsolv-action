defmodule Rsolv.EmailService do
  @moduledoc """
  Service for sending emails via Postmark.

  This module serves as the primary interface for sending transactional emails
  throughout the application. It abstracts away the email delivery implementation
  and provides a clean, consistent API for email operations.

  It also ensures that emails are not sent to users who have unsubscribed.
  """
  require Logger

  alias Rsolv.{Emails, Mailer, EmailOptOutService, EmailManagement}

  @doc """
  Send a welcome email to a new subscriber.
  This is the first email in the onboarding sequence.
  """
  def send_welcome_email(email, first_name \\ nil) do
    Logger.info("[EMAIL] send_welcome_email called",
      email: email,
      first_name: first_name,
      timestamp: DateTime.utc_now() |> DateTime.to_string()
    )

    email
    |> Emails.welcome_email(first_name)
    |> send_email()
  end

  @doc """
  Send an early access welcome email to a new early access program subscriber.
  This is the first email in the early access onboarding sequence.
  """
  def send_early_access_welcome_email(email, first_name \\ nil) do
    Logger.info("[EMAIL] send_early_access_welcome_email called",
      email: email,
      first_name: first_name,
      timestamp: DateTime.utc_now() |> DateTime.to_string()
    )

    email
    |> Emails.early_access_welcome_email(first_name)
    |> send_email()
  end

  @doc """
  Send a getting started email. This is typically sent 1 day after signup.
  """
  def send_getting_started_email(email, first_name \\ nil) do
    email
    |> Emails.getting_started_email(first_name)
    |> send_email()
  end

  @doc """
  Send a setup verification email. This is typically sent 2 days after signup.
  """
  def send_setup_verification_email(email, first_name \\ nil) do
    email
    |> Emails.setup_verification_email(first_name)
    |> send_email()
  end

  @doc """
  Send an email about submitting the first issue. This is typically sent 3 days after signup.
  """
  def send_first_issue_email(email, first_name \\ nil) do
    email
    |> Emails.first_issue_email(first_name)
    |> send_email()
  end

  @doc """
  Send a feature deep dive email. This is typically sent 5 days after signup.
  """
  def send_feature_deep_dive_email(email, first_name \\ nil) do
    email
    |> Emails.feature_deep_dive_email(first_name)
    |> send_email()
  end

  @doc """
  Send a feedback request email. This is typically sent 7 days after signup.
  """
  def send_feedback_request_email(email, first_name \\ nil) do
    email
    |> Emails.feedback_request_email(first_name)
    |> send_email()
  end

  @doc """
  Send a success check-in email. This is typically sent 14 days after signup.
  """
  def send_success_checkin_email(email, first_name \\ nil, usage_stats \\ nil) do
    email
    |> Emails.success_checkin_email(first_name, usage_stats)
    |> send_email()
  end

  @doc """
  Send a payment failed notification email to a customer.
  This is triggered when a subscription payment fails.
  """
  def send_payment_failed_email(
        customer_id,
        invoice_id,
        amount_due,
        next_payment_attempt \\ nil,
        attempt_count \\ 1
      ) do
    # Get the customer from the database
    customer = Rsolv.Customers.get_customer!(customer_id)

    # Build and send the email
    customer
    |> Emails.payment_failed_email(invoice_id, amount_due, next_payment_attempt, attempt_count)
    |> send_email()
  end

  @doc """
  Send a contact form notification email to admins.
  This is sent when a user submits the contact form.

  Contact data should include:
  - name: Contact's name
  - email: Contact's email
  - company: Company name (optional)
  - message: Message content
  - team_size: Team size (optional)
  - timestamp: Submission timestamp
  - source: Form source identifier
  """
  def send_contact_form_notification(contact_data) do
    Logger.info("[EMAIL] send_contact_form_notification called",
      email: contact_data[:email] || contact_data["email"],
      source: contact_data[:source] || contact_data["source"],
      timestamp: DateTime.utc_now() |> DateTime.to_string()
    )

    # Note: Contact form emails are admin notifications and don't need unsubscribe checking
    # They go to admin@rsolv.dev, not to the contact's email
    contact_data
    |> Emails.contact_form_notification()
    |> send_email_without_unsubscribe_check()
  end

  @doc """
  Send an admin notification email for new signups.
  This is sent when a user signs up for early access.

  Signup data should include:
  - email: User's email
  - company: Company name (optional)
  - timestamp: Signup timestamp
  - source: Signup source identifier
  - utm_source, utm_medium, utm_campaign: UTM parameters (optional)
  - referrer: Referrer URL (optional)
  """
  def send_admin_signup_notification(signup_data) do
    Logger.info("[EMAIL] send_admin_signup_notification called",
      email: signup_data[:email] || signup_data["email"],
      source: signup_data[:source] || signup_data["source"],
      timestamp: DateTime.utc_now() |> DateTime.to_string()
    )

    # Note: Admin notification emails don't need unsubscribe checking
    # They go to admin@rsolv.dev, not to the signup email
    signup_data
    |> Emails.admin_signup_notification()
    |> send_email_without_unsubscribe_check()
  end

  # Private helper to send email via Bamboo and log activity
  defp send_email(email) do
    timestamp = utc_timestamp()
    recipient_email = extract_recipient_email(email)

    log_email_debug(email, recipient_email, timestamp)

    if recipient_email && EmailOptOutService.is_unsubscribed?(recipient_email) do
      log_unsubscribed_skip(recipient_email, email.subject, timestamp)
      {:skipped, %{status: "unsubscribed", message: "Recipient has unsubscribed"}}
    else
      deliver_email(email, timestamp)
    end
  end

  # Private helper to send email without unsubscribe checking (for admin notifications)
  # This is used for emails sent TO admins (not FROM users), which should not be affected by user unsubscribes
  defp send_email_without_unsubscribe_check(email) do
    timestamp = utc_timestamp()

    Logger.info("[EMAIL DEBUG] Full email struct before sending (no unsubscribe check)",
      email_struct: inspect(email),
      timestamp: timestamp
    )

    deliver_email(email, timestamp)
  end

  ## Core delivery logic

  # Delivers the email through Mailer with configuration validation and error handling
  defp deliver_email(email, timestamp) do
    config = get_mailer_config()
    current_env = Application.get_env(:rsolv, :env) || :prod

    log_mailer_config(config, current_env, timestamp)

    try do
      log_sending_attempt(email, timestamp)

      with :ok <- validate_adapter_for_environment(config, current_env, timestamp),
           {:ok, email_result} <- send_via_mailer(email) do
        log_sending_success(email, email_result, timestamp)
        {:ok, %{status: "sent", email: email_result}}
      end
    rescue
      error ->
        log_sending_error(email, error, __STACKTRACE__, timestamp)
        log_failed_email(email)
        {:error, %{status: "send_failed", message: "Failed to send email", error: error}}
    end
  end

  # Sends email via Mailer and unwraps the result
  defp send_via_mailer(email) do
    Application.ensure_all_started(:hackney)

    email
    |> Mailer.deliver_now()
    |> unwrap_mailer_result()
    |> then(&{:ok, &1})
  end

  # Unwraps result from Mailer - some adapters return {:ok, email}, others return email directly
  defp unwrap_mailer_result({:ok, email}), do: email
  defp unwrap_mailer_result(email), do: email

  # Validates that test adapter is not used in production
  defp validate_adapter_for_environment(config, env, timestamp) do
    if config[:adapter] == Bamboo.TestAdapter && env != :test do
      Logger.error("[EMAIL ERROR] Test adapter detected in non-test environment!",
        adapter: inspect(config[:adapter]),
        environment: env,
        timestamp: timestamp
      )

      {:error, %{status: "configuration_error", message: "Test adapter configured in production"}}
    else
      :ok
    end
  end

  ## Configuration helpers

  defp get_mailer_config, do: Application.get_env(:rsolv, Rsolv.Mailer)

  defp get_email_config, do: Application.get_env(:rsolv, :email_config, %{})

  defp mask_api_key(nil), do: "NOT_CONFIGURED"

  defp mask_api_key(api_key) do
    first_four = String.slice(api_key, 0..3)
    last_four = String.slice(api_key, -4..-1)
    "#{first_four}...#{last_four}"
  end

  ## Logging helpers

  defp utc_timestamp, do: DateTime.utc_now() |> DateTime.to_string()

  defp log_email_debug(email, recipient_email, timestamp) do
    Logger.info("[EMAIL DEBUG] Full email struct before sending",
      email_struct: inspect(email),
      timestamp: timestamp
    )

    Logger.info("[EMAIL DEBUG] Extracted recipient email",
      recipient_email: recipient_email,
      email_to_field: inspect(email.to),
      timestamp: timestamp
    )

    email_config = get_email_config()

    Logger.info("[EMAIL DEBUG] Email configuration",
      sender_email: Map.get(email_config, :sender_email),
      sender_name: Map.get(email_config, :sender_name),
      reply_to: Map.get(email_config, :reply_to),
      from_field: inspect(email.from),
      timestamp: timestamp
    )
  end

  defp log_unsubscribed_skip(recipient_email, subject, timestamp) do
    Logger.info("[EMAIL] Skipping email to unsubscribed recipient",
      to: recipient_email,
      subject: subject,
      timestamp: timestamp
    )
  end

  defp log_mailer_config(config, env, timestamp) do
    api_key = config[:api_key]

    Logger.info("[EMAIL DEBUG] Postmark configuration",
      adapter: config[:adapter],
      adapter_module: inspect(config[:adapter]),
      is_test_adapter: config[:adapter] == Bamboo.TestAdapter,
      api_key_configured: api_key != nil,
      api_key_masked: mask_api_key(api_key),
      postmark_base_uri: Application.get_env(:bamboo, :postmark_base_uri),
      environment: env,
      timestamp: timestamp
    )
  end

  defp log_sending_attempt(email, timestamp) do
    Logger.info("[EMAIL] Attempting to send email via Postmark",
      to: email.to,
      subject: email.subject,
      message_id: email.headers["Message-ID"],
      tag: email.headers["X-Postmark-Tag"],
      timestamp: timestamp
    )
  end

  defp log_sending_success(email, email_result, timestamp) do
    result_type =
      case email_result do
        %{__struct__: struct} -> inspect(struct)
        _ -> "not a struct"
      end

    Logger.info("[EMAIL DEBUG] Raw Postmark response",
      result: inspect(email_result),
      result_type: result_type,
      timestamp: timestamp
    )

    Logger.info("[EMAIL] Email sent successfully via Postmark",
      to: email.to,
      subject: email.subject,
      timestamp: timestamp
    )
  end

  defp log_sending_error(email, error, stacktrace, timestamp) do
    Logger.error("[EMAIL ERROR] Failed to send email via Postmark",
      to: email.to,
      subject: email.subject,
      error_message: Exception.message(error),
      error_type: error.__struct__,
      error_details: inspect(error),
      stacktrace: Exception.format_stacktrace(stacktrace),
      timestamp: timestamp
    )
  end

  ## Email extraction and persistence helpers

  # Helper to extract recipient email from a Bamboo.Email struct
  defp extract_recipient_email(email) do
    case email.to do
      [{_, email_address}] -> email_address
      [email_address] when is_binary(email_address) -> email_address
      email_address when is_binary(email_address) -> email_address
      _ -> nil
    end
  end

  # Log a failed email attempt for potential retry
  defp log_failed_email(email) do
    to_email = extract_recipient_email(email) || "unknown"

    attrs = %{
      to_email: to_email,
      subject: email.subject || "No subject",
      template: email.private[:template_name] || "unknown",
      error_message: "Email delivery failed",
      email_data: %{
        from: format_from_field(email.from),
        to: email.to,
        subject: email.subject,
        timestamp: utc_timestamp()
      }
    }

    case EmailManagement.create_failed_email(attrs) do
      {:ok, failed_email} ->
        Logger.info("Failed email logged for potential retry",
          metadata: %{id: failed_email.id, email: to_email}
        )

      {:error, changeset} ->
        Logger.error("Could not log failed email to database",
          email: to_email,
          errors: inspect(changeset.errors)
        )
    end
  end

  defp format_from_field({name, email}), do: "#{name} <#{email}>"
  defp format_from_field(email) when is_binary(email), do: email
  defp format_from_field(_), do: "unknown@rsolv.dev"
end
