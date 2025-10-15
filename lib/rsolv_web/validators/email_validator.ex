defmodule RsolvWeb.Validators.EmailValidator do
  @moduledoc """
  Enhanced email validation module for the RSOLV application.
  Provides robust email validation with helpful error messages.
  """

  @doc """
  Validates an email address with comprehensive checks.

  ## Parameters
  - email: The email address to validate

  ## Returns
  - `true` if the email is valid, `false` otherwise
  """
  def is_valid?(email) do
    case validate_with_feedback(email) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Validates an email address and provides detailed feedback.

  ## Parameters
  - email: The email address to validate

  ## Returns
  - `{:ok, "Valid email"}` if the email is valid
  - `{:error, message}` with a descriptive error message if invalid
  - `{:error, nil}` if the email is empty (no error message)
  """
  def validate_with_feedback(email) do
    cond do
      # Empty validation
      email == nil || email == "" ->
        # No error message for empty
        {:error, nil}

      # Length check
      String.length(email) < 5 ->
        {:error, "Email is too short"}

      # Basic format check
      not String.contains?(email, "@") ->
        {:error, "Email must contain @"}

      # Basic pattern check - just check for basic structure
      not String.match?(email, ~r/^[^@\s]+@[^@\s]+$/) ->
        {:error, "Invalid email format"}

      # Enhanced validation
      true ->
        validate_enhanced(email)
    end
  end

  @doc """
  Performs enhanced validation on an email that passed basic checks.
  Catches common typos and domain issues.
  """
  def validate_enhanced(email) do
    # Common typos in TLD
    cond do
      String.ends_with?(email, ".con") ->
        {:error, "Did you mean .com?"}

      String.ends_with?(email, ".cmo") ->
        {:error, "Did you mean .com?"}

      String.ends_with?(email, ".xom") ->
        {:error, "Did you mean .com?"}

      String.ends_with?(email, ".ney") ->
        {:error, "Did you mean .net?"}

      String.ends_with?(email, ".ogr") ->
        {:error, "Did you mean .org?"}

      # Consecutive dots
      String.contains?(email, "..") ->
        {:error, "Email contains consecutive dots"}

      # Leading/trailing dots in local part
      String.starts_with?(email, ".") ->
        {:error, "Email can't start with a dot"}

      # Further domain validation
      true ->
        validate_domain(email)
    end
  end

  @doc """
  Validates the domain portion of an email address.
  """
  def validate_domain(email) do
    [_, domain] = String.split(email, "@", parts: 2)

    cond do
      String.contains?(domain, "--") ->
        {:error, "Domain contains consecutive hyphens"}

      String.starts_with?(domain, "-") ->
        {:error, "Domain can't start with a hyphen"}

      String.starts_with?(domain, ".") ->
        {:error, "Domain can't start with a dot"}

      String.ends_with?(domain, ".") ->
        {:error, "Domain can't end with a dot"}

      # Check if any part ends with hyphen
      domain |> String.split(".") |> Enum.any?(fn part -> String.ends_with?(part, "-") end) ->
        {:error, "Domain can't end with a hyphen"}

      # TLD validation
      validate_tld(domain) != :ok ->
        validate_tld(domain)

      # If we've passed all checks, the email is valid
      true ->
        {:ok, "Valid email"}
    end
  end

  @doc """
  Validates the Top-Level Domain (TLD) portion of a domain.
  """
  def validate_tld(domain) do
    parts = String.split(domain, ".")

    if length(parts) < 2 do
      {:error, "Domain must include a TLD (e.g., .com, .org)"}
    else
      tld = List.last(parts)

      cond do
        String.length(tld) < 2 ->
          {:error, "TLD is too short"}

        String.match?(tld, ~r/[^a-z]/i) ->
          {:error, "TLD should only contain letters"}

        true ->
          :ok
      end
    end
  end

  @doc """
  Suggests a correction for common email typos.

  ## Parameters
  - email: The potentially invalid email address

  ## Returns
  - The corrected email if a simple correction is possible
  - The original email if no simple correction is possible
  """
  def suggest_correction(email) do
    if not is_valid?(email) and is_binary(email) do
      cond do
        # Common TLD typos
        String.ends_with?(email, ".con") ->
          String.replace_suffix(email, ".con", ".com")

        String.ends_with?(email, ".cmo") ->
          String.replace_suffix(email, ".cmo", ".com")

        String.ends_with?(email, ".xom") ->
          String.replace_suffix(email, ".xom", ".com")

        String.ends_with?(email, ".ney") ->
          String.replace_suffix(email, ".ney", ".net")

        String.ends_with?(email, ".ogr") ->
          String.replace_suffix(email, ".ogr", ".org")

        # Double @ symbol - take the part before the first @ and after the last @
        String.match?(email, ~r/@.*@/) ->
          [local | rest] = String.split(email, "@")
          domain = List.last(rest)
          "#{local}@#{domain}"

        # Consecutive dots
        String.contains?(email, "..") ->
          String.replace(email, "..", ".")

        # Trailing dot in domain
        String.ends_with?(email, ".") ->
          String.slice(email, 0..-2//1)

        true ->
          email
      end
    else
      email
    end
  end
end
