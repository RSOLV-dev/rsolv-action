defmodule RsolvWeb.ApiErrorCodes do
  @moduledoc """
  Centralized API error codes for consistent error responses.

  This module defines standard error codes used across all API endpoints
  to provide structured, machine-readable error responses.
  """

  @doc """
  Error code for missing API key authentication.
  """
  def auth_required, do: "AUTH_REQUIRED"

  @doc """
  Error code for invalid or expired API key.
  """
  def invalid_api_key, do: "INVALID_API_KEY"

  @doc """
  Error code for missing required parameters.
  """
  def missing_parameters, do: "MISSING_PARAMETERS"

  @doc """
  Error code for invalid request format.
  """
  def invalid_request, do: "INVALID_REQUEST"

  @doc """
  Error code for usage limit exceeded.
  """
  def usage_limit_exceeded, do: "USAGE_LIMIT_EXCEEDED"

  @doc """
  Error code for resource not found.
  """
  def not_found, do: "NOT_FOUND"

  @doc """
  Error code for forbidden access.
  """
  def forbidden, do: "FORBIDDEN"

  @doc """
  Error code for internal server error.
  """
  def internal_error, do: "INTERNAL_ERROR"

  @doc """
  Error code for rate limit exceeded.
  """
  def rate_limit_exceeded, do: "RATE_LIMIT_EXCEEDED"
end
