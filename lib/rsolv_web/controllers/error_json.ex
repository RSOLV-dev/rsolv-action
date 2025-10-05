defmodule RsolvWeb.ErrorJSON do
  @moduledoc """
  This module is invoked by your endpoint in case of errors on JSON requests.

  See config/config.exs.
  """

  # If you want to customize a particular status code,
  # you may add your own clauses, such as:
  #
  # def render("500.json", _assigns) do
  #   %{errors: %{detail: "Internal Server Error"}}
  # end

  # Handle 401 authentication errors with structured format
  def render("401.json", %{error_code: error_code, message: message, request_id: request_id}) do
    %{
      error: %{
        code: error_code,
        message: message
      },
      requestId: request_id
    }
  end

  # Handle 403 forbidden errors with structured format
  def render("403.json", %{error_code: error_code, message: message, request_id: request_id}) do
    %{
      error: %{
        code: error_code,
        message: message
      },
      requestId: request_id
    }
  end

  # Handle 404 not found errors with structured format
  def render("404.json", %{error_code: error_code, message: message, request_id: request_id}) do
    %{
      error: %{
        code: error_code,
        message: message
      },
      requestId: request_id
    }
  end

  # Handle 400 bad request errors with structured format
  def render("400.json", %{error_code: error_code, message: message, request_id: request_id}) do
    %{
      error: %{
        code: error_code,
        message: message
      },
      requestId: request_id
    }
  end

  # Legacy format support (deprecated) - for backward compatibility during transition
  def render("401.json", %{error: error, message: message}) do
    %{
      error: error,
      message: message
    }
  end

  # By default, Phoenix returns the status message from
  # the template name. For example, "404.json" becomes
  # "Not Found".
  def render(template, _assigns) do
    %{errors: %{detail: Phoenix.Controller.status_message_from_template(template)}}
  end
end
