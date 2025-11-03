defmodule Rsolv.ConvertKitTestHelpers do
  @moduledoc """
  Shared test helpers for mocking ConvertKit API interactions.

  Provides reusable setup functions to stub ConvertKit HTTP calls,
  preventing Mox.UnexpectedCallError in tests that trigger email
  sequences with ConvertKit tagging.

  ## Usage

      use Rsolv.DataCase
      import Rsolv.ConvertKitTestHelpers

      setup do
        stub_convertkit_success()
        :ok
      end
  """

  import Mox

  @doc """
  Configures ConvertKit with test credentials and stubs HTTP client
  to return successful responses for all ConvertKit API calls.

  This is the most common setup needed for tests that trigger customer
  onboarding or email sequences.

  ## Examples

      setup do
        stub_convertkit_success()
        :ok
      end
  """
  def stub_convertkit_success do
    configure_convertkit()

    stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
      {:ok, success_response()}
    end)
  end

  @doc """
  Configures ConvertKit with test credentials only, without stubbing HTTP client.

  Use this when you need more control over the mock expectations.

  ## Examples

      setup do
        configure_convertkit()

        expect(Rsolv.HTTPClientMock, :post, fn url, _body, _headers, _options ->
          if String.contains?(url, "/tags/"), do: {:ok, tag_response()}, else: {:ok, success_response()}
        end)

        :ok
      end
  """
  def configure_convertkit do
    Application.put_env(:rsolv, :convertkit,
      api_key: "test_api_key",
      form_id: "test_form_id",
      early_access_tag_id: "7700607",
      tag_onboarding: "7700607",
      api_base_url: "https://api.convertkit.com/v3"
    )
  end

  @doc """
  Returns a successful ConvertKit API response for subscriber operations.
  """
  def success_response do
    %HTTPoison.Response{
      status_code: 200,
      body: Jason.encode!(%{"subscription" => %{"id" => 123_456}})
    }
  end

  @doc """
  Returns a successful ConvertKit API response for tag operations.

  Alias for success_response/0 - ConvertKit uses the same response format
  for both subscriber and tag operations.
  """
  def tag_response, do: success_response()

  @doc """
  Returns an error response for testing failure scenarios.

  ## Options

  * `:status_code` - HTTP status code (default: 422)
  * `:error_message` - Error message (default: "API error")

  ## Examples

      stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
        {:ok, error_response(status_code: 401, error_message: "Invalid API key")}
      end)
  """
  def error_response(opts \\ []) do
    status_code = Keyword.get(opts, :status_code, 422)
    error_message = Keyword.get(opts, :error_message, "API error")

    %HTTPoison.Response{
      status_code: status_code,
      body: Jason.encode!(%{"error" => error_message})
    }
  end
end
