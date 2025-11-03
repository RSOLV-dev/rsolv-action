defmodule Rsolv.ConvertKitTestHelpers do
  @moduledoc """
  Shared test helpers for mocking ConvertKit API interactions.

  Provides reusable setup functions to stub ConvertKit HTTP calls,
  preventing Mox.UnexpectedCallError in tests that trigger email
  sequences with ConvertKit tagging.

  ## Usage

  ### Simple usage (most common):

      use Rsolv.DataCase
      import Rsolv.ConvertKitTestHelpers

      setup :stub_convertkit_success

  ### Alternative (if you need to do other setup):

      setup do
        stub_convertkit_success()
        # other setup...
        :ok
      end
  """

  import Mox

  @test_config [
    api_key: "test_api_key",
    form_id: "test_form_id",
    early_access_tag_id: "7700607",
    tag_onboarding: "7700607",
    api_base_url: "https://api.convertkit.com/v3"
  ]

  @doc """
  Configures ConvertKit with test credentials and stubs HTTP client
  to return successful responses for all ConvertKit API calls.

  This is the most common setup needed for tests that trigger customer
  onboarding or email sequences.

  Can be used as a setup callback (accepts context) or called directly.

  ## Examples

      # As a setup callback:
      setup :stub_convertkit_success

      # Or called directly:
      setup do
        stub_convertkit_success()
        :ok
      end
  """
  def stub_convertkit_success(_context \\ %{}) do
    configure_convertkit()

    stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
      {:ok, fixtures().tag_success}
    end)

    :ok
  end

  @doc """
  Configures ConvertKit with test credentials only, without stubbing HTTP client.

  Use this when you need more control over the mock expectations.

  ## Examples

      setup do
        configure_convertkit()

        expect(Rsolv.HTTPClientMock, :post, fn url, _body, _headers, _options ->
          cond do
            String.contains?(url, "/tags/") -> {:ok, fixtures().tag_success}
            String.contains?(url, "/subscribers") -> {:ok, fixtures().subscription_success}
            true -> {:ok, fixtures().subscription_form_not_found}
          end
        end)

        :ok
      end
  """
  def configure_convertkit do
    Application.put_env(:rsolv, :convertkit, @test_config)
  end

  @doc """
  Returns ConvertKit test fixtures from RsolvWeb.Mocks.

  Provides access to predefined response fixtures for various scenarios:
  - `subscription_success` - Successful subscriber creation
  - `tag_success` - Successful tag application
  - `subscription_form_not_found` - Form not found error
  - `subscription_unauthorized` - Authentication error
  - `tag_not_found` - Tag not found error
  - `network_error` - Network connection error
  """
  defdelegate fixtures, to: RsolvWeb.Mocks, as: :convertkit_fixtures
end
