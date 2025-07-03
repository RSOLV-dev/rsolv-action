defmodule RsolvWeb.Mocks do
  @moduledoc """
  Mocks for external services like ConvertKit API.
  """
  
  # Define mocks for external services
  Mox.defmock(RsolvWeb.HTTPoisonMock, for: HTTPoison.Base)
  Mox.defmock(Rsolv.HTTPClientMock, for: HTTPoison.Base)
  
  # Define test data
  def convertkit_fixtures do
    %{
      # Successful subscription response
      subscription_success: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscription" => %{
            "id" => 123456789,
            "state" => "active",
            "source" => "API",
            "created_at" => "2023-05-01T12:00:00Z",
            "subscriber" => %{
              "id" => 987654321,
              "email_address" => "test@example.com"
            }
          }
        })
      },

      # Failed subscription response (already subscribed)
      subscription_already_exists: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscription" => %{
            "id" => 123456789,
            "state" => "active",
            "source" => "API"
          }
        })
      },

      # Failed subscription response (invalid form)
      subscription_form_not_found: %HTTPoison.Response{
        status_code: 404,
        body: Jason.encode!(%{
          "error" => "Form not found"
        })
      },

      # Failed subscription response (invalid API key)
      subscription_unauthorized: %HTTPoison.Response{
        status_code: 401,
        body: Jason.encode!(%{
          "error" => "Unauthorized"
        })
      },

      # Successful tag response
      tag_success: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscription" => %{
            "id" => 123456789,
            "subscriber" => %{
              "id" => 987654321,
              "email_address" => "test@example.com"
            }
          }
        })
      },

      # Failed tag response (tag not found)
      tag_not_found: %HTTPoison.Response{
        status_code: 404,
        body: Jason.encode!(%{
          "error" => "Tag not found"
        })
      },

      # Subscriber lookup response
      subscriber_lookup_success: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscribers" => [
            %{
              "id" => 987654321,
              "email_address" => "test@example.com",
              "state" => "active",
              "created_at" => "2023-05-01T12:00:00Z"
            }
          ]
        })
      },

      # Empty subscriber lookup response
      subscriber_lookup_empty: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscribers" => []
        })
      },

      # Successful unsubscribe response
      unsubscribe_success: %HTTPoison.Response{
        status_code: 200,
        body: Jason.encode!(%{
          "subscriber" => %{
            "id" => 987654321,
            "state" => "cancelled"
          }
        })
      },

      # Network error
      network_error: {:error, %HTTPoison.Error{reason: :econnrefused}}
    }
  end
  
  # Helper for setting up mocks in tests
  def setup_convertkit_mocks do
    fixtures = convertkit_fixtures()
    
    # Setup successful subscription and tag API calls
    Mox.stub(RsolvWeb.HTTPoisonMock, :post, fn url, _body, _headers, _options ->
      cond do
        String.contains?(url, "/subscribers") ->
          {:ok, fixtures.subscription_success}
          
        String.contains?(url, "/forms/") && String.contains?(url, "/subscribe") ->
          {:ok, fixtures.subscription_success}
          
        String.contains?(url, "/tags/") && String.contains?(url, "/subscribe") ->
          {:ok, fixtures.tag_success}
          
        true ->
          {:ok, %HTTPoison.Response{status_code: 404, body: "Not found"}}
      end
    end)
  end
  
  # Helper to setup Mox for ConvertKit API testing
  def setup_mox_for_convertkit do
    # Configure the application to use our mock
    Application.put_env(:rsolv, :convertkit, [
      api_key: "test_api_key",
      form_id: "test_form_id", 
      early_access_tag_id: "test_tag_id",
      api_base_url: "http://localhost:4000/v3"  # Fixed port instead of bypass.port
    ])
    
    # Set up the mock to be used by the current process
    Mox.stub_with(Rsolv.HTTPClientMock, RsolvWeb.Mocks)
    
    :ok
  end
  
  # Implement HTTPoison.Base behavior for mocking
  def post(url, _body, _headers \\ [], _options \\ []) do
    cond do
      String.contains?(url, "/v3/subscribers") ->
        convertkit_fixtures().subscription_success
      
      String.contains?(url, "/v3/tags/") and String.contains?(url, "/subscribe") ->
        convertkit_fixtures().subscription_success
      
      true ->
        convertkit_fixtures().subscription_form_not_found
    end
  end
  
  def get(_url, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def put(_url, _body, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def delete(_url, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def head(_url, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def patch(_url, _body, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def options(_url, _headers \\ [], _options \\ []) do
    convertkit_fixtures().subscription_success
  end
  
  def request(_request) do
    convertkit_fixtures().subscription_success
  end
  
  # Helper functions for test setup
  def setup_subscription_success do
    Mox.stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
      convertkit_fixtures().subscription_success
    end)
  end
  
  def setup_tag_success(tag_id \\ "test_tag_id") do
    Mox.stub(Rsolv.HTTPClientMock, :post, fn url, _body, _headers, _options ->
      if String.contains?(url, "/v3/tags/#{tag_id}/subscribe") do
        convertkit_fixtures().subscription_success
      else
        convertkit_fixtures().subscription_form_not_found
      end
    end)
  end
  
  def setup_subscription_error(status_code \\ 401) do
    error_response = %HTTPoison.Response{
      status_code: status_code,
      body: Jason.encode!(%{"error" => "Unauthorized"})
    }
    
    Mox.stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
      error_response
    end)
  end
  
  def setup_tag_error(tag_id \\ "test_tag_id", status_code \\ 404) do
    error_response = %HTTPoison.Response{
      status_code: status_code,
      body: Jason.encode!(%{"error" => "Tag not found"})
    }
    
    Mox.stub(Rsolv.HTTPClientMock, :post, fn url, _body, _headers, _options ->
      if String.contains?(url, "/v3/tags/#{tag_id}/subscribe") do
        error_response
      else
        convertkit_fixtures().subscription_form_not_found
      end
    end)
  end
end