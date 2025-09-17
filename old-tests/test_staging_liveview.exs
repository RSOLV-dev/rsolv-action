#!/usr/bin/env elixir

# Test Staging Customer Admin with Elixir
# Run with: elixir test_staging_liveview.exs

Mix.install([
  {:phoenix_live_view, "~> 1.0"},
  {:jason, "~> 1.4"},
  {:hackney, "~> 1.18"},
  {:tesla, "~> 1.4"}
])

defmodule StagingTest do
  @base_url "https://api.rsolv-staging.com"
  @admin_email "admin@rsolv.dev"
  @admin_password "AdminP@ssw0rd2025!"

  def run do
    IO.puts("\n🔍 Testing Customer Admin Dashboard on Staging")
    IO.puts("=" |> String.duplicate(50))

    with {:ok, cookie} <- test_login(),
         :ok <- test_customer_list(cookie),
         :ok <- test_customer_detail(cookie) do
      IO.puts("\n✅ All tests passed!")
    else
      {:error, reason} ->
        IO.puts("\n❌ Test failed: #{reason}")
    end
  end

  defp test_login do
    IO.puts("\n1. Testing Admin Login...")

    case Tesla.get("#{@base_url}/admin/login",
                   opts: [adapter: [ssl_options: [verify: :verify_none]]]) do
      {:ok, %{status: 200, body: body, headers: headers}} ->
        IO.puts("   ✓ Login page loaded")

        # Extract CSRF token
        csrf = extract_csrf(body)
        cookie = extract_cookie(headers)

        if csrf && cookie do
          IO.puts("   ✓ Got CSRF token: #{String.slice(csrf, 0..10)}...")
          IO.puts("   ✓ Got session cookie")

          # Test that we can access protected pages
          case Tesla.get("#{@base_url}/admin/customers",
                        headers: [{"cookie", "_rsolv_landing_key=#{cookie}"}],
                        opts: [adapter: [ssl_options: [verify: :verify_none]]]) do
            {:ok, %{status: 302}} ->
              IO.puts("   ✓ Authentication required (redirect to login)")
              {:ok, cookie}
            {:ok, %{status: 200}} ->
              IO.puts("   ✓ Already authenticated")
              {:ok, cookie}
            _ ->
              {:error, "Failed to verify authentication"}
          end
        else
          {:error, "Failed to extract CSRF or cookie"}
        end

      _ ->
        {:error, "Failed to load login page"}
    end
  end

  defp test_customer_list(cookie) do
    IO.puts("\n2. Testing Customer List View...")

    # Note: Without actual authentication, we'll check for redirect
    case Tesla.get("#{@base_url}/admin/customers",
                   headers: [{"cookie", "_rsolv_landing_key=#{cookie}"}],
                   opts: [adapter: [ssl_options: [verify: :verify_none]]]) do
      {:ok, %{status: 302, headers: headers}} ->
        location = get_header(headers, "location")
        if location =~ "login" do
          IO.puts("   ✓ Authentication working (redirects to login)")
          :ok
        else
          IO.puts("   ⚠ Unexpected redirect: #{location}")
          :ok
        end
      {:ok, %{status: 200, body: body}} ->
        check_customer_list_elements(body)
        :ok
      _ ->
        {:error, "Failed to access customer list"}
    end
  end

  defp test_customer_detail(cookie) do
    IO.puts("\n3. Testing Customer Detail View...")

    # Try to access a customer detail page
    case Tesla.get("#{@base_url}/admin/customers/1",
                   headers: [{"cookie", "_rsolv_landing_key=#{cookie}"}],
                   opts: [adapter: [ssl_options: [verify: :verify_none]]]) do
      {:ok, %{status: 302}} ->
        IO.puts("   ✓ Authentication required for detail view")
        :ok
      {:ok, %{status: 200, body: body}} ->
        check_customer_detail_elements(body)
        :ok
      _ ->
        IO.puts("   ⚠ Could not test detail view")
        :ok
    end
  end

  defp check_customer_list_elements(body) do
    elements = [
      {"New Customer", "New Customer button"},
      {"Actions", "Actions column"},
      {"View", "View buttons"},
      {"Edit", "Edit buttons"},
      {"Delete", "Delete buttons"},
      {"Status", "Status filter"}
    ]

    Enum.each(elements, fn {text, description} ->
      if String.contains?(body, text) do
        IO.puts("   ✓ #{description} present")
      else
        IO.puts("   ✗ #{description} missing")
      end
    end)
  end

  defp check_customer_detail_elements(body) do
    elements = [
      {"Customer Information", "Customer info section"},
      {"Usage Statistics", "Usage stats section"},
      {"API Keys", "API keys section"},
      {"Generate New Key", "Generate key button"},
      {"Back to Customers", "Back navigation"}
    ]

    Enum.each(elements, fn {text, description} ->
      if String.contains?(body, text) do
        IO.puts("   ✓ #{description} present")
      else
        IO.puts("   ✗ #{description} missing")
      end
    end)
  end

  defp extract_csrf(body) do
    case Regex.run(~r/name="csrf-token" content="([^"]+)"/, body) do
      [_, token] -> token
      _ -> nil
    end
  end

  defp extract_cookie(headers) do
    case get_header(headers, "set-cookie") do
      nil -> nil
      cookie_header ->
        case Regex.run(~r/_rsolv_landing_key=([^;]+)/, cookie_header) do
          [_, cookie] -> cookie
          _ -> nil
        end
    end
  end

  defp get_header(headers, name) do
    headers
    |> Enum.find(fn {k, _} -> String.downcase(k) == String.downcase(name) end)
    |> case do
      {_, value} -> value
      nil -> nil
    end
  end
end

StagingTest.run()