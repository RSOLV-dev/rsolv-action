defmodule RsolvWeb.Admin.CustomerLiveApiKeyTest do
  use RsolvWeb.ConnCase, async: false
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]

  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures

  alias Rsolv.Customers
  alias Rsolv.Repo

  setup do
    staff = staff_customer_fixture()
    customer = customer_fixture(name: "Test Customer")

    %{staff: staff, customer: customer}
  end

  describe "API Key Generation" do
    test "generates and saves API key to database", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Count API keys before generation
      initial_count = length(Customers.list_api_keys(customer))

      # Generate new API key
      view
      |> element("button", "Generate New Key")
      |> render_click()

      # Should show the generated key in modal
      html = render(view)
      assert html =~ "API Key Generated Successfully"
      assert html =~ "rsolv_"

      # Extract the generated key from the modal
      generated_key = extract_api_key_from_html(html)
      refute is_nil(generated_key)

      # Verify key was saved to database
      api_keys = Customers.list_api_keys(customer)
      assert length(api_keys) == initial_count + 1

      # Verify the key exists in database with correct attributes
      saved_key = Repo.get_by(Customers.ApiKey, key: generated_key)
      assert saved_key != nil
      assert saved_key.customer_id == customer.id
      assert saved_key.active == true
      assert saved_key.name == "API Key"
    end

    test "can retrieve API key by key value", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Generate new API key
      view
      |> element("button", "Generate New Key")
      |> render_click()

      html = render(view)
      generated_key = extract_api_key_from_html(html)

      # Test the lookup function used by credential controller
      api_key = Customers.get_api_key_by_key(generated_key)
      assert api_key != nil
      assert api_key.customer_id == customer.id

      # Verify customer can be retrieved from API key
      customer_from_key = Customers.get_customer_by_api_key(generated_key)
      assert customer_from_key != nil
      assert customer_from_key.id == customer.id
    end

    test "generated API keys are active by default", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Generate new API key
      view
      |> element("button", "Generate New Key")
      |> render_click()

      html = render(view)
      generated_key = extract_api_key_from_html(html)

      # Verify key is active
      api_key = Repo.get_by(Customers.ApiKey, key: generated_key)
      assert api_key.active == true
    end

    test "multiple API keys can be generated for same customer", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Generate first key
      view
      |> element("button", "Generate New Key")
      |> render_click()

      html1 = render(view)
      key1 = extract_api_key_from_html(html1)

      # Close modal
      view
      |> element("button", "Done")
      |> render_click()

      # Generate second key
      view
      |> element("button", "Generate New Key")
      |> render_click()

      html2 = render(view)
      key2 = extract_api_key_from_html(html2)

      # Verify both keys exist and are different
      assert key1 != key2
      assert Repo.get_by(Customers.ApiKey, key: key1) != nil
      assert Repo.get_by(Customers.ApiKey, key: key2) != nil

      # Verify both belong to same customer
      api_keys = Customers.list_api_keys(customer)
      assert length(api_keys) >= 2
      assert Enum.any?(api_keys, &(&1.key == key1))
      assert Enum.any?(api_keys, &(&1.key == key2))
    end
  end

  # Helper function to extract API key from HTML
  defp extract_api_key_from_html(html) do
    # Look for the value attribute in the input field
    case Regex.run(~r/value="(rsolv_[\w\-]+)"/, html) do
      [_, key] -> key
      _ -> nil
    end
  end
end