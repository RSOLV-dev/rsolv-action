defmodule Rsolv.Phases.RepositoriesTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]
  alias Rsolv.Phases.Repositories
  alias Rsolv.Phases.Repository
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.{Customer, ApiKey}
  alias Rsolv.Repo

  describe "find_or_create/2" do
    setup do
      # Create a customer
      customer =
        %Customer{}
        |> Customer.changeset(%{
          name: "Test Corp",
          email: unique_email(),
          active: true
        })
        |> Repo.insert!()

      # Create an API key
      raw_api_key = "test_" <> Ecto.UUID.generate()

      api_key =
        %ApiKey{}
        |> ApiKey.changeset(%{
          customer_id: customer.id,
          name: "Test Key",
          raw_raw_key: raw_api_key,
          active: true
        })
        |> Repo.insert!()

      # Create a forge account for this customer
      forge_account =
        %ForgeAccount{}
        |> ForgeAccount.changeset(%{
          customer_id: customer.id,
          forge_type: :github,
          namespace: "RSOLV-dev",
          verified_at: DateTime.utc_now()
        })
        |> Repo.insert!()

      %{customer: customer, raw_api_raw_raw_key: raw_api_key, forge_account: forge_account}
    end

    test "creates new repository on first use", %{customer: customer} do
      # RED: Function doesn't exist yet
      attrs = %{
        forge_type: "github",
        namespace: "RSOLV-dev",
        name: "test-repo"
      }

      assert {:ok, repo} = Repositories.find_or_create(attrs, customer)

      # GREEN: Will implement the function
      assert repo.full_path == "RSOLV-dev/test-repo"
      assert repo.forge_type == :github
      assert repo.namespace == "RSOLV-dev"
      assert repo.name == "test-repo"
      assert repo.customer_id == customer.id
    end

    test "returns existing repository on subsequent calls", %{customer: customer} do
      attrs = %{
        forge_type: "github",
        namespace: "RSOLV-dev",
        name: "test-repo"
      }

      {:ok, repo1} = Repositories.find_or_create(attrs, customer)
      {:ok, repo2} = Repositories.find_or_create(attrs, customer)

      assert repo1.id == repo2.id
    end

    test "enforces namespace ownership - customer can only access their namespaces", %{
      customer: customer
    } do
      # Create another customer with different namespace
      other_customer =
        %Customer{}
        |> Customer.changeset(%{
          name: "Other Corp",
          email: "other@example.com",
          active: true
        })
        |> Repo.insert!()

      other_forge =
        %ForgeAccount{}
        |> ForgeAccount.changeset(%{
          customer_id: other_customer.id,
          forge_type: :github,
          namespace: "OTHER-org",
          verified_at: DateTime.utc_now()
        })
        |> Repo.insert!()

      # Try to access another customer's namespace
      attrs = %{
        forge_type: "github",
        namespace: "OTHER-org",
        name: "repo"
      }

      assert {:error, :unauthorized} = Repositories.find_or_create(attrs, customer)
    end

    test "allows access to owned namespace", %{customer: customer} do
      attrs = %{
        forge_type: "github",
        namespace: "RSOLV-dev",
        name: "allowed-repo"
      }

      assert {:ok, repo} = Repositories.find_or_create(attrs, customer)
      assert repo.namespace == "RSOLV-dev"
    end

    test "handles unverified forge accounts", %{customer: customer} do
      # Create unverified forge account
      unverified =
        %ForgeAccount{}
        |> ForgeAccount.changeset(%{
          customer_id: customer.id,
          forge_type: :github,
          namespace: "unverified-org",
          # Not verified
          verified_at: nil
        })
        |> Repo.insert!()

      attrs = %{
        forge_type: "github",
        namespace: "unverified-org",
        name: "repo"
      }

      assert {:error, :forge_not_verified} = Repositories.find_or_create(attrs, customer)
    end

    test "updates last_activity_at on repository access", %{customer: customer} do
      attrs = %{
        forge_type: "github",
        namespace: "RSOLV-dev",
        name: "activity-test"
      }

      {:ok, repo1} = Repositories.find_or_create(attrs, customer)
      initial_activity = repo1.last_activity_at

      # Sleep to ensure timestamp difference
      Process.sleep(10)

      {:ok, repo2} = Repositories.find_or_create(attrs, customer)

      assert repo1.id == repo2.id
      assert DateTime.compare(repo2.last_activity_at, initial_activity) == :gt
    end
  end
end
