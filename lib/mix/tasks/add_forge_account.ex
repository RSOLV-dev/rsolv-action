defmodule Mix.Tasks.AddForgeAccount do
  use Mix.Task
  alias Rsolv.Repo
  alias Rsolv.Customers.ForgeAccount

  @shortdoc "Adds a forge_account association for an existing API key"

  @moduledoc """
  Adds a forge_account association to enable platform storage access.

  Usage:
    mix add_forge_account --api-key="rsolv_..." --namespace="RSOLV-dev" --forge-type="github"

  This enables the API key to access repositories in the specified namespace
  for platform phase data storage.
  """

  def run(args) do
    Mix.Task.run("app.start")

    {opts, _} =
      OptionParser.parse!(args,
        strict: [
          api_key: :string,
          namespace: :string,
          forge_type: :string
        ]
      )

    api_key = opts[:api_key] || raise "Missing required --api-key argument"
    namespace = opts[:namespace] || raise "Missing required --namespace argument"
    forge_type = String.to_existing_atom(opts[:forge_type] || "github")

    # Get the API key record and customer
    api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)

    if !api_key_record do
      raise "API key '#{String.slice(api_key, 0..15)}...' not found"
    end

    customer = api_key_record.customer

    IO.puts("Found API key for customer: #{customer.name} (#{customer.email})")

    # Check if forge_account already exists
    existing =
      Repo.get_by(ForgeAccount,
        customer_id: customer.id,
        forge_type: forge_type,
        namespace: namespace
      )

    if existing do
      if existing.verified_at do
        IO.puts("✅ Forge account already exists and is verified")
        IO.puts("   Namespace: #{namespace}")
        IO.puts("   Verified at: #{existing.verified_at}")
      else
        # Verify existing forge account
        changeset = ForgeAccount.changeset(existing, %{verified_at: DateTime.utc_now()})

        case Repo.update(changeset) do
          {:ok, updated} ->
            IO.puts("✅ Existing forge account verified successfully")
            IO.puts("   Namespace: #{namespace}")
            IO.puts("   Verified at: #{updated.verified_at}")

          {:error, changeset} ->
            IO.puts("❌ Failed to verify forge account:")
            IO.inspect(changeset.errors)
        end
      end
    else
      # Create new forge account
      changeset =
        ForgeAccount.changeset(%ForgeAccount{}, %{
          customer_id: customer.id,
          forge_type: forge_type,
          namespace: namespace,
          verified_at: DateTime.utc_now(),
          metadata: %{
            type: "manual_addition",
            created_by: "mix_task",
            created_at: DateTime.utc_now()
          }
        })

      case Repo.insert(changeset) do
        {:ok, forge_account} ->
          IO.puts("✅ Forge account created successfully")
          IO.puts("   Customer: #{customer.name}")
          IO.puts("   Namespace: #{forge_account.namespace}")
          IO.puts("   Forge Type: #{forge_account.forge_type}")
          IO.puts("   Verified at: #{forge_account.verified_at}")

          # Test platform storage access
          IO.puts("\n🧪 Testing platform storage access...")
          test_platform_storage_access(api_key_record, namespace)

        {:error, changeset} ->
          IO.puts("❌ Failed to create forge account:")
          IO.inspect(changeset.errors)
      end
    end
  end

  defp test_platform_storage_access(api_key, namespace) do
    # Try to store and retrieve test phase data
    test_repo = "#{namespace}/test-repo"

    test_attrs = %{
      repo: test_repo,
      commit_sha: "test-commit-#{System.os_time(:second)}",
      data: %{test: true, created_at: DateTime.utc_now()}
    }

    case Rsolv.Phases.store_scan(test_attrs, api_key) do
      {:ok, _scan} ->
        IO.puts("✅ Platform storage test successful!")
        IO.puts("   Can now store phase data for #{namespace}/* repositories")

      {:error, :unauthorized} ->
        IO.puts("❌ Platform storage still unauthorized - may need database refresh")

      {:error, error} ->
        IO.puts("⚠️  Platform storage test failed with: #{inspect(error)}")
    end
  end
end
