defmodule Rsolv.Phases.PhaseStorageTest do
  use Rsolv.DataCase
  alias Rsolv.Phases
  alias Rsolv.Phases.{Repository, ScanExecution, ValidationExecution, MitigationExecution}
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.{Customer, ApiKey}
  alias Rsolv.Accounts.User
  alias Rsolv.Repo

  describe "phase storage" do
    setup do
      # Create a user first (required for customer)
      user = %User{}
      |> User.registration_changeset(%{
        email: "test@example.com",
        password: "password123456"
      })
      |> Repo.insert!()
      
      # Create a customer
      customer = %Customer{}
      |> Customer.changeset(%{
        user_id: user.id,
        name: "Test Corp",
        email: "test@example.com",
        active: true
      })
      |> Repo.insert!()
      
      # Create an API key
      api_key = %ApiKey{}
      |> ApiKey.changeset(%{
        customer_id: customer.id,
        name: "Test Key",
        key: "test_" <> Ecto.UUID.generate(),
        active: true
      })
      |> Repo.insert!()
      
      # Create a forge account for this customer
      forge_account = %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        verified_at: DateTime.utc_now()
      })
      |> Repo.insert!()
      
      %{customer: customer, api_key: api_key, forge_account: forge_account}
    end

    test "stores scan execution with auto-created repo", %{api_key: api_key} do
      # RED: Function doesn't exist yet
      assert {:ok, scan} = Phases.store_scan(%{
        repo: "RSOLV-dev/nodegoat-demo",
        commit_sha: "abc123",
        branch: "main",
        data: %{
          vulnerabilities: [
            %{
              type: "xss",
              file: "app.js",
              line: 42,
              severity: "high"
            }
          ],
          timestamp: DateTime.utc_now(),
          commitHash: "abc123"
        }
      }, api_key)
      
      # GREEN: Will implement the function
      assert scan.repository.full_path == "RSOLV-dev/nodegoat-demo"
      assert scan.commit_sha == "abc123"
      assert scan.branch == "main"
      assert scan.vulnerabilities_count == 1
      assert length(scan.data["vulnerabilities"]) == 1
      assert scan.status == :completed
    end

    test "stores validation execution with issue number", %{api_key: api_key} do
      assert {:ok, validation} = Phases.store_validation(%{
        repo: "RSOLV-dev/nodegoat-demo",
        issue_number: 123,
        commit_sha: "abc123",
        data: %{
          validated: true,
          vulnerabilities: [
            %{
              type: "xss",
              file: "app.js",
              testResults: %{
                passed: true
              }
            }
          ],
          confidence: 0.95
        }
      }, api_key)
      
      assert validation.issue_number == 123
      assert validation.validated == true
      assert validation.vulnerabilities_found == 1
      assert validation.data["confidence"] == 0.95
      assert validation.status == :completed
    end

    test "stores mitigation execution with PR details", %{api_key: api_key} do
      assert {:ok, mitigation} = Phases.store_mitigation(%{
        repo: "RSOLV-dev/nodegoat-demo",
        issue_number: 123,
        commit_sha: "def456",
        data: %{
          pr_url: "https://github.com/RSOLV-dev/nodegoat-demo/pull/456",
          pr_number: 456,
          files_changed: 3,
          fixes: [
            %{
              file: "app.js",
              vulnerability: "xss",
              fixed: true
            }
          ],
          commitHash: "def456"
        }
      }, api_key)
      
      assert mitigation.issue_number == 123
      assert mitigation.pr_url == "https://github.com/RSOLV-dev/nodegoat-demo/pull/456"
      assert mitigation.pr_number == 456
      assert mitigation.files_changed == 3
      assert mitigation.status == :completed
    end

    test "enforces namespace access control for phase storage", %{customer: customer} do
      # Create another customer with different namespace
      other_user = %User{}
      |> User.registration_changeset(%{
        email: "other@example.com",
        password: "password123456"
      })
      |> Repo.insert!()
      
      other_customer = %Customer{}
      |> Customer.changeset(%{
        user_id: other_user.id,
        name: "Other Corp",
        email: "other@example.com",
        active: true
      })
      |> Repo.insert!()
      
      other_api_key = %ApiKey{}
      |> ApiKey.changeset(%{
        customer_id: other_customer.id,
        name: "Other Key",
        key: "test_" <> Ecto.UUID.generate(),
        active: true
      })
      |> Repo.insert!()
      
      # Try to store data for a namespace they don't own
      assert {:error, :unauthorized} = Phases.store_scan(%{
        repo: "RSOLV-dev/nodegoat-demo",  # RSOLV-dev is owned by first customer
        commit_sha: "abc123",
        data: %{vulnerabilities: []}
      }, other_api_key)
    end

    test "auto-creates repository on first phase storage", %{api_key: api_key} do
      # Verify repo doesn't exist
      assert nil == Repo.get_by(Repository, 
        forge_type: :github,
        namespace: "RSOLV-dev",
        name: "new-repo"
      )
      
      # Store scan data
      {:ok, scan} = Phases.store_scan(%{
        repo: "RSOLV-dev/new-repo",
        commit_sha: "abc123",
        data: %{vulnerabilities: []}
      }, api_key)
      
      # Verify repo was created
      repo = Repo.get_by(Repository,
        forge_type: :github,
        namespace: "RSOLV-dev",
        name: "new-repo"
      )
      
      assert repo != nil
      assert repo.full_path == "RSOLV-dev/new-repo"
      assert repo.id == scan.repository_id
    end

    test "handles phase storage errors gracefully", %{api_key: api_key} do
      # Missing required fields
      assert {:error, changeset} = Phases.store_scan(%{
        repo: "RSOLV-dev/test",
        # Missing commit_sha
        data: %{vulnerabilities: []}
      }, api_key)
      
      assert %{commit_sha: ["can't be blank"]} = errors_on(changeset)
    end

    test "tracks phase execution timing", %{api_key: api_key} do
      {:ok, scan} = Phases.store_scan(%{
        repo: "RSOLV-dev/timing-test",
        commit_sha: "abc123",
        data: %{vulnerabilities: []},
        started_at: ~U[2025-08-15 10:00:00Z],
        completed_at: ~U[2025-08-15 10:05:00Z]
      }, api_key)
      
      assert DateTime.compare(scan.started_at, ~U[2025-08-15 10:00:00Z]) == :eq
      assert DateTime.compare(scan.completed_at, ~U[2025-08-15 10:05:00Z]) == :eq
    end
  end
  
  describe "ForgeAccount in correct context" do
    test "ForgeAccount is in Customers context not Phases" do
      # This will FAIL initially - ForgeAccount is in wrong context
      assert Code.ensure_loaded?(Rsolv.Customers.ForgeAccount)
      
      # Should NOT be in Phases context after refactor
      refute Code.ensure_loaded?(Rsolv.Phases.ForgeAccount)
    end
    
    test "ForgeAccount belongs to Customer" do
      # Ensure the relationship is properly defined
      assert %Ecto.Association.BelongsTo{} = 
        Rsolv.Customers.ForgeAccount.__schema__(:association, :customer)
      
      # Ensure it points to the right schema
      assoc = Rsolv.Customers.ForgeAccount.__schema__(:association, :customer)
      assert assoc.related == Rsolv.Customers.Customer
    end
  end
end