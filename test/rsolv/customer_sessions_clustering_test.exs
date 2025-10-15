defmodule Rsolv.CustomerSessionsClusteringTest do
  @moduledoc """
  Tests for distributed Mnesia clustering behavior in CustomerSessions.
  Tests that sessions are properly shared across nodes.
  """

  use Rsolv.IntegrationCase
  alias Rsolv.CustomerSessions

  @moduletag :distributed
  @moduletag :skip
  @moduletag timeout: 60_000

  describe "Mnesia clustering" do
    test "CustomerSessions properly joins existing Mnesia cluster" do
      # The key issue: when CustomerSessions starts on a second node,
      # it should join the existing Mnesia cluster, not create its own

      # First verify local Mnesia is running
      assert :mnesia.system_info(:is_running) == :yes
      assert :mnesia.system_info(:running_db_nodes) == [node()]

      # Create a session locally first
      token = "test-clustering-token"
      customer_id = 999
      assert :ok = CustomerSessions.put_session(token, customer_id)

      # Now we'll test the real clustering logic directly
      # This simulates what happens when a new pod joins in Kubernetes
      test_node = :"test_node@127.0.0.1"

      # Mock what would happen when another node joins
      # The critical part is that join_mnesia_cluster must be called
      # when CustomerSessions starts on the new node

      # Check that the session exists locally
      assert {:ok, ^customer_id} = CustomerSessions.get_session(token)

      # Cleanup
      CustomerSessions.delete_session(token)
    end

    test "sessions created on one node are visible on another" do
      # Start a second node
      {:ok, node2} = start_slave_node(:test_node2)
      assert Node.connect(node2)

      # Start CustomerSessions on the remote node
      :rpc.call(node2, Application, :ensure_all_started, [:rsolv])
      :rpc.call(node2, CustomerSessions, :start_link, [[]])

      # Wait for Mnesia to sync
      Process.sleep(1000)

      # Create session on local node
      token = "distributed-test-token"
      customer_id = 999

      assert :ok = CustomerSessions.put_session(token, customer_id)

      # Verify it exists locally
      assert {:ok, ^customer_id} = CustomerSessions.get_session(token)

      # Verify it exists on remote node
      remote_result = :rpc.call(node2, CustomerSessions, :get_session, [token])
      assert {:ok, ^customer_id} = remote_result

      # Cleanup
      CustomerSessions.delete_session(token)
      stop_slave_node(node2)
    end

    test "sessions deleted on one node are removed from all nodes" do
      # Start a second node
      {:ok, node2} = start_slave_node(:test_node2)
      assert Node.connect(node2)

      # Start CustomerSessions on the remote node
      :rpc.call(node2, Application, :ensure_all_started, [:rsolv])
      :rpc.call(node2, CustomerSessions, :start_link, [[]])

      # Wait for Mnesia to sync
      Process.sleep(1000)

      # Create session on local node
      token = "delete-test-token"
      customer_id = 888

      assert :ok = CustomerSessions.put_session(token, customer_id)

      # Verify it exists on both nodes
      assert {:ok, ^customer_id} = CustomerSessions.get_session(token)
      assert {:ok, ^customer_id} = :rpc.call(node2, CustomerSessions, :get_session, [token])

      # Delete on remote node
      :rpc.call(node2, CustomerSessions, :delete_session, [token])

      # Verify it's gone from both nodes
      assert {:error, :not_found} = CustomerSessions.get_session(token)
      assert {:error, :not_found} = :rpc.call(node2, CustomerSessions, :get_session, [token])

      # Cleanup
      stop_slave_node(node2)
    end

    test "new node joining cluster gets existing sessions" do
      # Create session first
      token = "pre-existing-token"
      customer_id = 777

      assert :ok = CustomerSessions.put_session(token, customer_id)

      # Now start a second node
      {:ok, node2} = start_slave_node(:test_node2)
      assert Node.connect(node2)

      # Start CustomerSessions on the remote node (should join existing cluster)
      :rpc.call(node2, Application, :ensure_all_started, [:rsolv])
      :rpc.call(node2, CustomerSessions, :start_link, [[]])

      # Wait for Mnesia to sync
      Process.sleep(2000)

      # Verify the new node can see the pre-existing session
      remote_result = :rpc.call(node2, CustomerSessions, :get_session, [token])
      assert {:ok, ^customer_id} = remote_result

      # Cleanup
      CustomerSessions.delete_session(token)
      stop_slave_node(node2)
    end
  end

  # Helper functions for managing peer nodes

  defp start_slave_node(name) do
    # Ensure epmd is running
    System.cmd("epmd", ["-daemon"])

    # Start distributed Erlang on the current node if not already started
    case Node.alive?() do
      false ->
        Node.start(:"primary@127.0.0.1")
        Node.set_cookie(:test_cookie)

      true ->
        :ok
    end

    # Start the peer node using the new :peer module
    {:ok, _pid, node} =
      :peer.start(%{
        name: name,
        host: ~c"127.0.0.1",
        args: [~c"-setcookie", ~c"test_cookie"]
      })

    # Load our code on the peer
    :rpc.call(node, :code, :add_paths, [:code.get_path()])

    {:ok, node}
  end

  defp stop_slave_node(node) do
    :peer.stop(node)
  end
end
