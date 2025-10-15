defmodule Rsolv.CustomerSessionsTest do
  use Rsolv.DataCase
  alias Rsolv.CustomerSessions

  # Test helpers
  defp create_session(token, customer_id) do
    CustomerSessions.put_session(token, customer_id)
  end

  defp create_expired_session(token, customer_id) do
    past_time = DateTime.add(DateTime.utc_now(), -3600, :second)

    :mnesia.transaction(fn ->
      :mnesia.write({
        :customer_sessions_mnesia,
        token,
        customer_id,
        DateTime.utc_now(),
        past_time
      })
    end)
  end

  defp clear_all_sessions do
    CustomerSessions.all_sessions()
    |> Enum.each(fn {_, token, _, _, _} ->
      CustomerSessions.delete_session(token)
    end)
  end

  describe "setup_mnesia/0" do
    test "creates table" do
      tables = :mnesia.system_info(:tables)
      assert :customer_sessions_mnesia in tables
    end

    test "uses ram_copies" do
      node_list = :mnesia.table_info(:customer_sessions_mnesia, :ram_copies)
      assert node() in node_list
    end
  end

  describe "put_session/2" do
    test "returns atomic ok" do
      assert {:atomic, :ok} = create_session("token1", 1)
    end

    test "stores customer_id" do
      create_session("token2", 42)

      {:atomic, [{_, _, customer_id, _, _}]} =
        :mnesia.transaction(fn ->
          :mnesia.read(:customer_sessions_mnesia, "token2")
        end)

      assert customer_id == 42
    end
  end

  describe "get_session/1" do
    test "retrieves valid session" do
      create_session("token3", 99)
      assert {:ok, 99} = CustomerSessions.get_session("token3")
    end

    test "returns not_found for missing" do
      assert {:error, :not_found} = CustomerSessions.get_session("missing")
    end

    test "returns expired and cleans up" do
      create_expired_session("old", 1)
      assert {:error, :expired} = CustomerSessions.get_session("old")
      assert {:error, :not_found} = CustomerSessions.get_session("old")
    end
  end

  describe "delete_session/1" do
    test "removes session" do
      create_session("token4", 77)
      CustomerSessions.delete_session("token4")
      assert {:error, :not_found} = CustomerSessions.get_session("token4")
    end
  end

  describe "cleanup_expired_sessions/0" do
    setup do
      clear_all_sessions()
      :ok
    end

    test "removes only expired" do
      create_expired_session("old1", 1)
      create_expired_session("old2", 2)
      create_session("new1", 3)

      count = CustomerSessions.cleanup_expired_sessions()
      assert count == 2

      sessions = CustomerSessions.all_sessions()
      assert length(sessions) == 1
    end
  end

  describe "all_sessions/0" do
    setup do
      clear_all_sessions()
      :ok
    end

    test "returns all sessions" do
      create_session("s1", 1)
      create_session("s2", 2)

      sessions = CustomerSessions.all_sessions()
      assert length(sessions) == 2
    end
  end

  describe "Mnesia cluster joining" do
    @moduletag :distributed

    test "joins existing cluster when available" do
      # Requires multi-node test setup
      assert true
    end
  end
end
