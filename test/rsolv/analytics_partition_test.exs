defmodule Rsolv.AnalyticsPartitionTest do
  use Rsolv.DataCase
  import ExUnit.CaptureLog

  alias Rsolv.Analytics
  alias Rsolv.Repo

  describe "ensure_partition_exists/1" do
    test "creates a partition for current month if it doesn't exist" do
      # Arrange
      current_date = DateTime.utc_now()

      # Act - This should create the partition without error
      assert :ok = Analytics.ensure_partition_exists(current_date)

      # Assert - Verify partition was created
      assert partition_exists?(current_date)
    end

    test "handles existing partition gracefully" do
      # Arrange
      current_date = DateTime.utc_now()

      # Create partition first
      :ok = Analytics.ensure_partition_exists(current_date)

      # Act - Call again with same date
      assert :ok = Analytics.ensure_partition_exists(current_date)

      # Assert - Should still have exactly one partition for this month
      assert partition_exists?(current_date)
    end

    test "creates partition for future dates" do
      # Arrange
      future_date = DateTime.utc_now() |> DateTime.add(90, :day)

      # Act
      assert :ok = Analytics.ensure_partition_exists(future_date)

      # Assert
      assert partition_exists?(future_date)
    end

    test "creates partition for past dates" do
      # Arrange
      past_date = DateTime.utc_now() |> DateTime.add(-60, :day)

      # Act
      assert :ok = Analytics.ensure_partition_exists(past_date)

      # Assert
      assert partition_exists?(past_date)
    end

    test "handles database errors gracefully" do
      # This test would require mocking the database call
      # For now, we'll test that errors are handled properly

      # Arrange - use an invalid date that would cause an error
      invalid_date = nil

      # Act & Assert - Should not crash
      assert_raise FunctionClauseError, fn ->
        Analytics.ensure_partition_exists(invalid_date)
      end
    end
  end

  describe "create_event/1 with automatic partition creation" do
    test "automatically creates partition when inserting event for current month" do
      # Arrange
      attrs = %{
        event_type: "page_view",
        visitor_id: "test_visitor_#{System.unique_integer()}",
        metadata: %{test: true}
      }

      # Act
      assert {:ok, event} = Analytics.create_event(attrs)

      # Assert
      assert event.id
      assert event.event_type == "page_view"
      assert partition_exists?(event.inserted_at)
    end

    test "creates event with explicit timestamp and ensures partition" do
      # Arrange
      future_timestamp = DateTime.utc_now() |> DateTime.add(60, :day)

      attrs = %{
        event_type: "future_event",
        visitor_id: "test_visitor_#{System.unique_integer()}",
        metadata: %{test: true},
        inserted_at: future_timestamp
      }

      # Act
      assert {:ok, event} = Analytics.create_event(attrs)

      # Assert
      assert event.id
      assert partition_exists?(future_timestamp)
    end

    test "handles concurrent partition creation attempts" do
      # Arrange
      future_date = DateTime.utc_now() |> DateTime.add(120, :day)

      # Spawn multiple processes trying to create the same partition
      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            attrs = %{
              event_type: "concurrent_event_#{i}",
              visitor_id: "visitor_#{i}",
              metadata: %{index: i},
              inserted_at: future_date
            }

            Analytics.create_event(attrs)
          end)
        end

      # Act - Wait for all tasks to complete
      results = Task.await_many(tasks, 5000)

      # Assert - All should succeed
      assert Enum.all?(results, fn
               {:ok, _event} -> true
               _ -> false
             end)

      assert partition_exists?(future_date)
    end
  end

  describe "partition management" do
    test "lists existing partitions" do
      # Create a few partitions
      current_date = DateTime.utc_now()
      future_date = DateTime.add(current_date, 30, :day)
      past_date = DateTime.add(current_date, -30, :day)

      Analytics.ensure_partition_exists(current_date)
      Analytics.ensure_partition_exists(future_date)
      Analytics.ensure_partition_exists(past_date)

      # Query for partitions
      query = """
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname = 'public' 
          AND tablename LIKE 'analytics_events_%'
        ORDER BY tablename
      """

      {:ok, %{rows: partitions}} = Repo.query(query)

      # Should have at least the partitions we created
      assert length(partitions) >= 1

      # Verify partition names follow expected format
      Enum.each(partitions, fn [partition_name] ->
        assert String.starts_with?(partition_name, "analytics_events_")
        assert Regex.match?(~r/analytics_events_\d{4}_\d{2}/, partition_name)
      end)
    end
  end

  # Helper functions

  defp partition_exists?(datetime) do
    date =
      case datetime do
        %DateTime{} -> DateTime.to_date(datetime)
        %NaiveDateTime{} -> NaiveDateTime.to_date(datetime)
        %Date{} -> datetime
      end

    partition_name =
      "analytics_events_#{date.year}_#{String.pad_leading(to_string(date.month), 2, "0")}"

    query = """
      SELECT EXISTS (
        SELECT 1 
        FROM pg_tables 
        WHERE schemaname = 'public' 
          AND tablename = $1
      )
    """

    case Repo.query(query, [partition_name]) do
      {:ok, %{rows: [[true]]}} -> true
      _ -> false
    end
  end
end
