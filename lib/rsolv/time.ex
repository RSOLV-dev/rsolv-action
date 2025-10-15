defmodule Rsolv.Time do
  @moduledoc """
  Time abstraction layer for testability.

  This module provides a centralized way to get the current time,
  allowing tests to control time without mocking.

  ## Usage in Production Code

      # Instead of DateTime.utc_now()
      Rsolv.Time.utc_now()
      
      # Or with dependency injection
      def my_function(current_time \\ Rsolv.Time.utc_now()) do
        # ...
      end

  ## Usage in Tests

      # Freeze time in a test
      Rsolv.Time.freeze(~U[2024-01-01 12:00:00Z])
      
      # Advance time
      Rsolv.Time.advance(seconds: 30)
      
      # Unfreeze (usually in test cleanup)
      Rsolv.Time.unfreeze()
  """

  @doc """
  Returns the current UTC datetime.

  In tests, this can be controlled via freeze/1 and advance/1.
  """
  def utc_now do
    case Process.get(:rsolv_frozen_time) do
      nil -> DateTime.utc_now()
      frozen_time -> frozen_time
    end
  end

  @doc """
  Returns the current system time in the given unit.
  """
  def system_time(unit \\ :nanosecond) do
    case Process.get(:rsolv_frozen_time) do
      nil ->
        System.system_time(unit)

      frozen_time ->
        DateTime.to_unix(frozen_time, unit)
    end
  end

  @doc """
  Returns the current monotonic time.

  Note: In frozen mode, this returns a fixed value based on frozen time.
  """
  def monotonic_time(unit \\ :nanosecond) do
    case Process.get(:rsolv_frozen_time) do
      nil ->
        System.monotonic_time(unit)

      frozen_time ->
        # Use unix timestamp as a stable monotonic value
        DateTime.to_unix(frozen_time, unit)
    end
  end

  # Test helpers

  @doc """
  Freezes time at the given DateTime for the current process.

  ## Examples

      iex> Rsolv.Time.freeze(~U[2024-01-01 12:00:00Z])
      :ok
      iex> Rsolv.Time.utc_now()
      ~U[2024-01-01 12:00:00Z]
  """
  def freeze(datetime = %DateTime{}) do
    Process.put(:rsolv_frozen_time, datetime)
    :ok
  end

  def freeze(iso8601_string) when is_binary(iso8601_string) do
    {:ok, datetime, _} = DateTime.from_iso8601(iso8601_string)
    freeze(datetime)
  end

  @doc """
  Advances the frozen time by the given amount.

  ## Examples

      iex> Rsolv.Time.freeze(~U[2024-01-01 12:00:00Z])
      iex> Rsolv.Time.advance(seconds: 30)
      :ok
      iex> Rsolv.Time.utc_now()
      ~U[2024-01-01 12:00:30Z]
  """
  def advance(opts) do
    case Process.get(:rsolv_frozen_time) do
      nil ->
        {:error, :time_not_frozen}

      frozen_time ->
        seconds = Keyword.get(opts, :seconds, 0)
        minutes = Keyword.get(opts, :minutes, 0)
        hours = Keyword.get(opts, :hours, 0)
        days = Keyword.get(opts, :days, 0)

        total_seconds = seconds + minutes * 60 + hours * 3600 + days * 86400
        new_time = DateTime.add(frozen_time, total_seconds, :second)
        Process.put(:rsolv_frozen_time, new_time)
        :ok
    end
  end

  @doc """
  Unfreezes time, returning to real time.
  """
  def unfreeze do
    Process.delete(:rsolv_frozen_time)
    :ok
  end

  @doc """
  Runs a function with frozen time, automatically unfreezing afterward.

  ## Examples

      Rsolv.Time.with_frozen_time(~U[2024-01-01 12:00:00Z], fn ->
        # Time is frozen here
        do_something()
      end)
      # Time is unfrozen here
  """
  def with_frozen_time(datetime, fun) do
    freeze(datetime)

    try do
      fun.()
    after
      unfreeze()
    end
  end
end
