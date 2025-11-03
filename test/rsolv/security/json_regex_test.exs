defmodule Rsolv.Security.JsonRegexTest do
  use ExUnit.Case

  test "Jason fails to encode regex" do
    # This test demonstrates the current failure - Red phase of TDD
    assert_raise Protocol.UndefinedError, fn ->
      JSON.encode!(~r/test/)
    end
  end

  test "Pattern with regex fails to encode" do
    pattern = %{pattern: ~r/SELECT.*FROM/}

    assert_raise Protocol.UndefinedError, fn ->
      JSON.encode!(pattern)
    end
  end
end
