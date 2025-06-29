defmodule RSOLVApi.Security.JsonRegexTest do
  use ExUnit.Case
  
  test "Jason fails to encode regex" do
    # This test demonstrates the current failure - Red phase of TDD
    assert_raise Protocol.UndefinedError, fn ->
      Jason.encode!(~r/test/)
    end
  end
  
  test "Pattern with regex fails to encode" do
    pattern = %{pattern: ~r/SELECT.*FROM/}
    assert_raise Protocol.UndefinedError, fn ->
      Jason.encode!(pattern)
    end
  end
end