defmodule Rsolv.Billing.MoneyTest do
  use ExUnit.Case, async: true

  alias Money

  describe "ex_money formatting" do
    test "formats currency correctly" do
      # Test basic formatting
      money = Money.new(:USD, 1000)
      assert Money.to_string(money) == "$10.00"

      # Test with cents
      money = Money.new(:USD, 1050)
      assert Money.to_string(money) == "$10.50"

      # Test large amounts
      money = Money.new(:USD, 50000)
      assert Money.to_string(money) == "$500.00"
    end

    test "handles zero amounts" do
      money = Money.new(:USD, 0)
      assert Money.to_string(money) == "$0.00"
    end

    test "supports arithmetic operations" do
      m1 = Money.new(:USD, 1000)
      m2 = Money.new(:USD, 500)

      {:ok, result} = Money.add(m1, m2)
      assert Money.to_string(result) == "$15.00"

      {:ok, result} = Money.sub(m1, m2)
      assert Money.to_string(result) == "$5.00"
    end

    test "prevents mixing currencies" do
      usd = Money.new(:USD, 1000)
      eur = Money.new(:EUR, 1000)

      assert {:error, _} = Money.add(usd, eur)
    end
  end
end
