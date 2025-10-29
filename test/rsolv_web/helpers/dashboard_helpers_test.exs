defmodule RsolvWeb.Helpers.DashboardHelpersTest do
  use RsolvWeb.ConnCase, async: true
  import RsolvWeb.Helpers.DashboardHelpers

  alias Rsolv.Customers.Customer

  describe "show_wizard?/1" do
    test "shows wizard if no scans completed and wizard_preference is 'auto'" do
      customer = %Customer{
        wizard_preference: "auto",
        first_scan_at: nil
      }

      assert show_wizard?(customer) == true
    end

    test "hides wizard after first scan completes with wizard_preference 'auto'" do
      customer = %Customer{
        wizard_preference: "auto",
        first_scan_at: ~U[2025-10-20 12:00:00Z]
      }

      assert show_wizard?(customer) == false
    end

    test "manual dismiss sets wizard_preference = 'hidden'" do
      customer = %Customer{
        wizard_preference: "hidden",
        first_scan_at: nil
      }

      assert show_wizard?(customer) == false
    end

    test "manual re-enter sets wizard_preference = 'shown'" do
      customer = %Customer{
        wizard_preference: "shown",
        first_scan_at: ~U[2025-10-20 12:00:00Z]
      }

      assert show_wizard?(customer) == true
    end

    test "returns false for nil customer" do
      assert show_wizard?(nil) == false
    end

    test "returns false for customer with invalid wizard_preference" do
      customer = %Customer{
        wizard_preference: "invalid",
        first_scan_at: nil
      }

      assert show_wizard?(customer) == false
    end
  end

  describe "format_datetime/1" do
    test "formats DateTime struct correctly" do
      datetime = ~U[2023-05-20 12:34:56Z]
      assert format_datetime(datetime) == "May 20, 2023 12:34 PM"
    end

    test "formats ISO8601 string correctly" do
      assert format_datetime("2023-05-20T12:34:56Z") == "May 20, 2023 12:34 PM"
    end

    test "handles invalid input gracefully" do
      assert format_datetime(nil) == "Unknown"
      assert format_datetime(12345) == "Unknown"
    end
  end

  describe "format_duration/1" do
    test "formats seconds only" do
      assert format_duration(45) == "45s"
    end

    test "formats minutes and seconds" do
      assert format_duration(65) == "1m 5s"
    end

    test "formats hours, minutes, and seconds" do
      assert format_duration(3665) == "1h 1m 5s"
    end

    test "handles zero and negative values" do
      assert format_duration(0) == "0s"
      assert format_duration(-10) == "0s"
    end
  end

  describe "is_empty_chart_data/1" do
    test "returns true for nil" do
      assert is_empty_chart_data(nil) == true
    end

    test "returns true for empty list" do
      assert is_empty_chart_data([]) == true
    end

    test "returns true for empty map" do
      assert is_empty_chart_data(%{}) == true
    end

    test "returns false for list with data" do
      assert is_empty_chart_data([%{count: 1}]) == false
    end

    test "returns false for map with data" do
      assert is_empty_chart_data(%{data: [1, 2, 3]}) == false
    end
  end

  describe "safe_get/3" do
    test "retrieves nested values from map" do
      data = %{a: %{b: %{c: 1}}}
      assert safe_get(data, [:a, :b, :c]) == 1
    end

    test "returns default when key not found" do
      data = %{a: %{b: 1}}
      assert safe_get(data, [:a, :x], "default") == "default"
    end

    test "handles nil data gracefully" do
      assert safe_get(nil, [:a, :b], 0) == 0
    end

    test "handles empty path" do
      data = %{value: 42}
      assert safe_get(data, [], "default") == data
    end
  end
end
