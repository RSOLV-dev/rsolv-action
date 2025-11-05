defmodule RsolvWeb.ReportControllerTest do
  # Don't run async due to FunWithFlags database issues
  use RsolvWeb.ConnCase, async: false
  import ExUnit.CaptureLog

  setup do
    # Enable the admin dashboard flag globally
    {:ok, _} = FunWithFlags.enable(:admin_dashboard)

    # FunWithFlags.enable is synchronous - no delay needed
    on_exit(fn ->
      # Clean up flag after test
      FunWithFlags.clear(:admin_dashboard)
    end)

    :ok
  end

  describe "download/2" do
    test "generates CSV report with default parameters", %{conn: conn} do
      # Call the controller directly to bypass routing and feature flag issues
      log =
        capture_log(fn ->
          conn = RsolvWeb.ReportController.download(conn, %{})

          assert response_content_type(conn, :csv)

          assert get_resp_header(conn, "content-disposition") == [
                   "attachment; filename=rsolv-analytics-conversions-30d.csv"
                 ]

          assert response(conn, 200)
        end)

      assert log =~ "Analytics report downloaded"
    end

    test "generates JSON report when format is json", %{conn: conn} do
      log =
        capture_log(fn ->
          conn = RsolvWeb.ReportController.download(conn, %{"format" => "json"})

          assert response_content_type(conn, :json)

          assert get_resp_header(conn, "content-disposition") == [
                   "attachment; filename=rsolv-analytics-conversions-30d.json"
                 ]

          assert response(conn, 200)
        end)

      assert log =~ "Analytics report downloaded"
    end

    test "handles different report types", %{conn: conn} do
      report_types = [
        "conversions",
        "page_views",
        "traffic",
        "form_events",
        "engagement",
        "signup"
      ]

      for report_type <- report_types do
        log =
          capture_log(fn ->
            conn = RsolvWeb.ReportController.download(conn, %{"type" => report_type})

            assert response(conn, 200)

            assert get_resp_header(conn, "content-disposition") == [
                     "attachment; filename=rsolv-analytics-#{report_type}-30d.csv"
                   ]
          end)

        assert log =~ "report_type: #{report_type}"
      end
    end

    test "handles different time periods", %{conn: conn} do
      periods = ["1d", "7d", "30d", "90d", "all"]

      for period <- periods do
        log =
          capture_log(fn ->
            conn = RsolvWeb.ReportController.download(conn, %{"period" => period})

            assert response(conn, 200)

            assert get_resp_header(conn, "content-disposition") == [
                     "attachment; filename=rsolv-analytics-conversions-#{period}.csv"
                   ]
          end)

        assert log =~ "period: #{period}"
      end
    end

    test "handles empty data gracefully", %{conn: conn} do
      conn = RsolvWeb.ReportController.download(conn, %{})

      response_body = response(conn, 200)
      # When there's no data, we should get a "No data available" message or empty CSV
      assert response_body =~ "No data available" or response_body == ""
    end

    test "combines parameters correctly", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            RsolvWeb.ReportController.download(conn, %{
              "type" => "page_views",
              "format" => "json",
              "period" => "7d"
            })

          assert response_content_type(conn, :json)

          assert get_resp_header(conn, "content-disposition") == [
                   "attachment; filename=rsolv-analytics-page_views-7d.json"
                 ]

          assert response(conn, 200)
        end)

      assert log =~ "report_type: page_views"
      assert log =~ "format: json"
      assert log =~ "period: 7d"
    end

    test "handles unknown report type", %{conn: conn} do
      # Should default to conversions
      conn = RsolvWeb.ReportController.download(conn, %{"type" => "unknown"})

      assert response(conn, 200)

      assert get_resp_header(conn, "content-disposition") == [
               "attachment; filename=rsolv-analytics-unknown-30d.csv"
             ]
    end

    test "handles invalid period", %{conn: conn} do
      # Should default to 30d
      conn = RsolvWeb.ReportController.download(conn, %{"period" => "invalid"})

      assert response(conn, 200)

      assert get_resp_header(conn, "content-disposition") == [
               "attachment; filename=rsolv-analytics-conversions-invalid.csv"
             ]
    end
  end
end
