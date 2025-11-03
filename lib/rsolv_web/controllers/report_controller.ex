defmodule RsolvWeb.ReportController do
  use RsolvWeb, :controller
  require Logger
  alias Rsolv.Analytics

  @doc """
  Generate and download analytics report in CSV or JSON format
  """
  def download(conn, params) do
    # Extract parameters
    report_type = params["type"] || "conversions"
    format = params["format"] || "csv"
    period = params["period"] || "30d"

    # Convert period to date range
    {since, until} = period_to_date_range(period)

    # Map report type to data type
    data_type =
      case report_type do
        "conversions" -> :conversions
        "page_views" -> :page_views
        "traffic" -> :page_views
        "form_events" -> :form_events
        "engagement" -> :events
        "signup" -> :conversions
        _ -> :conversions
      end

    # Fetch data - query_data always returns {:ok, result}
    {:ok, data} = Analytics.query_data(data_type, since: since, until: until)

    # Generate filename
    filename = "rsolv-analytics-#{report_type}-#{period}.#{format}"

    # Format data based on requested format
    content =
      case format do
        "csv" -> generate_csv(data)
        "json" -> JSON.encode!(data)
        _ -> JSON.encode!(data)
      end

    # Set content type based on format
    content_type =
      case format do
        "csv" -> "text/csv"
        "json" -> "application/json"
        _ -> "application/octet-stream"
      end

    # Log the download
    Logger.info(
      "Analytics report downloaded, report_type: #{report_type}, format: #{format}, period: #{period}, record_count: #{length(data)}"
    )

    # Return file for download
    conn
    |> put_resp_content_type(content_type)
    |> put_resp_header("content-disposition", "attachment; filename=#{filename}")
    |> send_resp(200, content)
  end

  # Helper to generate CSV from data
  defp generate_csv(data) do
    if Enum.empty?(data) do
      "No data available"
    else
      # Get headers from first entry
      sample = List.first(data)
      headers = Map.keys(sample) |> Enum.join(",")

      # Generate rows
      rows =
        Enum.map(data, fn entry ->
          Map.values(entry)
          |> Enum.map(fn value ->
            if is_binary(value),
              do: "\"#{String.replace(value, "\"", "\"\"")}\",",
              else: "#{value},"
          end)
          |> Enum.join("")
          |> String.trim_trailing(",")
        end)

      [headers | rows] |> Enum.join("\n")
    end
  end

  # Convert period string to actual date range
  defp period_to_date_range(period) do
    today = Date.utc_today()

    since =
      case period do
        "1d" -> Date.add(today, -1)
        "7d" -> Date.add(today, -7)
        "30d" -> Date.add(today, -30)
        "90d" -> Date.add(today, -90)
        # For simplicity, we'll use a year for "all"
        "all" -> Date.add(today, -365)
        # Default to 30 days
        _ -> Date.add(today, -30)
      end

    {since, today}
  end
end
