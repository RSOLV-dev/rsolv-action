defmodule RsolvWeb.Admin.DashboardHTML do
  use RsolvWeb, :html

  embed_templates "dashboard_html/*"

  def health_color(status) do
    case status do
      "Operational" -> "text-green-600"
      "Error" -> "text-red-600"
      _ -> "text-yellow-600"
    end
  end

  def format_relative_time(datetime) do
    now = NaiveDateTime.utc_now()
    diff_seconds = NaiveDateTime.diff(now, datetime)

    cond do
      diff_seconds < 60 ->
        "Just now"

      diff_seconds < 3600 ->
        minutes = div(diff_seconds, 60)
        "#{minutes} minute#{if minutes == 1, do: "", else: "s"} ago"

      diff_seconds < 86_400 ->
        hours = div(diff_seconds, 3600)
        "#{hours} hour#{if hours == 1, do: "", else: "s"} ago"

      diff_seconds < 604_800 ->
        days = div(diff_seconds, 86_400)
        "#{days} day#{if days == 1, do: "", else: "s"} ago"

      true ->
        Calendar.strftime(datetime, "%b %d, %Y")
    end
  end
end
