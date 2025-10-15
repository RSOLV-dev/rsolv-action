defmodule RsolvWeb.FeedbackDashLive do
  use RsolvWeb, :live_view
  require Logger
  alias Rsolv.Feedback

  def mount(_params, _session, socket) do
    # Get all feedback entries
    feedback =
      Feedback.list_entries()
      |> Enum.sort_by(
        fn f ->
          f.inserted_at
        end,
        :desc
      )

    # Get statistics
    total_count = Feedback.count_entries()
    recent_entries = Feedback.list_recent_entries(5)

    # Calculate rating distribution
    rating_distribution = calculate_rating_distribution(feedback)

    stats = %{
      total_feedback: total_count,
      rating_distribution: rating_distribution,
      recent_feedback: recent_entries
    }

    socket =
      socket
      |> assign(:feedback, feedback)
      |> assign(:stats, stats)
      |> assign(:filter, nil)
      |> assign(:current_path, "/dashboard/feedback")

    {:ok, socket}
  end

  def handle_params(_params, uri, socket) do
    # Parse the URI to get the current path
    parsed_uri = URI.parse(uri)

    {:noreply, assign(socket, :current_path, parsed_uri.path)}
  end

  def handle_event("filter", %{"type" => type}, socket) do
    filtered_feedback =
      if type == "all" do
        Feedback.list_entries()
      else
        # Filter by tags if we have a type filter
        Feedback.list_entries()
        |> Enum.filter(fn entry ->
          entry.tags && type in entry.tags
        end)
      end
      |> Enum.sort_by(
        fn f ->
          f.inserted_at
        end,
        :desc
      )

    socket =
      socket
      |> assign(:feedback, filtered_feedback)
      |> assign(:filter, if(type == "all", do: nil, else: type))

    {:noreply, socket}
  end

  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-10">
      <div class="flex items-center justify-between mb-8">
        <h1 class="text-3xl font-bold">Feedback Dashboard</h1>
        <div>
          <a href="/" class="btn-outline">Back to Home</a>
        </div>
      </div>
      
    <!-- Statistics Overview -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6">
          <h3 class="text-lg font-semibold mb-2">Total Feedback</h3>
          <p class="text-3xl font-bold">{@stats.total_feedback}</p>
        </div>

        <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6">
          <h3 class="text-lg font-semibold mb-2">Average Rating</h3>
          <p class="text-3xl font-bold">
            {calculate_average_rating(@feedback)}
          </p>
        </div>

        <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6">
          <h3 class="text-lg font-semibold mb-2">Rating Distribution</h3>
          <div class="text-sm">
            <%= for {rating, count} <- @stats.rating_distribution |> Enum.sort() do %>
              <div class="flex justify-between">
                <span>{rating} stars:</span>
                <span>{count}</span>
              </div>
            <% end %>
          </div>
        </div>
      </div>
      
    <!-- Filter Buttons -->
      <div class="mb-6 flex gap-2">
        <button
          phx-click="filter"
          phx-value-type="all"
          class={"btn btn-sm #{if is_nil(@filter), do: "btn-primary", else: "btn-outline"}"}
        >
          All Feedback
        </button>
        <button
          phx-click="filter"
          phx-value-type="general"
          class={"btn btn-sm #{if @filter == "general", do: "btn-primary", else: "btn-outline"}"}
        >
          General
        </button>
        <button
          phx-click="filter"
          phx-value-type="bug"
          class={"btn btn-sm #{if @filter == "bug", do: "btn-primary", else: "btn-outline"}"}
        >
          Bugs
        </button>
        <button
          phx-click="filter"
          phx-value-type="feature"
          class={"btn btn-sm #{if @filter == "feature", do: "btn-primary", else: "btn-outline"}"}
        >
          Features
        </button>
      </div>
      
    <!-- Feedback Table -->
      <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg overflow-hidden">
        <table class="w-full">
          <thead class="bg-white bg-opacity-10">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Email</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">
                Message
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Rating</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Tags</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Date</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white divide-opacity-10">
            <%= for entry <- @feedback do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  {entry.email || "Anonymous"}
                </td>
                <td class="px-6 py-4 text-sm">
                  <div class="max-w-xs overflow-hidden text-ellipsis">
                    {entry.message || ""}
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  <%= if entry.rating do %>
                    <%= for i <- 1..5 do %>
                      <span class={"#{if i <= entry.rating, do: "text-yellow-400", else: "text-gray-600"}"}>
                        ★
                      </span>
                    <% end %>
                  <% else %>
                    <span class="text-gray-500">N/A</span>
                  <% end %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  <%= if entry.tags && length(entry.tags) > 0 do %>
                    {Enum.join(entry.tags, ", ")}
                  <% else %>
                    <span class="text-gray-500">—</span>
                  <% end %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  {format_date(entry.inserted_at)}
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <%= if length(@feedback) == 0 do %>
          <div class="text-center py-8 text-gray-400">
            No feedback entries found.
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp calculate_rating_distribution(entries) do
    entries
    |> Enum.filter(& &1.rating)
    |> Enum.group_by(& &1.rating)
    |> Enum.map(fn {rating, items} -> {rating, length(items)} end)
    |> Map.new()
  end

  defp calculate_average_rating(entries) do
    rated_entries = Enum.filter(entries, & &1.rating)

    if Enum.empty?(rated_entries) do
      "N/A"
    else
      sum = Enum.reduce(rated_entries, 0, fn entry, acc -> acc + entry.rating end)
      avg = sum / length(rated_entries)
      :erlang.float_to_binary(avg, decimals: 1)
    end
  end

  defp format_date(nil), do: ""

  defp format_date(date) do
    Calendar.strftime(date, "%b %d, %Y %H:%M")
  end
end
