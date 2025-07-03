defmodule RsolvWeb.BlogHTML do
  @moduledoc """
  This module contains pages rendered by BlogController.
  """
  use RsolvWeb, :html

  embed_templates "blog_html/*"

  @doc """
  Format a date for display.
  """
  def format_date(%Date{} = date) do
    Calendar.strftime(date, "%B %d, %Y")
  end

  @doc """
  Generate reading time text.
  """
  def reading_time(minutes) when is_integer(minutes) do
    case minutes do
      1 -> "1 minute read"
      n when n > 1 -> "#{n} minutes read"
      _ -> "Quick read"
    end
  end

  def reading_time(minutes) when is_binary(minutes) do
    case Integer.parse(minutes) do
      {int_minutes, _} -> reading_time(int_minutes)
      :error -> "Quick read"
    end
  end

  def reading_time(_), do: "Quick read"

  @doc """
  Generate tag links for blog posts.
  """
  def tag_links(tags) when is_list(tags) do
    assigns = %{tags: tags}
    ~H"""
    <%= for tag <- @tags do %>
      <span class="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-2 mb-2">
        <%= tag %>
      </span>
    <% end %>
    """
  end

  @doc """
  Truncate text for excerpts.
  """
  def truncate(text, length \\ 150) do
    if String.length(text) <= length do
      text
    else
      text
      |> String.slice(0, length)
      |> String.trim()
      |> Kernel.<>("...")
    end
  end

  @doc """
  Generate HTML meta tags for SEO.
  """
  def html_meta_tags(assigns) do
    ~H"""
    <meta name="description" content={assigns[:description] || "RSOLV AI Security Blog"} />
    <meta property="og:title" content={assigns[:title] || "RSOLV Blog"} />
    <meta property="og:description" content={assigns[:description] || "AI Security Insights"} />
    <meta property="og:type" content={assigns[:type] || "website"} />
    <meta property="og:url" content={assigns[:url] || "https://rsolv.dev/blog"} />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content={assigns[:title] || "RSOLV Blog"} />
    <meta name="twitter:description" content={assigns[:description] || "AI Security Insights"} />
    """
  end
end