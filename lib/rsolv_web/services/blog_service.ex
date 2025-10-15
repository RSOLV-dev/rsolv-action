defmodule RsolvWeb.Services.BlogService do
  @moduledoc """
  Service for handling blog post operations including parsing markdown,
  extracting frontmatter, and generating RSS feeds.
  """

  require Logger

  @site_url "https://rsolv.dev"

  defp blog_dir do
    Application.app_dir(:rsolv, "priv/blog")
  end

  @doc """
  Get a single blog post by slug.
  """
  def get_post(slug) do
    # Sanitize slug to prevent path traversal
    sanitized_slug = sanitize_slug(slug)

    if sanitized_slug != slug do
      {:error, :not_found}
    else
      file_path = Path.join([blog_dir(), "#{sanitized_slug}.md"])

      case File.read(file_path) do
        {:ok, content} ->
          # parse_frontmatter always returns {:ok, metadata, markdown}
          {:ok, metadata, markdown} = parse_frontmatter(content)
          {:ok, build_post(sanitized_slug, metadata, markdown)}

        {:error, :enoent} ->
          {:error, :not_found}

        {:error, reason} ->
          Logger.error("Failed to read blog post #{slug}: #{inspect(reason)}")
          {:error, :read_error}
      end
    end
  end

  @doc """
  List all available blog posts, sorted by published date (newest first).
  Posts are filtered based on their status and the current environment:
  - Published posts are visible in all environments
  - Draft posts are only visible in development
  """
  def list_posts do
    case File.ls(blog_dir()) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".md"))
        |> Enum.map(fn filename ->
          slug = String.replace_suffix(filename, ".md", "")

          case get_post(slug) do
            {:ok, post} -> post
            _ -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.filter(&should_show_post?/1)
        |> Enum.sort_by(& &1.published_at, {:desc, Date})

      {:error, :enoent} ->
        # Blog directory doesn't exist yet
        []

      {:error, reason} ->
        Logger.error("Failed to list blog posts: #{inspect(reason)}")
        []
    end
  end

  @doc """
  Generate RSS feed XML for published blog posts only.
  RSS feeds should only include published content regardless of environment.
  """
  def generate_rss do
    posts =
      list_all_posts()
      |> Enum.filter(&(&1.status == "published"))

    """
    <?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>RSOLV Blog</title>
        <link>#{@site_url}/blog</link>
        <description>AI Security Insights and Vulnerability Analysis</description>
        <language>en-us</language>
        <lastBuildDate>#{format_rss_date(DateTime.utc_now())}</lastBuildDate>
        #{Enum.map_join(posts, "\n", &format_rss_item/1)}
      </channel>
    </rss>
    """
  end

  @doc """
  List all blog posts without environment filtering.
  This is exposed for testing purposes.
  """
  def list_all_posts_unfiltered do
    list_all_posts()
  end

  # List all blog posts without environment filtering (used internally for RSS).
  defp list_all_posts do
    case File.ls(blog_dir()) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".md"))
        |> Enum.map(fn filename ->
          slug = String.replace_suffix(filename, ".md", "")

          case get_post(slug) do
            {:ok, post} -> post
            _ -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.sort_by(& &1.published_at, {:desc, Date})

      {:error, :enoent} ->
        []

      {:error, reason} ->
        Logger.error("Failed to list all blog posts: #{inspect(reason)}")
        []
    end
  end

  # Determine if a post should be visible based on its status and current environment.
  # - Published posts are visible in all environments
  # - Draft posts are visible when display_draft_blog_posts feature flag is enabled
  defp should_show_post?(post) do
    case post.status do
      "published" -> true
      "draft" -> FunWithFlags.enabled?(:display_draft_blog_posts)
      _ -> false
    end
  end

  @doc """
  Parse YAML frontmatter from markdown content.

  ## Examples

      iex> content = \"\"\"
      ...> ---
      ...> title: "Test Post"
      ...> status: "draft"
      ...> ---
      ...>
      ...> Content here
      ...> \"\"\"
      iex> {:ok, metadata, markdown} = RsolvWeb.Services.BlogService.parse_frontmatter(content)
      iex> metadata["title"]
      "Test Post"
      iex> metadata["status"]
      "draft"
      iex> String.trim(markdown)
      "Content here"

      iex> content = "No frontmatter here"
      iex> {:ok, metadata, markdown} = RsolvWeb.Services.BlogService.parse_frontmatter(content)
      iex> metadata
      %{}
      iex> markdown
      "No frontmatter here"
  """
  def parse_frontmatter(content) do
    case String.split(content, "---", parts: 3) do
      ["", frontmatter, markdown] ->
        # Has frontmatter
        case YamlElixir.read_from_string(frontmatter) do
          {:ok, metadata} ->
            {:ok, metadata, String.trim(markdown)}

          {:error, reason} ->
            Logger.warning("Failed to parse YAML frontmatter: #{inspect(reason)}")
            {:ok, %{}, content}
        end

      _ ->
        # No frontmatter
        {:ok, %{}, content}
    end
  rescue
    _ ->
      # Fallback if YamlElixir is not available
      parse_simple_frontmatter(content)
  end

  # Simple frontmatter parser fallback
  defp parse_simple_frontmatter(content) do
    case String.split(content, "---", parts: 3) do
      ["", frontmatter, markdown] ->
        metadata =
          frontmatter
          |> String.split("\n")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))
          |> Enum.reduce(%{}, fn line, acc ->
            case String.split(line, ":", parts: 2) do
              [key, value] ->
                parsed_value = parse_yaml_value(String.trim(value))
                Map.put(acc, String.trim(key), parsed_value)

              _ ->
                acc
            end
          end)

        {:ok, metadata, String.trim(markdown)}

      _ ->
        {:ok, %{}, content}
    end
  end

  defp parse_yaml_value(value) do
    cond do
      # Handle arrays like ["tag1", "tag2"]
      String.starts_with?(value, "[") and String.ends_with?(value, "]") ->
        value
        |> String.slice(1..-2//1)
        |> String.split(",")
        |> Enum.map(&String.trim/1)
        |> Enum.map(&String.trim(&1, "\""))

      # Handle quoted strings
      String.starts_with?(value, "\"") and String.ends_with?(value, "\"") ->
        String.slice(value, 1..-2//1)

      # Handle dates
      String.match?(value, ~r/^\d{4}-\d{2}-\d{2}$/) ->
        case Date.from_iso8601(value) do
          {:ok, date} -> date
          _ -> value
        end

      # Handle numbers
      String.match?(value, ~r/^\d+$/) ->
        case Integer.parse(value) do
          {int_value, ""} -> int_value
          _ -> value
        end

      # Default string
      true ->
        value
    end
  end

  defp sanitize_slug(slug) do
    slug
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9\-]/, "")
    # Limit length
    |> String.slice(0, 100)
  end

  defp remove_duplicate_title(markdown, title) when is_binary(title) do
    # Match H1 at the beginning of the content (after optional whitespace)
    # that matches the title from metadata
    pattern = ~r/^\s*#\s+#{Regex.escape(title)}\s*\n/

    case Regex.match?(pattern, markdown) do
      true -> Regex.replace(pattern, markdown, "", global: false)
      false -> markdown
    end
  end

  defp remove_duplicate_title(markdown, _), do: markdown

  defp build_post(slug, metadata, markdown) do
    # Remove duplicate H1 if it matches the title
    markdown_cleaned = remove_duplicate_title(markdown, Map.get(metadata, "title"))

    # Convert markdown to HTML with MDEx - includes syntax highlighting
    html =
      MDEx.to_html!(markdown_cleaned,
        extension: [
          strikethrough: true,
          table: true,
          autolink: true,
          tasklist: true,
          footnotes: true,
          shortcodes: true
        ],
        parse: [smart: true],
        render: [unsafe_: true]
      )

    %{
      slug: slug,
      title: Map.get(metadata, "title", "Untitled"),
      excerpt: Map.get(metadata, "excerpt", ""),
      status: Map.get(metadata, "status", "draft"),
      content: markdown,
      html: html,
      tags: Map.get(metadata, "tags", []),
      category: Map.get(metadata, "category", "general"),
      published_at: parse_date(Map.get(metadata, "published_at")),
      reading_time:
        parse_reading_time(Map.get(metadata, "reading_time", estimate_reading_time(markdown)))
    }
  end

  defp parse_date(nil), do: Date.utc_today()
  defp parse_date(%Date{} = date), do: date

  defp parse_date(date_string) when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} -> date
      _ -> Date.utc_today()
    end
  end

  defp parse_date(_), do: Date.utc_today()

  defp parse_reading_time(time) when is_integer(time), do: time

  defp parse_reading_time(time) when is_binary(time) do
    case Integer.parse(time) do
      {int_time, _} -> int_time
      :error -> 1
    end
  end

  defp parse_reading_time(_), do: 1

  defp estimate_reading_time(content) do
    word_count =
      content
      |> String.split()
      |> length()

    # Average reading speed: 200 words per minute
    max(1, div(word_count, 200))
  end

  defp format_rss_item(post) do
    """
        <item>
          <title>#{escape_xml(post.title)}</title>
          <link>#{@site_url}/blog/#{post.slug}</link>
          <description>#{escape_xml(post.excerpt)}</description>
          <pubDate>#{format_rss_date(post.published_at)}</pubDate>
          <guid>#{@site_url}/blog/#{post.slug}</guid>
        </item>
    """
  end

  defp format_rss_date(%Date{} = date) do
    date
    |> Date.to_erl()
    |> then(fn {y, m, d} -> {{y, m, d}, {0, 0, 0}} end)
    |> NaiveDateTime.from_erl!()
    |> DateTime.from_naive!("Etc/UTC")
    |> format_rss_date()
  end

  defp format_rss_date(%DateTime{} = datetime) do
    datetime
    |> Calendar.strftime("%a, %d %b %Y %H:%M:%S %z")
  end

  defp escape_xml(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end
end
