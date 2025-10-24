defmodule RsolvWeb.SitemapController do
  use RsolvWeb, :controller

  def index(conn, _params) do
    sitemap = generate_sitemap()

    conn
    |> put_resp_content_type("application/xml")
    |> send_resp(200, sitemap)
  end

  defp generate_sitemap do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      #{url_entry("https://rsolv.dev/", "1.0", "daily")}
      #{url_entry("https://rsolv.dev/blog", "0.9", "weekly")}
      #{url_entry("https://rsolv.dev/privacy", "0.3", "monthly")}
      #{url_entry("https://rsolv.dev/terms", "0.3", "monthly")}
      #{url_entry("https://rsolv.dev/dashboard", "0.5", "weekly")}
      #{docs_entries()}
      #{blog_post_entries()}
    </urlset>
    """
  end

  defp url_entry(loc, priority, changefreq) do
    """
      <url>
        <loc>#{loc}</loc>
        <lastmod>#{format_date(DateTime.utc_now())}</lastmod>
        <changefreq>#{changefreq}</changefreq>
        <priority>#{priority}</priority>
      </url>
    """
  end

  defp docs_entries do
    # Documentation pages (high priority for GitHub Marketplace)
    [
      {"https://docs.rsolv.dev/", "0.9", "weekly"},
      {"https://docs.rsolv.dev/installation", "1.0", "weekly"},
      {"https://docs.rsolv.dev/getting-started", "0.9", "weekly"},
      {"https://docs.rsolv.dev/troubleshooting", "0.9", "weekly"},
      {"https://docs.rsolv.dev/api-reference", "0.8", "weekly"},
      {"https://docs.rsolv.dev/workflows", "0.8", "weekly"},
      {"https://docs.rsolv.dev/configuration", "0.8", "weekly"},
      {"https://docs.rsolv.dev/faq", "0.7", "monthly"}
    ]
    |> Enum.map(fn {url, priority, freq} -> url_entry(url, priority, freq) end)
    |> Enum.join("\n")
  end

  defp blog_post_entries do
    posts = RsolvWeb.Services.BlogService.list_posts()

    posts
    |> Enum.filter(&(&1.status == "published"))
    |> Enum.map(fn post ->
      url_entry(
        "https://rsolv.dev/blog/#{post.slug}",
        "0.7",
        "monthly"
      )
    end)
    |> Enum.join("\n")
  end

  defp format_date(datetime) do
    datetime
    |> DateTime.to_date()
    |> Date.to_iso8601()
  end
end
