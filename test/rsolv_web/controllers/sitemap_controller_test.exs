defmodule RsolvWeb.SitemapControllerTest do
  use RsolvWeb.ConnCase

  describe "GET /sitemap.xml" do
    test "returns XML sitemap with correct content type", %{conn: conn} do
      conn = get(conn, "/sitemap.xml")

      assert response_content_type(conn, :xml)
      assert response(conn, 200)

      body = response(conn, 200)
      assert body =~ "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      assert body =~ "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
      assert body =~ "<loc>https://rsolv.dev/</loc>"
      assert body =~ "<loc>https://rsolv.dev/blog</loc>"
      assert body =~ "<loc>https://rsolv.dev/privacy</loc>"
      assert body =~ "<loc>https://rsolv.dev/terms</loc>"
      assert body =~ "<lastmod>"
      assert body =~ "<changefreq>"
      assert body =~ "<priority>"
    end

    test "includes existing blog posts in sitemap", %{conn: conn} do
      # The blog posts are loaded from markdown files in priv/blog
      # We'll check for actual blog posts that exist
      conn = get(conn, "/sitemap.xml")
      body = response(conn, 200)

      # Check for known blog posts
      assert body =~ "<loc>https://rsolv.dev/blog/success-based-pricing</loc>"
    end
  end
end
