defmodule RsolvWeb.BlogController do
  use RsolvWeb, :controller

  alias RsolvWeb.Services.BlogService

  plug :check_blog_feature_flag

  def index(conn, _params) do
    posts = BlogService.list_posts()
    
    conn
    |> assign(:posts, posts)
    |> assign(:page_title, "RSOLV Blog - AI Security Insights")
    |> assign(:page_description, "Technical insights on AI security, vulnerability detection, and automated code analysis from the RSOLV team.")
    |> render(:index)
  end

  def show(conn, %{"slug" => slug}) do
    case BlogService.get_post(slug) do
      {:ok, post} ->
        if should_show_post?(post) do
          conn
          |> assign(:post, post)
          |> assign(:page_title, post.title)
          |> assign(:page_description, post.excerpt)
          |> assign(:page_type, "article")
          |> render(:show)
        else
          conn
          |> put_status(:not_found)
          |> put_view(RsolvWeb.ErrorHTML)
          |> render(:"404")
        end
      
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> put_view(RsolvWeb.ErrorHTML)
        |> render(:"404")
    end
  end

  def rss(conn, _params) do
    rss_xml = BlogService.generate_rss()
    
    conn
    |> put_resp_content_type("application/rss+xml")
    |> text(rss_xml)
  end

  defp check_blog_feature_flag(conn, _opts) do
    if FunWithFlags.enabled?(:blog) do
      conn
    else
      conn
      |> put_status(:not_found)
      |> put_view(RsolvWeb.ErrorHTML)
      |> render(:"404")
      |> halt()
    end
  end

  # Determine if a post should be visible based on its status and feature flags.
  # - Published posts are visible in all environments
  # - Draft posts are visible when display_draft_blog_posts feature flag is enabled
  defp should_show_post?(post) do
    case post.status do
      "published" -> true
      "draft" -> FunWithFlags.enabled?(:display_draft_blog_posts)
      _ -> false
    end
  end
end