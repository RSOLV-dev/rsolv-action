defmodule RsolvWeb.PageHTML do
  use RsolvWeb, :html

  embed_templates "page_html/*"

  def submit_early_access(conn, params) do
    RsolvWeb.PageController.submit_early_access(conn, params)
  end
end
