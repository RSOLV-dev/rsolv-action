defmodule RsolvWeb.DocsHTML do
  @moduledoc """
  HTML templates for documentation pages
  """
  use RsolvWeb, :html
  use RsolvWeb.Components.Docs

  embed_templates "docs_html/*"
end
