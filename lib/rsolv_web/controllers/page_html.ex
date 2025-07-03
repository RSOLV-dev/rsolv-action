defmodule RsolvWeb.PageHTML do
  @moduledoc """
  This module contains pages rendered by PageController.
  """
  use RsolvWeb, :html

  embed_templates "page_html/*"
end