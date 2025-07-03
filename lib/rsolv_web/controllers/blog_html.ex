defmodule RsolvWeb.BlogHTML do
  use RsolvWeb, :html

  embed_templates "blog_html/*"

  @doc """
  Formats a date for display in the blog listing.
  """
  def format_date(%Date{} = date) do
    Calendar.strftime(date, "%B %d, %Y")
  end
  
  def format_date(_), do: ""
end