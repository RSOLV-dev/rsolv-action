defmodule RsolvWeb.ErrorHTML do
  @moduledoc """
  This module handles HTML error rendering for the API.
  Since this is primarily an API application, it renders simple text responses.
  """

  # The default is to render a plain text page based on
  # the template name. For example, "404.html" becomes
  # "Not Found".
  def render(template, _assigns) do
    Phoenix.Controller.status_message_from_template(template)
  end
end