defmodule RSOLVWeb.ErrorJSON do
  @moduledoc """
  This module is invoked by Phoenix on errors.
  """

  def render(template, _assigns) do
    %{errors: %{detail: Phoenix.Controller.status_message_from_template(template)}}
  end
end