defmodule RsolvWeb.Admin.SessionController do
  use RsolvWeb, :controller

  def new(conn, _params) do
    render(conn, :new, error_message: nil)
  end
end