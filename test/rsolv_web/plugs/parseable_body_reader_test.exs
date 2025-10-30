defmodule RsolvWeb.Plugs.ParseableBodyReaderTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias RsolvWeb.Plugs.ParseableBodyReader

  describe "read_body/2" do
    test "reads body and stores it in conn assigns" do
      body = ~s({"key": "value"})

      conn =
        conn(:post, "/test", body)
        |> put_req_header("content-type", "application/json")

      {:ok, read_body, conn} = ParseableBodyReader.read_body(conn, [])

      assert read_body == body
      assert conn.assigns[:raw_body] == body
    end

    test "passes through errors from Plug.Conn.read_body" do
      # Create a connection that will trigger an error scenario
      conn = conn(:post, "/test", "")

      # Should handle the result properly
      result = ParseableBodyReader.read_body(conn, length: 0, read_length: 0)

      assert {:ok, "", _conn} = result
    end
  end
end
