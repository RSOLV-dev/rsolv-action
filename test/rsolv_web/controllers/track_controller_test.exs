defmodule RsolvWeb.TrackControllerTest do
  use RsolvWeb.ConnCase
  import ExUnit.CaptureLog

  describe "track/2" do
    test "handles page_view event", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "page_view",
              "data" => %{
                "page" => "/home",
                "referrer" => "https://google.com"
              }
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: page_view"
    end

    test "handles form_submit event", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "form_submit",
              "data" => %{
                "form_id" => "contact-form",
                "status" => "success"
              }
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: form_submit"
    end

    test "handles conversion event", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "conversion",
              "data" => %{
                "conversion_type" => "signup"
              }
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: conversion"
    end

    test "handles JSON string data", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "custom",
              "data" => Jason.encode!(%{"custom_field" => "value"})
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: custom"
    end

    test "handles malformed JSON string data", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "custom",
              "data" => "not valid json"
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: custom"
    end

    test "handles missing event type", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "data" => %{"page" => "/home"}
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: unknown"
    end

    test "handles missing data", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            post(conn, "/api/track", %{
              "type" => "page_view"
            })

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Tracking event received: page_view"
    end

    test "includes request metadata", %{conn: conn} do
      log =
        capture_log(fn ->
          conn =
            conn
            |> put_req_header("user-agent", "Test Browser")
            |> post("/api/track", %{"type" => "test"})

          assert json_response(conn, 201) == %{"success" => true}
        end)

      assert log =~ "Test Browser"
    end

    test "handles all supported event types", %{conn: conn} do
      event_types = [
        "session_start",
        "session_end",
        "heartbeat",
        "click",
        "scroll_depth",
        "section_view",
        "exit_intent"
      ]

      for event_type <- event_types do
        log =
          capture_log(fn ->
            conn = post(conn, "/api/track", %{"type" => event_type})
            assert json_response(conn, 201) == %{"success" => true}
          end)

        assert log =~ "Tracking event received: #{event_type}"
      end
    end
  end
end
