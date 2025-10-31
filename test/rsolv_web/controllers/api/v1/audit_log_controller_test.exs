defmodule RsolvWeb.Api.V1.AuditLogControllerTest do
  use RsolvWeb.ConnCase, async: false

  alias Rsolv.AST.AuditLogger

  setup do
    # Clear buffer before each test
    AuditLogger.clear_buffer()
    :ok
  end

  describe "GET /api/v1/audit-logs/:id" do
    test "returns audit event when found", %{conn: conn} do
      # Create a test event
      event =
        AuditLogger.log_event(:session_created, %{
          session_id: "test_session_123",
          customer_id: "customer_456"
        })

      conn = get(conn, ~p"/api/v1/audit-logs/#{event.id}")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert response["event"]["id"] == event.id
      assert response["event"]["event_type"] == "session_created"
    end

    test "returns 404 when event not found", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/audit-logs/nonexistent_id")

      assert conn.status == 404
      response = json_response(conn, 404)
      assert response["error"] == "Audit event not found"
    end
  end

  describe "GET /api/v1/audit-logs" do
    test "returns list of audit events", %{conn: conn} do
      # Create test events
      AuditLogger.log_event(:session_created, %{session_id: "test_1"})
      AuditLogger.log_event(:file_encrypted, %{file_id: "file_1"})

      conn = get(conn, ~p"/api/v1/audit-logs")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert is_list(response["events"])
      assert response["total"] >= 2
    end

    test "filters events by event_type", %{conn: conn} do
      # Create events of different types
      AuditLogger.log_event(:session_created, %{session_id: "test_1"})
      AuditLogger.log_event(:file_encrypted, %{file_id: "file_1"})
      AuditLogger.log_event(:session_created, %{session_id: "test_2"})

      conn = get(conn, ~p"/api/v1/audit-logs?event_type=session_created")

      assert conn.status == 200
      response = json_response(conn, 200)

      # All returned events should be session_created
      Enum.each(response["events"], fn event ->
        assert event["event_type"] == "session_created"
      end)
    end

    test "filters events by severity", %{conn: conn} do
      # Create events with different severities
      AuditLogger.log_event(:session_created, %{session_id: "test_1"})
      AuditLogger.log_event(:malicious_input_detected, %{details: "test"})

      conn = get(conn, ~p"/api/v1/audit-logs?severity=critical")

      assert conn.status == 200
      response = json_response(conn, 200)

      # All returned events should be critical severity
      Enum.each(response["events"], fn event ->
        assert event["severity"] == "critical"
      end)
    end

    test "returns empty list when no events match filter", %{conn: conn} do
      AuditLogger.log_event(:session_created, %{session_id: "test_1"})

      conn = get(conn, ~p"/api/v1/audit-logs?event_type=nonexistent_type")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert response["events"] == []
      assert response["total"] == 0
    end

    test "handles query with correlation_id filter", %{conn: conn} do
      correlation_id = AuditLogger.generate_correlation_id()

      AuditLogger.log_event(:session_created, %{session_id: "test_1"},
        correlation_id: correlation_id
      )

      AuditLogger.log_event(:file_encrypted, %{file_id: "file_1"})

      conn = get(conn, ~p"/api/v1/audit-logs?correlation_id=#{correlation_id}")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert length(response["events"]) == 1
      assert hd(response["events"])["correlation_id"] == correlation_id
    end
  end
end
