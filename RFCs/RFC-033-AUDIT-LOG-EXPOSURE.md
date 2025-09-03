# RFC-033: Audit Log Exposure and Observability

**Status**: Proposed  
**Created**: 2025-06-27  
**Author**: RSOLV Engineering Team

## Summary

Design a comprehensive strategy for exposing AST service audit logs through standard observability platforms including Prometheus, Grafana, and OpenTelemetry.

## Motivation

We've implemented comprehensive audit logging for the AST service (Phase 6.2), but the logs are currently only stored in ETS and accessible via API calls. For production operations, we need:

1. Real-time security monitoring dashboards
2. Alerting on suspicious activities
3. Compliance reporting capabilities
4. Long-term storage and analysis
5. Integration with existing observability stack

## Current State

### What We Have
- Comprehensive audit logging via `AuditLogger` module
- Structured events with severity levels
- Correlation ID tracking
- Security event aggregation
- CSV export capability
- ETS-based storage (in-memory)

### What's Missing
- Prometheus metrics export
- Grafana dashboard
- OpenTelemetry integration
- Persistent storage backend
- Real-time alerting
- Log forwarding to SIEM

## Proposed Design

### 1. Prometheus Metrics

Create a PromEx plugin for audit metrics:

```elixir
defmodule RSOLV.PromEx.AuditLogPlugin do
  use PromEx.Plugin
  
  @impl true
  def event_metrics(_opts) do
    [
      security_events_metrics(),
      parser_lifecycle_metrics(),
      session_metrics()
    ]
  end
  
  defp security_events_metrics do
    Event.build(
      :audit_security_events,
      [
        counter("rsolv.audit.security_events.total",
          event_name: [:audit, :security, :event],
          description: "Total security events by type and severity",
          tags: [:event_type, :severity]
        ),
        
        distribution("rsolv.audit.parse_time.milliseconds",
          event_name: [:ast, :parse, :complete],
          description: "AST parsing time distribution",
          tags: [:language, :status],
          unit: {:native, :millisecond}
        )
      ]
    )
  end
end
```

### 2. Telemetry Integration

Emit telemetry events from AuditLogger:

```elixir
# In AuditLogger
defp emit_telemetry(event) do
  :telemetry.execute(
    [:audit, event.category || :general, :event],
    %{count: 1},
    %{
      event_type: event.event_type,
      severity: event.severity,
      node: event.node
    }
  )
end
```

### 3. Grafana Dashboard

Create a dedicated security dashboard with:
- Security events timeline (by type/severity)
- Parser health metrics (crashes, timeouts)
- Session lifecycle tracking
- Rate limiting violations
- Top security violations by customer
- Correlation ID trace view

### 4. Persistent Storage Options

#### Option A: PostgreSQL with TimescaleDB
```sql
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  correlation_id UUID,
  metadata JSONB,
  node TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TimescaleDB hypertable for time-series optimization
SELECT create_hypertable('audit_logs', 'timestamp');
```

#### Option B: Elasticsearch Integration
- Ship logs via Logstash
- Rich querying capabilities
- Built-in retention policies
- Kibana for visualization

#### Option C: AWS CloudWatch Logs
- Managed service approach
- Integration with AWS security tools
- Cost-effective for moderate volume

### 5. Real-time Streaming

Implement Phoenix PubSub for real-time audit events:

```elixir
defmodule RsolvApi.AST.AuditBroadcaster do
  def broadcast_event(event) do
    Phoenix.PubSub.broadcast(
      RSOLV.PubSub,
      "audit:#{event.severity}",
      {:audit_event, event}
    )
  end
end
```

### 6. OpenTelemetry Export

```elixir
defmodule RsolvApi.AST.AuditLogger.OtelExporter do
  def export_span(event) do
    OpentelemetryTelemetry.start_telemetry_span(
      "rsolv.audit",
      %{kind: :internal},
      %{time: event.timestamp}
    )
    |> Span.set_attributes(%{
      "audit.event_type" => event.event_type,
      "audit.severity" => event.severity,
      "audit.correlation_id" => event.correlation_id
    })
    |> Span.end_span()
  end
end
```

## Implementation Plan

### Phase 1: Telemetry & Metrics (1 week)
1. Add telemetry events to AuditLogger
2. Create PromEx plugin
3. Update existing Grafana dashboards

### Phase 2: Persistent Storage (1 week)
1. Implement PostgreSQL backend
2. Add background flushing from ETS
3. Create retention policies

### Phase 3: Real-time Features (3 days)
1. Add PubSub broadcasting
2. Create WebSocket endpoint for live monitoring
3. Build alerting rules

### Phase 4: External Integration (1 week)
1. OpenTelemetry exporter
2. Logstash shipper for SIEM
3. CloudWatch integration (if using AWS)

## Security Considerations

1. **Access Control**: Audit logs contain sensitive security information
2. **Data Retention**: Comply with privacy regulations (GDPR, etc.)
3. **Log Tampering**: Ensure audit trail integrity
4. **Performance Impact**: Minimize overhead on production traffic

## Alternatives Considered

1. **Direct Prometheus export**: Too limited for rich audit data
2. **File-based logging**: Difficult to query and analyze
3. **Third-party APM**: Vendor lock-in concerns

## Success Metrics

- < 5ms overhead per audit event
- 99.9% audit event delivery guarantee
- < 1 minute from event to dashboard visibility
- Support for 1M+ events/day
- 90-day retention capability

## Future Enhancements

1. Machine learning for anomaly detection
2. Automated incident response triggers
3. Compliance report generation
4. Multi-region log aggregation