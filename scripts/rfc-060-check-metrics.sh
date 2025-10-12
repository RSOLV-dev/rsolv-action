#!/bin/bash
# RFC-060 Metrics Monitoring Script
# Automated daily metrics check for Phase 6 monitoring

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
METRICS_URL="${RSOLV_METRICS_URL:-https://rsolv.dev/metrics}"
LOG_DIR="${RSOLV_LOG_DIR:-/tmp/rsolv-metrics-logs}"
DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOG_FILE="$LOG_DIR/metrics-check-$DATE.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Function to log with timestamp
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Function to fetch metric value
fetch_metric() {
    local metric_pattern="$1"
    curl -s "$METRICS_URL" | grep "$metric_pattern" | grep -v "^#"
}

# Function to extract counter value
extract_value() {
    local line="$1"
    echo "$line" | awk '{print $NF}'
}

# Function to calculate rate
calculate_rate() {
    local current="$1"
    local previous="$2"
    local time_diff="$3"  # in seconds

    if [ "$previous" = "0" ] || [ -z "$previous" ]; then
        echo "N/A"
    else
        echo "scale=2; ($current - $previous) / $time_diff * 60" | bc
    fi
}

log "=========================================="
log "RFC-060 Metrics Check - $TIMESTAMP"
log "=========================================="

# Check if metrics endpoint is accessible
if ! curl -sf "$METRICS_URL" > /dev/null; then
    log "${RED}ERROR: Cannot reach metrics endpoint at $METRICS_URL${NC}"
    exit 1
fi

log "${GREEN}✓ Metrics endpoint accessible${NC}"
log ""

# Fetch validation metrics
log "=== Validation Metrics ==="
validation_total=$(fetch_metric "rsolv_validation_executions_total")

if [ -z "$validation_total" ]; then
    log "${YELLOW}⚠ No validation metrics found${NC}"
else
    echo "$validation_total" | while read -r line; do
        value=$(extract_value "$line")
        log "  Validation Executions: $line"
    done
fi

# Fetch validation duration
validation_duration=$(fetch_metric "rsolv_validation_duration_milliseconds_sum")
validation_count=$(fetch_metric "rsolv_validation_duration_milliseconds_count")

if [ -n "$validation_duration" ] && [ -n "$validation_count" ]; then
    duration_sum=$(echo "$validation_duration" | awk '{print $NF}')
    count=$(echo "$validation_count" | awk '{print $NF}')
    if [ -n "$duration_sum" ] && [ -n "$count" ] && [ "$count" != "0" ]; then
        avg_duration=$(echo "scale=2; $duration_sum / $count" | bc)
        log "  Average Validation Duration: ${avg_duration}ms"
    fi
fi

log ""

# Fetch mitigation metrics
log "=== Mitigation Metrics ==="
mitigation_total=$(fetch_metric "rsolv_mitigation_executions_total")

if [ -z "$mitigation_total" ]; then
    log "${YELLOW}⚠ No mitigation metrics found yet${NC}"
else
    echo "$mitigation_total" | while read -r line; do
        log "  Mitigation Executions: $line"
    done
fi

# Fetch trust score if available
trust_score=$(fetch_metric "rsolv_mitigation_trust_score_value_sum")
trust_count=$(fetch_metric "rsolv_mitigation_trust_score_value_count")

if [ -n "$trust_score" ] && [ -n "$trust_count" ]; then
    score_sum=$(echo "$trust_score" | awk '{print $NF}')
    count=$(echo "$trust_count" | awk '{print $NF}')
    avg_trust=$(echo "scale=2; $score_sum / $count" | bc)
    log "  Average Trust Score: ${avg_trust}"

    # Check against thresholds
    threshold=$(echo "$avg_trust >= 80" | bc)
    if [ "$threshold" -eq 1 ]; then
        log "  ${GREEN}✓ Trust score above 80% threshold${NC}"
    else
        log "  ${YELLOW}⚠ Trust score below 80% threshold${NC}"
    fi
fi

log ""

# Calculate success rates
log "=== Success Rates ==="

completed=$(fetch_metric 'rsolv_validation_executions_total{.*status="completed"' | awk '{sum+=$NF} END {print sum}')
failed=$(fetch_metric 'rsolv_validation_executions_total{.*status="failed"' | awk '{sum+=$NF} END {print sum}')
total=$((completed + failed))

if [ "$total" -gt 0 ]; then
    success_rate=$(echo "scale=2; $completed / $total * 100" | bc)
    log "  Validation Success Rate: ${success_rate}%"
    log "    Completed: $completed"
    log "    Failed: $failed"
    log "    Total: $total"

    # Check against threshold
    threshold=$(echo "$success_rate >= 85" | bc)
    if [ "$threshold" -eq 1 ]; then
        log "  ${GREEN}✓ Success rate above 85% threshold${NC}"
    else
        log "  ${YELLOW}⚠ Success rate below 85% threshold${NC}"
    fi
else
    log "  ${YELLOW}No execution data yet${NC}"
fi

log ""
log "=========================================="
log "Check complete. Log saved to: $LOG_FILE"
log "=========================================="

# Summary for cron/notification
echo ""
echo "Quick Summary:"
echo "  Validation Executions: ${total:-0}"
echo "  Success Rate: ${success_rate:-N/A}%"
echo "  Average Trust Score: ${avg_trust:-N/A}"
