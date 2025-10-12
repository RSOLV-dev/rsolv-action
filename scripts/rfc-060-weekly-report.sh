#!/bin/bash
# RFC-060 Weekly Metrics Report
# Generate weekly summary of RFC-060 Phase 6 monitoring

set -euo pipefail

# Configuration
METRICS_URL="${RSOLV_METRICS_URL:-https://rsolv.dev/metrics}"
WEEK=$(date +%Y-W%V)
REPORT_FILE="/tmp/rfc-060-week-$WEEK-report.md"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "Generating RFC-060 Weekly Report for Week $WEEK..."

# Function to fetch and summarize metrics
fetch_summary() {
    local metric="$1"
    curl -s "$METRICS_URL" | grep "^$metric" | grep -v "^#"
}

# Generate report
cat > "$REPORT_FILE" << EOF
# RFC-060 Phase 6 Weekly Report

**Week**: $WEEK
**Generated**: $(date +'%Y-%m-%d %H:%M:%S')

## Validation Metrics Summary

### Total Executions
\`\`\`
$(fetch_summary "rsolv_validation_executions_total")
\`\`\`

### Duration Statistics
\`\`\`
$(fetch_summary "rsolv_validation_duration_milliseconds_sum")
$(fetch_summary "rsolv_validation_duration_milliseconds_count")
\`\`\`

## Mitigation Metrics Summary

### Total Executions
\`\`\`
$(fetch_summary "rsolv_mitigation_executions_total" || echo "No mitigation metrics yet")
\`\`\`

### Trust Scores
\`\`\`
$(fetch_summary "rsolv_mitigation_trust_score" || echo "No trust score metrics yet")
\`\`\`

## Analysis

EOF

# Calculate success rate
completed=$(fetch_summary 'rsolv_validation_executions_total{.*status="completed"' | awk '{sum+=$NF} END {print sum}')
failed=$(fetch_summary 'rsolv_validation_executions_total{.*status="failed"' | awk '{sum+=$NF} END {print sum}')
total=$((completed + failed))

if [ "$total" -gt 0 ]; then
    success_rate=$(echo "scale=2; $completed / $total * 100" | bc)
    cat >> "$REPORT_FILE" << EOF
### Success Rate

- **Total Validations**: $total
- **Completed**: $completed
- **Failed**: $failed
- **Success Rate**: ${success_rate}%

EOF

    if (( $(echo "$success_rate >= 85" | bc -l) )); then
        echo "✓ **Status**: Success rate meets >85% target" >> "$REPORT_FILE"
    else
        echo "⚠ **Status**: Success rate below 85% target" >> "$REPORT_FILE"
    fi
else
    cat >> "$REPORT_FILE" << EOF
### Success Rate

No execution data available for this period.

EOF
fi

# Calculate average trust score if available
trust_sum=$(fetch_summary "rsolv_mitigation_trust_score_value_sum" | awk '{print $NF}')
trust_count=$(fetch_summary "rsolv_mitigation_trust_score_value_count" | awk '{print $NF}')

if [ -n "$trust_sum" ] && [ -n "$trust_count" ] && [ "$trust_count" != "0" ]; then
    avg_trust=$(echo "scale=2; $trust_sum / $trust_count" | bc)
    cat >> "$REPORT_FILE" << EOF

### Trust Score

- **Average Trust Score**: ${avg_trust}

EOF

    if (( $(echo "$avg_trust >= 80" | bc -l) )); then
        echo "✓ **Status**: Trust score meets >80% target" >> "$REPORT_FILE"
    else
        echo "⚠ **Status**: Trust score below 80% target" >> "$REPORT_FILE"
    fi
else
    cat >> "$REPORT_FILE" << EOF

### Trust Score

No trust score data available yet (mitigations may not have run).

EOF
fi

# Add recommendations section
cat >> "$REPORT_FILE" << EOF

## Recommendations

Based on this week's metrics:

EOF

if [ "$total" -eq 0 ]; then
    echo "- ⚠ **No validation executions recorded** - Verify workflows are running" >> "$REPORT_FILE"
elif [ -n "$success_rate" ] && (( $(echo "$success_rate < 85" | bc -l) )); then
    echo "- ⚠ **Review failed validations** - Success rate below target" >> "$REPORT_FILE"
else
    echo "- ✓ **Validation performance good** - Continue monitoring" >> "$REPORT_FILE"
fi

if [ -n "$avg_trust" ]; then
    if (( $(echo "$avg_trust < 80" | bc -l) )); then
        echo "- ⚠ **Consider RFC-061 Phase 2** - Trust scores below threshold" >> "$REPORT_FILE"
    else
        echo "- ✓ **Trust scores acceptable** - Continue Phase 1 monitoring" >> "$REPORT_FILE"
    fi
fi

cat >> "$REPORT_FILE" << EOF

## Next Steps

1. Review detailed metrics in Grafana: http://localhost:3000/d/rfc-060-validation
2. Check failed validation logs if success rate is low
3. Run additional test workflows if data volume is low
4. Continue daily monitoring routine

---

**Dashboard**: http://localhost:3000/d/rfc-060-validation
**Metrics Endpoint**: $METRICS_URL
**Script**: \`scripts/rfc-060-weekly-report.sh\`
EOF

echo -e "${GREEN}✓ Weekly report generated: $REPORT_FILE${NC}"
echo ""
cat "$REPORT_FILE"
