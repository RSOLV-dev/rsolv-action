#!/bin/bash

# Load test for cache performance
# Simulates production-like load with various patterns

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== Cache Load Test ==="
echo "Simulating production workload..."
echo ""

# Configuration
TOTAL_REQUESTS=1000
CONCURRENT_REQUESTS=10
UNIQUE_VULNS=50  # Number of unique vulnerabilities to cycle through

# Track timing
START_TIME=$(date +%s)

# Function to make a request
make_request() {
    local index=$1
    local vuln_id=$((index % UNIQUE_VULNS))
    
    local start=$(date +%s%3N)
    
    curl -s -X POST "$API_URL" \
        -H "X-API-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"vulnerabilities\": [{
                \"type\": \"sql-injection\",
                \"locations\": [{
                    \"file_path\": \"app/file${vuln_id}.js\",
                    \"line\": $((vuln_id * 10)),
                    \"is_primary\": true
                }],
                \"code\": \"db.query(userInput${vuln_id})\"
            }],
            \"files\": {
                \"app/file${vuln_id}.js\": {
                    \"content\": \"// File ${vuln_id}\ndb.query(userInput${vuln_id});\",
                    \"hash\": \"sha256:loadtest${vuln_id}\"
                }
            },
            \"repository\": \"staging-test-org/load-test\"
        }" > /tmp/load_test_${index}.json
    
    local end=$(date +%s%3N)
    local duration=$((end - start))
    
    # Extract cache hit info
    local from_cache=$(jq -r '.validated[0].fromCache' /tmp/load_test_${index}.json)
    local hit_rate=$(jq -r '.cache_stats.hit_rate' /tmp/load_test_${index}.json)
    
    echo "Request $index: ${duration}ms, fromCache=${from_cache}, hitRate=${hit_rate}%"
    
    # Clean up
    rm -f /tmp/load_test_${index}.json
    
    return 0
}

# Warm up the cache first
echo "Phase 1: Cache Warming (${UNIQUE_VULNS} unique vulnerabilities)"
echo "------------------------------------------------"
for i in $(seq 1 $UNIQUE_VULNS); do
    make_request $i &
    
    # Rate limit
    if [ $((i % CONCURRENT_REQUESTS)) -eq 0 ]; then
        wait
    fi
done
wait

echo ""
echo "Phase 2: Production Load (${TOTAL_REQUESTS} requests)"
echo "------------------------------------------------"

# Track metrics
CACHE_HITS=0
CACHE_MISSES=0
TOTAL_TIME=0
MIN_TIME=999999
MAX_TIME=0

# Make concurrent requests
for i in $(seq 1 $TOTAL_REQUESTS); do
    (
        local start=$(date +%s%3N)
        
        # Use a mix of cached and new vulnerabilities
        local vuln_id=$((i % (UNIQUE_VULNS * 2)))  # Some will be cache misses
        
        RESPONSE=$(curl -s -X POST "$API_URL" \
            -H "X-API-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"vulnerabilities\": [{
                    \"type\": \"sql-injection\",
                    \"locations\": [{
                        \"file_path\": \"app/file${vuln_id}.js\",
                        \"line\": $((vuln_id * 10)),
                        \"is_primary\": true
                    }],
                    \"code\": \"db.query(userInput${vuln_id})\"
                }],
                \"files\": {
                    \"app/file${vuln_id}.js\": {
                        \"content\": \"// File ${vuln_id}\ndb.query(userInput${vuln_id});\",
                        \"hash\": \"sha256:loadtest${vuln_id}\"
                    }
                },
                \"repository\": \"staging-test-org/load-test\"
            }")
        
        local end=$(date +%s%3N)
        local duration=$((end - start))
        
        # Extract metrics
        local from_cache=$(echo "$RESPONSE" | jq -r '.validated[0].fromCache')
        
        if [ "$from_cache" = "true" ]; then
            echo "H" > /tmp/cache_result_${i}
        else
            echo "M" > /tmp/cache_result_${i}
        fi
        
        echo "$duration" > /tmp/time_result_${i}
        
        # Progress indicator
        if [ $((i % 100)) -eq 0 ]; then
            echo "Progress: $i/$TOTAL_REQUESTS completed"
        fi
    ) &
    
    # Control concurrency
    if [ $((i % CONCURRENT_REQUESTS)) -eq 0 ]; then
        wait
    fi
done
wait

# Calculate statistics
echo ""
echo "Phase 3: Analyzing Results"
echo "------------------------------------------------"

for i in $(seq 1 $TOTAL_REQUESTS); do
    if [ -f /tmp/cache_result_${i} ]; then
        result=$(cat /tmp/cache_result_${i})
        if [ "$result" = "H" ]; then
            CACHE_HITS=$((CACHE_HITS + 1))
        else
            CACHE_MISSES=$((CACHE_MISSES + 1))
        fi
        rm -f /tmp/cache_result_${i}
    fi
    
    if [ -f /tmp/time_result_${i} ]; then
        time=$(cat /tmp/time_result_${i})
        TOTAL_TIME=$((TOTAL_TIME + time))
        
        if [ $time -lt $MIN_TIME ]; then
            MIN_TIME=$time
        fi
        
        if [ $time -gt $MAX_TIME ]; then
            MAX_TIME=$time
        fi
        
        rm -f /tmp/time_result_${i}
    fi
done

# Calculate final metrics
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))
AVG_TIME=$((TOTAL_TIME / TOTAL_REQUESTS))
HIT_RATE=$((CACHE_HITS * 100 / (CACHE_HITS + CACHE_MISSES)))
REQUESTS_PER_SEC=$((TOTAL_REQUESTS / TOTAL_DURATION))

echo ""
echo "=== Load Test Results ==="
echo "Total Requests: $TOTAL_REQUESTS"
echo "Total Duration: ${TOTAL_DURATION}s"
echo "Requests/sec: $REQUESTS_PER_SEC"
echo ""
echo "Cache Performance:"
echo "  Cache Hits: $CACHE_HITS"
echo "  Cache Misses: $CACHE_MISSES"
echo "  Hit Rate: ${HIT_RATE}%"
echo ""
echo "Response Times:"
echo "  Min: ${MIN_TIME}ms"
echo "  Max: ${MAX_TIME}ms"
echo "  Avg: ${AVG_TIME}ms"
echo ""

# Performance evaluation
if [ $HIT_RATE -gt 70 ] && [ $AVG_TIME -lt 100 ]; then
    echo "✅ PASS: Cache performing excellently!"
elif [ $HIT_RATE -gt 50 ] && [ $AVG_TIME -lt 200 ]; then
    echo "⚠️  WARNING: Cache performing adequately"
else
    echo "❌ FAIL: Cache performance below expectations"
fi

echo ""
echo "Load test complete!"