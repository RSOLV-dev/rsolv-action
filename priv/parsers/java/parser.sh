#!/bin/bash
# Java parser placeholder - returns proper error until Maven is available to build

# Ensure stdout is not buffered
exec 1> >(stdbuf -oL cat)

# Process requests in a loop, similar to other parsers
while IFS= read -r json_input; do
    # Extract ID from JSON (basic parsing)
    id=$(echo "$json_input" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
    if [ -z "$id" ]; then
        id="unknown"
    fi
    
    # Check for health check
    if echo "$json_input" | grep -q '"action":"HEALTH_CHECK"'; then
        echo "{\"id\":\"$id\",\"result\":\"ok\"}"
    else
        # Return a proper error response for all parse requests - on single line
        echo "{\"id\":\"$id\",\"success\":false,\"error\":{\"type\":\"ParserNotAvailable\",\"message\":\"Java parser not built - requires Maven installation. Run 'mvn clean package' in the java parser directory to build.\"}}"
    fi
done
