#!/bin/bash

echo "=== RSOLV-API Pattern Tier Analysis ==="
echo
echo "Current tier distribution across all patterns:"
echo

# Count patterns by tier
echo "Public tier patterns:"
grep -r "default_tier: :public" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | wc -l

echo "Protected tier patterns:"
grep -r "default_tier: :protected" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | wc -l

echo "Patterns without explicit tier (defaulting to public):"
total_patterns=$(find lib/rsolv_api/security/patterns -name "*.ex" -not -name "*_test.ex" -not -name "pattern_base.ex" -not -path "*/patterns/*.ex" | wc -l)
patterns_with_tier=$(grep -r "default_tier:" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | wc -l)
echo $((total_patterns - patterns_with_tier))

echo
echo "=== Pattern Type Analysis ==="
echo

# Count by pattern type
echo "Analyzing pattern types..."
grep -r "type: :" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | sed 's/.*type: :\([a-z_]*\).*/\1/' | sort | uniq -c | sort -nr

echo
echo "=== Severity Distribution ==="
echo

# Count by severity
echo "Analyzing severity levels..."
grep -r "severity: :" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | sed 's/.*severity: :\([a-z]*\).*/\1/' | sort | uniq -c | sort -nr

echo
echo "=== CVE Pattern Analysis ==="
echo

# Find CVE patterns
echo "CVE-specific patterns:"
grep -r "cve\|CVE" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | grep -E "(id:|name:)" | wc -l

echo
echo "=== Patterns by Language with Details ==="
echo

# Function to analyze patterns in a directory
analyze_language() {
    local dir=$1
    local lang=$2
    
    echo "=== $lang ==="
    if [ -d "$dir" ]; then
        echo "Pattern files:"
        find "$dir" -name "*.ex" -not -name "*_test.ex" | while read file; do
            basename=$(basename "$file")
            # Try to extract pattern id
            id=$(grep "id:" "$file" | head -1 | sed 's/.*id: "\([^"]*\)".*/\1/')
            # Try to extract tier
            tier=$(grep "default_tier:" "$file" | head -1 | sed 's/.*default_tier: :\([a-z]*\).*/\1/')
            if [ -z "$tier" ]; then
                tier="public(default)"
            fi
            echo "  - $basename (tier: $tier)"
        done
        echo
    fi
}

analyze_language "lib/rsolv_api/security/patterns/javascript" "JavaScript"
analyze_language "lib/rsolv_api/security/patterns/python" "Python"
analyze_language "lib/rsolv_api/security/patterns/ruby" "Ruby"
analyze_language "lib/rsolv_api/security/patterns/java" "Java"
analyze_language "lib/rsolv_api/security/patterns/elixir" "Elixir"
analyze_language "lib/rsolv_api/security/patterns/php" "PHP"
analyze_language "lib/rsolv_api/security/patterns/rails" "Rails"
analyze_language "lib/rsolv_api/security/patterns/django" "Django"