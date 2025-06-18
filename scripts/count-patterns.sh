#!/bin/bash

echo "=== RSOLV-API Pattern Inventory ==="
echo

# Function to count patterns in a directory
count_patterns_in_dir() {
    local dir=$1
    local name=$2
    local count=$(find "$dir" -name "*.ex" -not -name "*_test.ex" -not -name "pattern_base.ex" | wc -l)
    echo "$name: $count patterns"
}

# Count JavaScript patterns
js_count=$(find lib/rsolv_api/security/patterns/javascript -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "JavaScript: $js_count patterns"

# Count Python patterns
py_count=$(find lib/rsolv_api/security/patterns/python -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Python: $py_count patterns"

# Count Ruby patterns
rb_count=$(find lib/rsolv_api/security/patterns/ruby -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Ruby: $rb_count patterns"

# Count Java patterns
java_count=$(find lib/rsolv_api/security/patterns/java -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Java: $java_count patterns"

# Count Elixir patterns
ex_count=$(find lib/rsolv_api/security/patterns/elixir -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Elixir: $ex_count patterns"

# Count PHP patterns
php_count=$(find lib/rsolv_api/security/patterns/php -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "PHP: $php_count patterns"

# Count Rails patterns
rails_count=$(find lib/rsolv_api/security/patterns/rails -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Rails: $rails_count patterns"

# Count Django patterns
django_count=$(find lib/rsolv_api/security/patterns/django -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Django: $django_count patterns"

# Count common patterns
common_count=$(find lib/rsolv_api/security/patterns/common -name "*.ex" -not -name "*_test.ex" | wc -l)
echo "Common: $common_count patterns"

# Calculate total
total=$((js_count + py_count + rb_count + java_count + ex_count + php_count + rails_count + django_count + common_count))
echo
echo "TOTAL: $total patterns"

echo
echo "=== Analyzing Pattern Details ==="
echo

# Extract tier information from individual pattern files
echo "Checking default tier assignments..."
grep -r "default_tier:" lib/rsolv_api/security/patterns --include="*.ex" | grep -v test | head -20