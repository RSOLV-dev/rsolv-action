#!/bin/bash
# Module rename script for RSOLV service consolidation
# This script handles the mixed naming conventions we currently have

set -e  # Exit on error

echo "=== RSOLV Service Consolidation Module Rename Script ==="
echo "This will rename:"
echo "  - RsolvApi → Rsolv"
echo "  - RSOLV → Rsolv"
echo "  - RSOLVWeb → RsolvWeb"
echo "  - :rsolv_api → :rsolv"
echo ""

# Create backup commit
echo "=== Creating backup commit ==="
git add -A && git commit -m "WIP: Pre-rename backup" || echo "No changes to commit"

# Count current occurrences for verification
echo ""
echo "=== Current module naming statistics ==="
echo "RsolvApi modules: $(grep -r "RsolvApi" lib/ test/ | wc -l)"
echo "RSOLV modules: $(grep -r "defmodule RSOLV\\." lib/ | wc -l)"
echo "RSOLVWeb modules: $(grep -r "RSOLVWeb" lib/ test/ | wc -l)"
echo ""

# Function to perform replacements with confirmation
perform_replacements() {
    local pattern=$1
    local replacement=$2
    local file_pattern=$3
    local description=$4
    
    echo "=== $description ==="
    echo "Pattern: $pattern → $replacement"
    
    # Show affected files
    affected_files=$(find . -name "$file_pattern" -type f | xargs grep -l "$pattern" 2>/dev/null | grep -v ".git" | sort || true)
    
    if [ -z "$affected_files" ]; then
        echo "No files to update"
        return
    fi
    
    echo "Files to update: $(echo "$affected_files" | wc -l)"
    echo "$affected_files" | head -5
    if [ $(echo "$affected_files" | wc -l) -gt 5 ]; then
        echo "... and $(( $(echo "$affected_files" | wc -l) - 5 )) more"
    fi
    
    # Perform replacement
    echo "$affected_files" | while read -r file; do
        if [ -f "$file" ]; then
            sed -i.bak "s/$pattern/$replacement/g" "$file"
            rm -f "${file}.bak"
        fi
    done
    
    echo "Updated!"
    echo ""
}

# Phase 1: Update module definitions and aliases
echo "=== Phase 1: Module Definitions and Aliases ==="

# RsolvApi → Rsolv
perform_replacements "defmodule RsolvApi\\." "defmodule Rsolv." "*.ex" "Update RsolvApi module definitions"
perform_replacements "alias RsolvApi\\." "alias Rsolv." "*.ex*" "Update RsolvApi aliases"
perform_replacements "RsolvApi\\." "Rsolv." "*.ex*" "Update RsolvApi references"

# RSOLV → Rsolv (careful to not affect RSOLVWeb)
perform_replacements "defmodule RSOLV\\." "defmodule Rsolv." "*.ex" "Update RSOLV module definitions"
perform_replacements "alias RSOLV\\." "alias Rsolv." "*.ex*" "Update RSOLV aliases"
# More careful with general RSOLV references to avoid breaking RSOLVWeb
find . -name "*.ex" -o -name "*.exs" | xargs sed -i 's/\bRSOLV\.\([^W]\)/Rsolv.\1/g' 2>/dev/null || true

# RSOLVWeb → RsolvWeb
perform_replacements "defmodule RSOLVWeb" "defmodule RsolvWeb" "*.ex" "Update RSOLVWeb module definitions"
perform_replacements "alias RSOLVWeb" "alias RsolvWeb" "*.ex*" "Update RSOLVWeb aliases"
perform_replacements "use RSOLVWeb" "use RsolvWeb" "*.ex*" "Update RSOLVWeb use statements"
perform_replacements "RSOLVWeb" "RsolvWeb" "*.ex*" "Update remaining RSOLVWeb references"

# Phase 2: Update mix.exs
echo "=== Phase 2: Update mix.exs ==="
sed -i 's/:rsolv_api/:rsolv/g' mix.exs
sed -i 's/defmodule RSOLV\.MixProject/defmodule Rsolv.MixProject/g' mix.exs
sed -i 's/{RSOLV\.Application/{Rsolv.Application/g' mix.exs

# Phase 3: Update config files
echo "=== Phase 3: Update configuration files ==="
find config -name "*.exs" -type f | while read -r file; do
    sed -i 's/:rsolv_api/:rsolv/g' "$file"
    sed -i 's/RsolvApi/Rsolv/g' "$file"
    sed -i 's/RSOLV\([^W]\)/Rsolv\1/g' "$file"
    sed -i 's/RSOLVWeb/RsolvWeb/g' "$file"
done

# Phase 4: Update test files
echo "=== Phase 4: Update test files ==="
find test -name "*.exs" -type f | while read -r file; do
    sed -i 's/RsolvApi/Rsolv/g' "$file"
    sed -i 's/\bRSOLV\.\([^W]\)/Rsolv.\1/g' "$file"
    sed -i 's/RSOLVWeb/RsolvWeb/g' "$file"
    sed -i 's/:rsolv_api/:rsolv/g' "$file"
done

# Phase 5: Update router and endpoint references
echo "=== Phase 5: Update special Phoenix files ==="
if [ -f "lib/rsolv_web/router.ex" ]; then
    sed -i 's/RsolvApiWeb/RsolvWeb/g' lib/rsolv_web/router.ex
fi
if [ -f "lib/rsolv_web/endpoint.ex" ]; then
    sed -i 's/RsolvApiWeb/RsolvWeb/g' lib/rsolv_web/endpoint.ex
fi

# Phase 6: Update string references
echo "=== Phase 6: Update string references ==="
find . -name "*.ex" -o -name "*.exs" | xargs sed -i 's/"RsolvApi\./"Rsolv./g' 2>/dev/null || true
find . -name "*.ex" -o -name "*.exs" | xargs sed -i "s/'RsolvApi\./'Rsolv./g" 2>/dev/null || true

# Phase 7: Update gettext domain
echo "=== Phase 7: Update gettext domain ==="
find . -name "*.ex" -o -name "*.exs" | xargs sed -i 's/"rsolv_api"/"rsolv"/g' 2>/dev/null || true

# Phase 8: Final verification
echo ""
echo "=== Final module naming statistics ==="
echo "Remaining RsolvApi references: $(grep -r "RsolvApi" lib/ test/ 2>/dev/null | wc -l || echo 0)"
echo "Remaining RSOLV references (excluding RsolvWeb): $(grep -r "\bRSOLV\." lib/ test/ 2>/dev/null | wc -l || echo 0)"
echo "Remaining RSOLVWeb references: $(grep -r "RSOLVWeb" lib/ test/ 2>/dev/null | wc -l || echo 0)"
echo "Remaining :rsolv_api references: $(grep -r ":rsolv_api" . --include="*.ex*" 2>/dev/null | wc -l || echo 0)"

echo ""
echo "=== Rename complete! ==="
echo "Next steps:"
echo "1. Run: mix deps.get"
echo "2. Run: mix compile --force"
echo "3. Fix any compilation errors"
echo "4. Run: mix test"
echo "5. Verify application starts: iex -S mix phx.server"