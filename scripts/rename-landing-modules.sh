#!/bin/bash
# Module rename script for rsolv-landing -> RSOLV-platform migration
# This renames all RsolvLanding* modules to Rsolv*

set -e  # Exit on error

echo "=== RSOLV-Landing Module Rename Script ==="
echo "This will rename:"
echo "  - RsolvLanding → Rsolv"
echo "  - RsolvLandingWeb → RsolvWeb"
echo "  - :rsolv_landing → :rsolv"
echo ""

# Function to perform replacements
perform_replacements() {
    local pattern=$1
    local replacement=$2
    local description=$3
    
    echo "=== $description ==="
    echo "Pattern: $pattern → $replacement"
    
    # Find and replace in all Elixir files
    find lib/rsolv_web -type f \( -name "*.ex" -o -name "*.exs" -o -name "*.heex" \) -exec sed -i "s/$pattern/$replacement/g" {} \;
    find lib/rsolv -type f \( -name "*.ex" -o -name "*.exs" -o -name "*.heex" \) -exec sed -i "s/$pattern/$replacement/g" {} \;
    find test -type f \( -name "*.ex" -o -name "*.exs" -o -name "*.heex" \) -exec sed -i "s/$pattern/$replacement/g" {} \;
    
    echo "Updated!"
    echo ""
}

# Phase 1: Update module definitions and aliases
echo "=== Phase 1: Module Definitions and Aliases ==="

# RsolvLandingWeb → RsolvWeb
perform_replacements "defmodule RsolvLandingWeb" "defmodule RsolvWeb" "Update RsolvLandingWeb module definitions"
perform_replacements "alias RsolvLandingWeb" "alias RsolvWeb" "Update RsolvLandingWeb aliases"
perform_replacements "use RsolvLandingWeb" "use RsolvWeb" "Update RsolvLandingWeb use statements"
perform_replacements "RsolvLandingWeb" "RsolvWeb" "Update remaining RsolvLandingWeb references"

# RsolvLanding → Rsolv (but not RsolvLandingWeb which we already handled)
perform_replacements "defmodule RsolvLanding\\\." "defmodule Rsolv." "Update RsolvLanding module definitions"
perform_replacements "alias RsolvLanding\\\." "alias Rsolv." "Update RsolvLanding aliases"
perform_replacements "RsolvLanding\\\." "Rsolv." "Update RsolvLanding references"

# Phase 2: Update atom references
echo "=== Phase 2: Update atom references ==="
perform_replacements ":rsolv_landing" ":rsolv" "Update :rsolv_landing atoms"

# Phase 3: Update specific imports
echo "=== Phase 3: Update specific imports ==="
perform_replacements "import RsolvLandingWeb" "import RsolvWeb" "Update RsolvLandingWeb imports"
perform_replacements "import RsolvLanding" "import Rsolv" "Update RsolvLanding imports"

# Phase 4: Update JavaScript imports to match new structure
echo "=== Phase 4: Update JavaScript imports ==="
if [ -f "assets/js/app.js" ]; then
    # Update any Analytics references
    sed -i 's/RsolvLandingWeb\.Services\.Analytics/Rsolv.Analytics/g' assets/js/app.js
fi

# Phase 5: Fix any context module issues
echo "=== Phase 5: Fix context modules ==="
# Analytics context
sed -i 's/alias Rsolv\.Analytics\./alias Rsolv.Analytics./g' lib/rsolv_web/services/analytics.ex || true
sed -i 's/Rsolv\.Analytics\./Rsolv.Analytics./g' lib/rsolv_web/services/analytics.ex || true

# Phase 6: Final verification
echo ""
echo "=== Final module naming statistics ==="
echo "Remaining RsolvLandingWeb references: $(grep -r "RsolvLandingWeb" lib/ test/ 2>/dev/null | wc -l || echo 0)"
echo "Remaining RsolvLanding references: $(grep -r "RsolvLanding\." lib/ test/ 2>/dev/null | wc -l || echo 0)"
echo "Remaining :rsolv_landing references: $(grep -r ":rsolv_landing" lib/ test/ 2>/dev/null | wc -l || echo 0)"

echo ""
echo "=== Rename complete! ==="
echo "Next steps:"
echo "1. Run: mix deps.get"
echo "2. Run: mix compile --force"
echo "3. Fix any compilation errors"
echo "4. Run: mix test"