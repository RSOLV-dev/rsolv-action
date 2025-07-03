#!/bin/bash
# Complete copy of all rsolv-landing files to RSOLV-platform
# This includes ALL JavaScript, CSS, images, and Elixir files

set -e  # Exit on error

echo "=== Complete RSOLV-Landing Migration Script ==="
echo "This will copy ALL files from rsolv-landing to RSOLV-platform"
echo ""

LANDING_DIR="/home/dylan/dev/rsolv/rsolv-landing"
PLATFORM_DIR="/home/dylan/dev/rsolv/RSOLV-platform"

# Copy all JavaScript files
echo "=== Copying JavaScript files ==="
cp -v $LANDING_DIR/assets/js/*.js $PLATFORM_DIR/assets/js/ || true

# Copy vendor directory
echo "=== Copying vendor directory ==="
mkdir -p $PLATFORM_DIR/assets/vendor/chart
cp -rv $LANDING_DIR/assets/vendor/* $PLATFORM_DIR/assets/vendor/

# Copy static assets
echo "=== Copying static assets ==="
mkdir -p $PLATFORM_DIR/assets/static/fonts
cp -rv $LANDING_DIR/assets/static/* $PLATFORM_DIR/assets/static/ || true

# Copy fonts to priv/static
echo "=== Copying fonts to priv/static ==="
mkdir -p $PLATFORM_DIR/priv/static/fonts
cp -v $LANDING_DIR/priv/static/fonts/*.woff2 $PLATFORM_DIR/priv/static/fonts/ || true
cp -v $LANDING_DIR/priv/static/fonts/*.css $PLATFORM_DIR/priv/static/fonts/ || true

# Copy images to priv/static
echo "=== Copying images to priv/static ==="
mkdir -p $PLATFORM_DIR/priv/static/images
cp -v $LANDING_DIR/priv/static/images/*.png $PLATFORM_DIR/priv/static/images/ || true
cp -v $LANDING_DIR/priv/static/images/*.svg $PLATFORM_DIR/priv/static/images/ || true

# Copy all web components (excluding what we already have)
echo "=== Copying web components ==="
for file in $LANDING_DIR/lib/rsolv_landing_web/components/*.ex; do
    filename=$(basename "$file")
    if [[ ! -f "$PLATFORM_DIR/lib/rsolv_web/components/$filename" ]]; then
        cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/components/"
    fi
done

# Copy controllers
echo "=== Copying controllers ==="
for file in $LANDING_DIR/lib/rsolv_landing_web/controllers/*.ex; do
    filename=$(basename "$file")
    if [[ ! -f "$PLATFORM_DIR/lib/rsolv_web/controllers/$filename" ]]; then
        cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/controllers/"
    fi
done

# Copy API controllers
echo "=== Copying API controllers ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/controllers/api
cp -v $LANDING_DIR/lib/rsolv_landing_web/controllers/api/*.ex $PLATFORM_DIR/lib/rsolv_web/controllers/api/ || true

# Copy helpers
echo "=== Copying helpers ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/helpers
cp -v $LANDING_DIR/lib/rsolv_landing_web/helpers/*.ex $PLATFORM_DIR/lib/rsolv_web/helpers/

# Copy live views
echo "=== Copying live views ==="
for file in $LANDING_DIR/lib/rsolv_landing_web/live/*.ex; do
    filename=$(basename "$file")
    if [[ ! -f "$PLATFORM_DIR/lib/rsolv_web/live/$filename" ]]; then
        cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/live/"
    fi
done

# Copy live view templates
for file in $LANDING_DIR/lib/rsolv_landing_web/live/*.heex; do
    filename=$(basename "$file")
    if [[ ! -f "$PLATFORM_DIR/lib/rsolv_web/live/$filename" ]]; then
        cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/live/"
    fi
done

# Copy plugs
echo "=== Copying plugs ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/plugs
cp -v $LANDING_DIR/lib/rsolv_landing_web/plugs/*.ex $PLATFORM_DIR/lib/rsolv_web/plugs/

# Copy services
echo "=== Copying services ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/services
for file in $LANDING_DIR/lib/rsolv_landing_web/services/*.ex; do
    filename=$(basename "$file")
    # Skip files we already have better versions of
    if [[ "$filename" != "kit.ex" && "$filename" != "email_sequence.ex" ]]; then
        cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/services/"
    fi
done

# Copy validators
echo "=== Copying validators ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/validators
cp -v $LANDING_DIR/lib/rsolv_landing_web/validators/*.ex $PLATFORM_DIR/lib/rsolv_web/validators/

# Copy views
echo "=== Copying views ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/views/api
cp -v $LANDING_DIR/lib/rsolv_landing_web/views/api/*.ex $PLATFORM_DIR/lib/rsolv_web/views/api/

# Copy live_hooks.ex
echo "=== Copying live_hooks.ex ==="
cp -v $LANDING_DIR/lib/rsolv_landing_web/live_hooks.ex $PLATFORM_DIR/lib/rsolv_web/

# Copy email templates with correct extensions
echo "=== Copying email templates ==="
mkdir -p $PLATFORM_DIR/lib/rsolv_web/controllers/emails
for file in $LANDING_DIR/lib/rsolv_landing_web/controllers/emails/*.heex; do
    filename=$(basename "$file" .heex)
    cp -v "$file" "$PLATFORM_DIR/lib/rsolv_web/controllers/emails/${filename}"
done

echo ""
echo "=== File copy complete! ==="
echo "Next steps:"
echo "1. Run the module rename script to update all module names"
echo "2. Fix any remaining import/alias issues"
echo "3. Run mix compile to check for errors"