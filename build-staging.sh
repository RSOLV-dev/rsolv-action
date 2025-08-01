#!/bin/bash
set -e

# Build staging image with timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
IMAGE_TAG="ghcr.io/rsolv-dev/rsolv-platform:staging-${TIMESTAMP}"

echo "Building staging image: ${IMAGE_TAG}"

# Build the image
docker build -t "${IMAGE_TAG}" -t "ghcr.io/rsolv-dev/rsolv-platform:staging" .

# Push both tags
echo "Pushing images..."
docker push "${IMAGE_TAG}"
docker push "ghcr.io/rsolv-dev/rsolv-platform:staging"

echo "Build complete: ${IMAGE_TAG}"