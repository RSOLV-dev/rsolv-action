#!/bin/bash

# Production Environment Configuration Script
# This script sets up the required environment variables for RSOLV production

echo "======================================"
echo "RSOLV Production Environment Setup"
echo "======================================"
echo ""
echo "IMPORTANT: You need to provide the following API keys:"
echo ""
echo "1. AI Provider Keys (at least one required):"
echo "   - Anthropic API Key (for Claude)"
echo "   - OpenAI API Key"
echo "   - OpenRouter API Key"
echo ""
echo "2. ConvertKit/Kit.com Integration (for landing page):"
echo "   - Kit API Key"
echo "   - Kit Form ID"
echo "   - Kit EA Tag ID"
echo ""
echo "3. Other Services (optional but recommended):"
echo "   - Postmark API Key (for transactional emails)"
echo ""

# Function to update a secret
update_secret() {
    local key=$1
    local value=$2
    local encoded=$(echo -n "$value" | base64 -w 0)

    kubectl patch secret rsolv-secrets -n rsolv-production \
        --type='json' \
        -p='[{"op": "replace", "path": "/data/'$key'", "value": "'$encoded'"}]'
}

# Prompt for API keys
read -p "Enter Anthropic API Key (or press Enter to skip): " ANTHROPIC_KEY
if [ ! -z "$ANTHROPIC_KEY" ]; then
    update_secret "anthropic-api-key" "$ANTHROPIC_KEY"
    echo "✅ Anthropic API key updated"
fi

read -p "Enter OpenAI API Key (or press Enter to skip): " OPENAI_KEY
if [ ! -z "$OPENAI_KEY" ]; then
    update_secret "openai-api-key" "$OPENAI_KEY"
    echo "✅ OpenAI API key updated"
fi

read -p "Enter OpenRouter API Key (or press Enter to skip): " OPENROUTER_KEY
if [ ! -z "$OPENROUTER_KEY" ]; then
    update_secret "openrouter-api-key" "$OPENROUTER_KEY"
    echo "✅ OpenRouter API key updated"
fi

read -p "Enter Kit API Key (or press Enter to skip): " KIT_API_KEY
if [ ! -z "$KIT_API_KEY" ]; then
    update_secret "kit-api-key" "$KIT_API_KEY"
    echo "✅ Kit API key updated"
fi

read -p "Enter Kit Form ID (or press Enter to skip): " KIT_FORM_ID
if [ ! -z "$KIT_FORM_ID" ]; then
    update_secret "kit-form-id" "$KIT_FORM_ID"
    echo "✅ Kit Form ID updated"
fi

read -p "Enter Kit EA Tag ID (or press Enter to skip): " KIT_EA_TAG_ID
if [ ! -z "$KIT_EA_TAG_ID" ]; then
    update_secret "kit-ea-tag-id" "$KIT_EA_TAG_ID"
    echo "✅ Kit EA Tag ID updated"
fi

echo ""
echo "======================================"
echo "Secret updates complete!"
echo "======================================"
echo ""
echo "To apply the changes, restart the deployment:"
echo "kubectl rollout restart deployment/rsolv-platform -n rsolv-production"
echo ""
echo "Note: The credential vending system will not work without at least one AI provider key."