#!/bin/bash
# Start Tidewave for AI-assisted development

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting Tidewave AI Development Assistant${NC}"
echo ""

# Check for Anthropic API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  ANTHROPIC_API_KEY not found in environment${NC}"
    echo "   Please set it in one of these ways:"
    echo "   1. Export in your shell: export ANTHROPIC_API_KEY='your-key'"
    echo "   2. Add to ~/.zshrc or ~/.bashrc"
    echo "   3. Set in .env.dev file"
    echo ""
    echo "   Get your key from: https://console.anthropic.com/"
    exit 1
fi

echo -e "${GREEN}✓ Anthropic API key found${NC}"

# Ask user for environment preference
echo ""
echo "How would you like to run Tidewave?"
echo "1) Local (mix phx.server) - Port 4000"
echo "2) Docker Compose - Port 4001"
echo ""
read -p "Enter choice [1-2]: " choice

case $choice in
    1)
        echo -e "\n${GREEN}Starting local Phoenix server with Tidewave...${NC}"
        echo "Access Tidewave at: http://localhost:4000/tidewave"
        echo "Or from network: http://10.5.0.5:4000/tidewave"
        echo ""
        echo "Press Ctrl+C to stop"
        mix phx.server
        ;;
    2)
        echo -e "\n${GREEN}Starting Docker Compose with Tidewave...${NC}"
        docker-compose -f docker-compose.dev.yml up -d
        
        echo -e "\n${GREEN}Waiting for services to be ready...${NC}"
        sleep 5
        
        # Check if services are healthy
        if curl -s http://localhost:4001/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Services are healthy${NC}"
            echo ""
            echo "Access Tidewave at: http://localhost:4001/tidewave"
            echo "Or from network: http://10.5.0.5:4001/tidewave"
            echo ""
            echo "View logs: docker-compose -f docker-compose.dev.yml logs -f"
            echo "Stop: docker-compose -f docker-compose.dev.yml down"
        else
            echo -e "${RED}⚠️  Services may not be ready yet${NC}"
            echo "Check logs: docker-compose -f docker-compose.dev.yml logs"
        fi
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac