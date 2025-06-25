#!/bin/bash
#
# Install all parser dependencies for RFC-031 AST Service
# Run from RSOLV-api/priv/parsers/setup directory

set -euo pipefail

echo "=== Installing Parser Dependencies for RFC-031 ==="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running from correct directory
if [[ ! -f "install-all.sh" ]]; then
    echo -e "${RED}Error: Must run from priv/parsers/setup directory${NC}"
    exit 1
fi

cd ..

# Python - ast module is built-in
echo -e "${GREEN}✓ Python${NC}: Using built-in ast module (no installation needed)"
echo "  Checking Python version..."
if command -v python3 &> /dev/null; then
    python3 --version
else
    echo -e "${RED}  Warning: python3 not found${NC}"
fi
echo

# Ruby - parser gem
echo -e "${YELLOW}→ Ruby${NC}: Installing parser gem..."
if command -v gem &> /dev/null; then
    gem install parser --no-document
    echo -e "${GREEN}  ✓ parser gem installed${NC}"
else
    echo -e "${RED}  Error: gem command not found. Install Ruby first.${NC}"
fi
echo

# PHP - PHP-Parser via Composer
echo -e "${YELLOW}→ PHP${NC}: Installing nikic/php-parser..."
if command -v composer &> /dev/null; then
    cd php/lib
    if [[ ! -f "composer.json" ]]; then
        composer init --no-interaction --name="rsolv/php-parser-wrapper" --type="project"
    fi
    composer require nikic/php-parser --no-interaction
    cd ../..
    echo -e "${GREEN}  ✓ PHP-Parser installed${NC}"
else
    echo -e "${RED}  Error: composer not found. Install Composer first.${NC}"
fi
echo

# Java - JavaParser JAR
echo -e "${YELLOW}→ Java${NC}: Downloading JavaParser..."
if command -v java &> /dev/null; then
    JAVAPARSER_VERSION="3.25.8"
    JAR_URL="https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/${JAVAPARSER_VERSION}/javaparser-core-${JAVAPARSER_VERSION}.jar"
    
    mkdir -p java/lib
    cd java/lib
    
    if [[ ! -f "javaparser-core-${JAVAPARSER_VERSION}.jar" ]]; then
        echo "  Downloading JavaParser ${JAVAPARSER_VERSION}..."
        curl -L -o "javaparser-core-${JAVAPARSER_VERSION}.jar" "$JAR_URL"
        ln -sf "javaparser-core-${JAVAPARSER_VERSION}.jar" "javaparser.jar"
        echo -e "${GREEN}  ✓ JavaParser downloaded${NC}"
    else
        echo -e "${GREEN}  ✓ JavaParser already present${NC}"
    fi
    cd ../..
else
    echo -e "${RED}  Error: java not found. Install JDK 11+ first.${NC}"
fi
echo

# Go - go/parser is built-in
echo -e "${GREEN}✓ Go${NC}: Using built-in go/parser package (no installation needed)"
echo "  Checking Go version..."
if command -v go &> /dev/null; then
    go version
else
    echo -e "${RED}  Warning: go not found${NC}"
fi
echo

echo "=== Installation Summary ==="
echo
echo "Next steps:"
echo "1. Run ./verify.sh to test parser installations"
echo "2. Create parser wrapper scripts in each language directory"
echo "3. Test with sample code files"
echo
echo "For missing runtimes, install:"
echo "  - Python 3.8+: https://www.python.org/"
echo "  - Ruby 2.7+: https://www.ruby-lang.org/"
echo "  - PHP 7.4+: https://www.php.net/"
echo "  - Java 11+: https://adoptium.net/"
echo "  - Go 1.18+: https://golang.org/"