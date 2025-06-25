#!/bin/bash
#
# Verify parser installations for RFC-031 AST Service

set -euo pipefail

echo "=== Verifying Parser Installations ==="
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

cd ..

# Python
echo -n "Python ast module: "
if python3 -c "import ast; print('OK')" 2>/dev/null | grep -q OK; then
    echo -e "${GREEN}✓ Available${NC}"
else
    echo -e "${RED}✗ Not working${NC}"
    ((ERRORS++))
fi

# Ruby
echo -n "Ruby parser gem: "
if ruby -e "require 'parser/current'; puts 'OK'" 2>/dev/null | grep -q OK; then
    echo -e "${GREEN}✓ Available${NC}"
else
    echo -e "${RED}✗ Not installed${NC}"
    ((ERRORS++))
fi

# PHP
echo -n "PHP-Parser: "
if [[ -f "php/lib/vendor/autoload.php" ]]; then
    if php -r "require 'php/lib/vendor/autoload.php'; use PhpParser\ParserFactory; echo 'OK';" 2>/dev/null | grep -q OK; then
        echo -e "${GREEN}✓ Available${NC}"
    else
        echo -e "${RED}✗ Not working${NC}"
        ((ERRORS++))
    fi
else
    echo -e "${RED}✗ Not installed${NC}"
    ((ERRORS++))
fi

# Java
echo -n "JavaParser: "
if [[ -f "java/lib/javaparser.jar" ]]; then
    echo -e "${GREEN}✓ JAR present${NC}"
else
    echo -e "${RED}✗ JAR missing${NC}"
    ((ERRORS++))
fi

# Go
echo -n "Go parser: "
if go version &>/dev/null; then
    echo -e "${GREEN}✓ Go available${NC}"
else
    echo -e "${RED}✗ Go not found${NC}"
    ((ERRORS++))
fi

echo
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}All parsers ready!${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS parser(s) need attention${NC}"
    exit 1
fi