#!/bin/bash
# Comprehensive test runner for RSOLV-action
# Consolidates multiple test execution strategies with proper synchronization
# Based on Bun test pollution research and mitigation strategies

set -e

# Configuration
DEFAULT_TIMEOUT=15000
ENHANCED_TIMEOUT=30000

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage function
usage() {
    echo "RSOLV Test Runner - Comprehensive test execution with pollution mitigation"
    echo ""
    echo "Usage: $0 [OPTIONS] [MODE] [PATTERN]"
    echo ""
    echo "MODES:"
    echo "  all          Run all tests (default)"
    echo "  sequential   Run tests sequentially to avoid interference"
    echo "  isolated     Run each test file in complete isolation"
    echo "  category     Run tests by category (security, integration, etc.)"
    echo "  single       Run a single test file or pattern"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help       Show this help message"
    echo "  -t, --timeout N  Set timeout in milliseconds (default: $DEFAULT_TIMEOUT)"
    echo "  -v, --verbose    Enable verbose output"
    echo "  -q, --quiet      Minimize output"
    echo "  --no-cleanup     Skip cleanup between tests (faster but less isolation)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                           # Run all tests with default settings"
    echo "  $0 sequential                # Run tests sequentially"
    echo "  $0 single pattern-api        # Run tests matching 'pattern-api'"
    echo "  $0 category security         # Run security tests only"
    echo "  $0 -t 20000 isolated        # Run isolated tests with 20s timeout"
}

# Test categories with corrected paths
declare -A TEST_CATEGORIES=(
    ["security"]="src/security/"
    ["integration"]="tests/integration/ src/__tests__/integration/"
    ["platforms"]="tests/platforms/"
    ["github"]="tests/github/"
    ["e2e"]="tests/e2e/ src/__tests__/pattern-api-e2e.test.ts"
    ["ai"]="src/__tests__/ai/ src/ai/__tests__/"
    ["core"]="src/__tests__/security-demo.test.ts src/__tests__/workflow-timeout.test.ts"
)

# Parse command line arguments
TIMEOUT=$DEFAULT_TIMEOUT
VERBOSE=false
QUIET=false
NO_CLEANUP=false
MODE="all"
PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        --no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        all|sequential|isolated|category|single)
            MODE="$1"
            shift
            ;;
        *)
            PATTERN="$1"
            shift
            ;;
    esac
done

# Logging functions
log_info() {
    if [[ "$QUIET" != true ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Cleanup function using proper synchronization
cleanup_environment() {
    local context="$1"
    
    if [[ "$NO_CLEANUP" == true ]]; then
        log_verbose "Skipping cleanup for $context"
        return
    fi
    
    log_verbose "Performing cleanup for $context"
    
    # Wait for any background processes to finish
    while pgrep -f "bun test" > /dev/null 2>&1; do
        log_verbose "Waiting for previous test processes to finish..."
        sleep 0.5
    done
    
    # Use sync utilities for proper cleanup
    if bun -e "import('./test-sync-utils.js').then(m => m.performCompleteCleanup())" 2>/dev/null; then
        log_verbose "✓ Async cleanup completed for $context"
    else
        log_verbose "⚠ Async cleanup not available, using fallback"
        # Fallback cleanup
        unset NODE_OPTIONS
        export NODE_ENV=test
        pkill -f "bun test" 2>/dev/null || true
    fi
}

# Run tests with proper environment setup
run_test_command() {
    local test_path="$1"
    local description="$2"
    
    # Set up clean environment
    export NODE_OPTIONS="--no-compilation-cache"
    export NODE_ENV="test"
    
    log_info "Testing: $description"
    
    if bun test "$test_path" --timeout "$TIMEOUT" --preload ./test-preload.ts; then
        log_success "$description - PASSED"
        return 0
    else
        log_error "$description - FAILED"
        return 1
    fi
}

# Mode: Run all tests
run_all_tests() {
    log_info "Running all tests with timeout ${TIMEOUT}ms"
    run_test_command "." "All Tests"
}

# Mode: Run tests sequentially by category
run_sequential_tests() {
    log_info "Running tests sequentially to prevent interference"
    
    local total_pass=0
    local total_fail=0
    local failed_categories=()
    
    for category in "${!TEST_CATEGORIES[@]}"; do
        local paths="${TEST_CATEGORIES[$category]}"
        
        log_info "Testing category: $category"
        
        if run_test_command "$paths" "Category: $category"; then
            ((total_pass++))
        else
            ((total_fail++))
            failed_categories+=("$category")
        fi
        
        cleanup_environment "$category"
    done
    
    log_info "Sequential test summary: $total_pass passed, $total_fail failed"
    
    if [[ ${#failed_categories[@]} -gt 0 ]]; then
        log_error "Failed categories: ${failed_categories[*]}"
        return 1
    fi
    
    return 0
}

# Mode: Run tests in complete isolation
run_isolated_tests() {
    log_info "Running tests in complete isolation"
    
    # Get all test files
    local test_files=()
    while IFS= read -r -d '' file; do
        test_files+=("$file")
    done < <(find . -name "*.test.ts" -not -path "./node_modules/*" -not -path "./test-scripts-archive-*/*" -print0)
    
    log_info "Found ${#test_files[@]} test files"
    
    local total_pass=0
    local total_fail=0
    local failed_files=()
    
    for test_file in "${test_files[@]}"; do
        log_verbose "Testing file: $test_file"
        
        if run_test_command "$test_file" "File: $test_file"; then
            ((total_pass++))
        else
            ((total_fail++))
            failed_files+=("$test_file")
        fi
        
        cleanup_environment "$test_file"
    done
    
    log_info "Isolated test summary: $total_pass passed, $total_fail failed"
    
    if [[ ${#failed_files[@]} -gt 0 ]]; then
        log_error "Failed files: ${failed_files[*]}"
        return 1
    fi
    
    return 0
}

# Mode: Run specific category
run_category_tests() {
    local category="$1"
    
    if [[ -z "${TEST_CATEGORIES[$category]}" ]]; then
        log_error "Unknown category: $category"
        log_info "Available categories: ${!TEST_CATEGORIES[*]}"
        return 1
    fi
    
    local paths="${TEST_CATEGORIES[$category]}"
    log_info "Running tests for category: $category"
    
    run_test_command "$paths" "Category: $category"
}

# Mode: Run single test or pattern
run_single_test() {
    local pattern="$1"
    
    if [[ -z "$pattern" ]]; then
        log_error "Pattern required for single test mode"
        return 1
    fi
    
    log_info "Running tests matching pattern: $pattern"
    run_test_command "*$pattern*" "Pattern: $pattern"
}

# Main execution
main() {
    log_info "RSOLV Test Runner starting in $MODE mode"
    
    case "$MODE" in
        all)
            run_all_tests
            ;;
        sequential)
            run_sequential_tests
            ;;
        isolated)
            run_isolated_tests
            ;;
        category)
            if [[ -z "$PATTERN" ]]; then
                log_error "Category name required for category mode"
                usage
                exit 1
            fi
            run_category_tests "$PATTERN"
            ;;
        single)
            run_single_test "$PATTERN"
            ;;
        *)
            log_error "Unknown mode: $MODE"
            usage
            exit 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "All tests completed successfully!"
    else
        log_error "Some tests failed (exit code: $exit_code)"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"