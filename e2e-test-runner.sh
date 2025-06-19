#!/bin/bash

# E2E Test Runner - Runs end-to-end tests without global mocks
# This runner is designed for integration testing with real services

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Test configuration
readonly DEFAULT_TIMEOUT=60000
readonly E2E_ENV="e2e"
readonly CLEANUP_DELAY=2000

# Global variables
VERBOSE=false
TIMEOUT=$DEFAULT_TIMEOUT
ENVIRONMENT="staging"
SKIP_SETUP=false
PRESERVE_ARTIFACTS=false
TEST_PATTERN=""
DRY_RUN=false

# Print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Print usage information
print_usage() {
    cat << EOF
E2E Test Runner - Isolated end-to-end testing without global mocks

USAGE:
    ./e2e-test-runner.sh [OPTIONS] [COMMAND] [PATTERN]

COMMANDS:
    all                 Run all E2E tests (default)
    integration         Run integration tests only
    api                 Run API integration tests
    workflow            Run full workflow tests
    github              Run GitHub integration tests
    single              Run single test file or pattern

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -t, --timeout N     Set timeout in milliseconds (default: $DEFAULT_TIMEOUT)
    -e, --env ENV       Environment to test against (staging/production)
    -s, --skip-setup    Skip environment setup
    -p, --preserve      Preserve test artifacts after completion
    -d, --dry-run       Show what would be run without executing
    --pattern PATTERN   Test pattern to match (regex)

EXAMPLES:
    ./e2e-test-runner.sh                              # Run all E2E tests
    ./e2e-test-runner.sh -v -e production integration # Run integration tests against production
    ./e2e-test-runner.sh single pattern-api           # Run specific test
    ./e2e-test-runner.sh --pattern "webhook.*" api    # Run API tests matching pattern
    ./e2e-test-runner.sh -d all                       # Dry run all tests

ENVIRONMENT VARIABLES:
    RSOLV_API_URL       API base URL (overrides --env)
    RSOLV_API_KEY       API key for authentication
    GITHUB_TOKEN        GitHub token for integration tests
    E2E_SKIP_CLEANUP    Skip cleanup between tests
    E2E_PRESERVE_LOGS   Preserve test logs

TEST CATEGORIES:
    integration         Cross-service integration tests
    api                 RSOLV API integration tests
    workflow            Complete workflow tests (issue -> PR)
    github              GitHub platform integration tests
    
ISOLATION FEATURES:
    - No global mocks (uses real services)
    - Clean environment for each test run
    - Real API credentials and network calls
    - Actual file system operations
    - Proper resource cleanup

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--skip-setup)
                SKIP_SETUP=true
                shift
                ;;
            -p|--preserve)
                PRESERVE_ARTIFACTS=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --pattern)
                TEST_PATTERN="$2"
                shift 2
                ;;
            all|integration|api|workflow|github|single)
                COMMAND="$1"
                shift
                ;;
            *)
                if [[ -z "${COMMAND:-}" ]] && [[ "$1" =~ ^[a-zA-Z] ]]; then
                    COMMAND="$1"
                elif [[ "${COMMAND:-}" == "single" ]] && [[ -z "${TEST_PATTERN:-}" ]]; then
                    TEST_PATTERN="$1"
                else
                    print_color $RED "ERROR: Unknown argument '$1'"
                    print_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Set default command
    COMMAND="${COMMAND:-all}"
}

# Setup test environment
setup_environment() {
    if [[ "$SKIP_SETUP" == "true" ]]; then
        print_color $CYAN "Skipping environment setup"
        return 0
    fi
    
    print_color $CYAN "Setting up E2E test environment..."
    
    # Set environment-specific configuration
    case "$ENVIRONMENT" in
        staging)
            export RSOLV_API_URL="${RSOLV_API_URL:-https://api.rsolv-staging.com}"
            ;;
        production)
            export RSOLV_API_URL="${RSOLV_API_URL:-https://api.rsolv.dev}"
            print_color $YELLOW "WARNING: Testing against production environment"
            ;;
        *)
            print_color $RED "ERROR: Unknown environment '$ENVIRONMENT'"
            exit 1
            ;;
    esac
    
    # Validate required environment variables
    local missing_vars=()
    
    if [[ -z "${RSOLV_API_KEY:-}" ]]; then
        missing_vars+=("RSOLV_API_KEY")
    fi
    
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        missing_vars+=("GITHUB_TOKEN")
    fi
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_color $RED "ERROR: Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            print_color $RED "  - $var"
        done
        exit 1
    fi
    
    # Set E2E-specific environment
    export NODE_ENV="test"
    export E2E_MODE="true"
    export E2E_ENVIRONMENT="$ENVIRONMENT"
    export E2E_TIMEOUT="$TIMEOUT"
    
    print_color $GREEN "Environment setup complete"
    if [[ "$VERBOSE" == "true" ]]; then
        print_color $BLUE "  API URL: $RSOLV_API_URL"
        print_color $BLUE "  Environment: $ENVIRONMENT"
        print_color $BLUE "  Timeout: ${TIMEOUT}ms"
    fi
}

# Get test files for a specific category
get_test_files() {
    local category=$1
    local files=()
    
    case "$category" in
        integration)
            files=(
                "tests/integration/ai-integration.test.ts"
                "tests/integration/config.test.ts"
                "tests/integration/container.test.ts"
                "src/__tests__/integration-test.ts"
            )
            ;;
        api)
            files=(
                "src/__tests__/pattern-api-e2e.test.ts"
                "tests/e2e/api-integration.test.ts"
            )
            ;;
        workflow)
            files=(
                "tests/e2e/workflow-complete.test.ts"
                "tests/e2e/issue-to-pr.test.ts"
            )
            ;;
        github)
            files=(
                "tests/platforms/github.test.ts"
                "tests/integration/github-integration.test.ts"
            )
            ;;
        all)
            # Recursively get all categories
            for cat in integration api workflow github; do
                local cat_files
                cat_files=($(get_test_files "$cat"))
                files+=("${cat_files[@]}")
            done
            ;;
        single)
            # Find files matching pattern
            if [[ -n "$TEST_PATTERN" ]]; then
                readarray -t files < <(find . -name "*.test.ts" -path "*/tests/*" -o -path "*/__tests__/*" | grep -E "$TEST_PATTERN" || true)
            fi
            ;;
    esac
    
    # Filter files that actually exist
    local existing_files=()
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            existing_files+=("$file")
        fi
    done
    
    printf '%s\n' "${existing_files[@]}"
}

# Run a single test file without global mocks
run_test_file() {
    local test_file=$1
    local test_name=$(basename "$test_file" .test.ts)
    
    print_color $BLUE "Running E2E test: $test_name"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_color $YELLOW "DRY RUN: Would run $test_file"
        return 0
    fi
    
    # Create clean test environment
    local temp_env=$(mktemp)
    local test_log=$(mktemp)
    
    # Export current environment to temp file
    export > "$temp_env"
    
    # Run test with E2E configuration (no global mocks)
    local test_command=(
        bun test
        --config bunfig.e2e.toml
        --preload ./e2e-test-preload.ts
        --timeout "$TIMEOUT"
        "$test_file"
    )
    
    if [[ "$VERBOSE" == "true" ]]; then
        test_command+=(--verbose)
    fi
    
    if [[ -n "$TEST_PATTERN" ]]; then
        test_command+=(--grep "$TEST_PATTERN")
    fi
    
    print_color $CYAN "  Command: ${test_command[*]}"
    
    # Execute test
    local exit_code=0
    if "${test_command[@]}" 2>&1 | tee "$test_log"; then
        print_color $GREEN "  ✅ PASSED: $test_name"
    else
        exit_code=$?
        print_color $RED "  ❌ FAILED: $test_name (exit code: $exit_code)"
        
        if [[ "$VERBOSE" == "true" ]]; then
            print_color $YELLOW "  Test output:"
            cat "$test_log" | sed 's/^/    /'
        fi
    fi
    
    # Cleanup unless preserving artifacts
    if [[ "$PRESERVE_ARTIFACTS" != "true" ]]; then
        rm -f "$temp_env" "$test_log"
    else
        print_color $CYAN "  Preserved artifacts: $temp_env, $test_log"
    fi
    
    # Brief pause to allow cleanup
    sleep $(echo "scale=3; $CLEANUP_DELAY / 1000" | bc)
    
    return $exit_code
}

# Run test category
run_test_category() {
    local category=$1
    local test_files
    readarray -t test_files < <(get_test_files "$category")
    
    if [[ ${#test_files[@]} -eq 0 ]]; then
        print_color $YELLOW "No test files found for category: $category"
        return 0
    fi
    
    print_color $PURPLE "Running E2E test category: $category (${#test_files[@]} files)"
    
    local failed_tests=()
    local passed_tests=()
    
    for test_file in "${test_files[@]}"; do
        if run_test_file "$test_file"; then
            passed_tests+=("$test_file")
        else
            failed_tests+=("$test_file")
        fi
    done
    
    # Summary
    print_color $CYAN "\n=== Category Summary: $category ==="
    print_color $GREEN "Passed: ${#passed_tests[@]}"
    print_color $RED "Failed: ${#failed_tests[@]}"
    
    if [[ ${#failed_tests[@]} -gt 0 ]]; then
        print_color $RED "Failed tests:"
        for test in "${failed_tests[@]}"; do
            print_color $RED "  - $test"
        done
        return 1
    fi
    
    return 0
}

# Cleanup function
cleanup() {
    local exit_code=$?
    
    if [[ "$PRESERVE_ARTIFACTS" != "true" ]]; then
        print_color $CYAN "Cleaning up test artifacts..."
        
        # Clean up any temporary files
        find /tmp -name "rsolv-e2e-*" -type f -mtime +1 -delete 2>/dev/null || true
        
        # Reset environment variables
        unset E2E_MODE E2E_ENVIRONMENT E2E_TIMEOUT
    fi
    
    print_color $CYAN "E2E test run completed"
    exit $exit_code
}

# Main execution
main() {
    print_color $CYAN "🧪 RSOLV E2E Test Runner"
    print_color $CYAN "========================="
    
    parse_args "$@"
    setup_environment
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Execute command
    case "$COMMAND" in
        all|integration|api|workflow|github)
            run_test_category "$COMMAND"
            ;;
        single)
            if [[ -z "$TEST_PATTERN" ]]; then
                print_color $RED "ERROR: Pattern required for single test mode"
                exit 1
            fi
            run_test_category "single"
            ;;
        *)
            print_color $RED "ERROR: Unknown command '$COMMAND'"
            print_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"