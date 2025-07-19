# RSOLV Customer End-to-End Journey - Current Implementation
**Date**: July 18, 2025  
**Status**: Based on actual codebase review  

## Architecture Overview

RSOLV consists of two main components:

1. **RSOLV-platform**: Backend API, pattern serving, AST validation, webhook handling, billing
2. **RSOLV-action**: GitHub Action that orchestrates scanning, fix generation, and PR creation

## ✅ What's Currently Implemented

### RSOLV-platform Features

1. **Email Signup & Onboarding**
   - Landing page with ConvertKit integration
   - Welcome email sequence via EmailSequence service
   - Dashboard with feature flag controls

2. **API Key Management**
   - Automatic API key generation for customers
   - Dashboard UI for viewing/regenerating keys
   - Secure storage in database

3. **AST-Enhanced Pattern Detection** (RFC-036)
   - 429+ security patterns across multiple languages
   - Server-side AST validation for 70-90% false positive reduction
   - Multi-language parsers (Python, JavaScript, Ruby, PHP, Elixir, etc.)
   - Pattern API with public/protected access levels

4. **Webhook & Billing Infrastructure**
   - GitHub webhook receiver for tracking PR events
   - Fix attempt tracking for billing
   - Customer usage tracking and limits

5. **Credential Vending Service**
   - Temporary AI provider credentials
   - Support for Anthropic, OpenAI, OpenRouter, Ollama
   - Usage tracking and reporting

### RSOLV-action Features

1. **Repository Scanning**
   - Proactive vulnerability scanning
   - AST validation integration with platform API
   - Issue grouping by vulnerability type
   - Automated GitHub issue creation with detailed reports

2. **AI-Powered Fix Generation**
   - Claude Code SDK integration (@anthropic-ai/claude-code)
   - Enhanced context gathering
   - Test-driven development approach
   - Git-based editing for accurate fixes

3. **Pull Request Creation**
   - Automated branch creation
   - File modifications via GitHub API
   - Comprehensive PR descriptions
   - Educational content and security explanations

4. **External Issue Tracker Support**
   - Jira integration
   - Linear integration
   - GitHub Issues (native)

## Complete Customer Journey

### Phase 1: Onboarding (5-10 minutes)

1. **Email Signup**
   ```
   → Visit rsolv.dev
   → Enter email in early access form
   → Receive welcome email sequence
   → ConvertKit handles email automation
   ```

2. **Dashboard Access**
   ```
   → Access dashboard at rsolv.dev/dashboard
   → View generated API key
   → Copy key for GitHub secrets
   ```

3. **GitHub Action Setup**
   ```yaml
   # .github/workflows/rsolv.yml
   name: RSOLV Security Automation
   
   on:
     schedule:
       - cron: '0 0 * * 1'  # Weekly scan
     workflow_dispatch:      # Manual trigger
     issues:
       types: [labeled]     # Fix automation
   
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: RSOLV-dev/rsolv-action@v2
           with:
             api_key: ${{ secrets.RSOLV_API_KEY }}
             scan_mode: scan
           env:
             GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   
     fix:
       if: github.event.label.name == 'rsolv:automate'
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: RSOLV-dev/rsolv-action@v2
           with:
             api_key: ${{ secrets.RSOLV_API_KEY }}
             issue_number: ${{ github.event.issue.number }}
           env:
             GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   ```

### Phase 2: Proactive Security Scanning

The action scans the repository and creates issues:

1. **Vulnerability Detection**
   - Fetches patterns from RSOLV API
   - Scans all supported file types
   - Performs AST validation to reduce false positives
   - Groups vulnerabilities by type

2. **Issue Creation**
   ```markdown
   # 🔒 SQL Injection vulnerabilities found in 3 files
   
   ## Security Vulnerability Report
   
   **Type**: SQL Injection
   **Severity**: CRITICAL
   **Total Instances**: 5
   **Affected Files**: 3
   
   ### Affected Files
   
   1. **app/models/user.rb** (2 instances)
      - Line 45: Direct string interpolation in query
      - Line 78: Unsafe parameter in WHERE clause
   
   2. **app/controllers/search_controller.rb** (2 instances)
      - Line 12: User input in SQL LIKE clause
      - Line 34: Dynamic ORDER BY clause
   
   3. **lib/reports/generator.rb** (1 instance)
      - Line 89: String concatenation in DELETE query
   
   ### Impact
   SQL injection can allow attackers to:
   - Read sensitive data
   - Modify or delete data
   - Execute administrative operations
   
   ### Recommended Action
   Apply the `rsolv:automate` label to have RSOLV automatically fix these vulnerabilities.
   ```

### Phase 3: Automated Fix Generation

When the `rsolv:automate` label is applied:

1. **Issue Analysis**
   - RSOLV-action reads the issue
   - Uses Claude Code SDK for deep context gathering
   - Analyzes codebase architecture and patterns

2. **Fix Generation Process**
   ```typescript
   // Internal process flow
   1. Credential exchange (RSOLV API key → Claude API key)
   2. Context gathering with file analysis
   3. Test framework detection
   4. TDD approach: write tests first
   5. Implement secure fix
   6. Validate no breaking changes
   ```

3. **Pull Request Creation**
   ```markdown
   # Fix SQL injection vulnerabilities in 3 files
   
   ## Summary
   This PR addresses critical SQL injection vulnerabilities by replacing 
   string interpolation with parameterized queries.
   
   ## Changes
   - ✅ Replace string interpolation with parameter binding in User model
   - ✅ Use ActiveRecord sanitization in SearchController
   - ✅ Implement prepared statements in report generator
   - ✅ Add security tests to prevent regression
   
   ## Security Tests Added
   ```ruby
   describe "SQL injection prevention" do
     it "sanitizes user input in search queries" do
       malicious_input = "'; DROP TABLE users; --"
       expect { User.search(malicious_input) }.not_to raise_error
       expect(User.count).to be > 0  # Table still exists
     end
   end
   ```
   
   ## Verification
   - All existing tests pass ✅
   - New security tests added ✅
   - No performance impact ✅
   
   Fixes #42
   
   ---
   🤖 Generated by RSOLV with Claude
   ```

### Phase 4: Review & Merge

1. **Automated Checks**
   - CI/CD runs all tests
   - Security validation passes
   - Code review by team

2. **Merge & Tracking**
   - PR merged to main branch
   - RSOLV webhook tracks the merge
   - Fix recorded for billing (if applicable)

## Technical Implementation Details

### AST Validation Flow
```
Pattern Detection → AST Parsing → Context Analysis → Confidence Scoring
                                 ↓
                          False Positive?
                               ↓
                        Filter out (70-90%)
```

### Credential Vending Flow
```
GitHub Action → RSOLV API → Validate API Key
                         ↓
                  Generate Temp Credentials
                         ↓
                  Return AI Provider Keys
                         ↓
            Direct AI API Calls from Action
```

### Fix Generation Architecture
```
Issue Context → Claude Code SDK → Repository Analysis
                              ↓
                     Test Generation (TDD)
                              ↓
                      Fix Implementation
                              ↓
                        PR Creation
```

## Metrics & Performance

- **Scan Time**: 2-5 minutes for average repository
- **Fix Generation**: 3-10 minutes per issue
- **False Positive Reduction**: 70-90% with AST validation
- **Languages Supported**: 8+ (JavaScript, TypeScript, Python, Ruby, PHP, Elixir, Java, Go)
- **Security Patterns**: 429+ and growing
- **Fix Success Rate**: ~85% for well-defined issues

## Configuration Options

### Advanced Scanning
```yaml
# .github/rsolv.yml
scanConfig:
  includePaths:
    - src/
    - lib/
  excludePaths:
    - test/
    - vendor/
  severityThreshold: medium
  maxIssuesPerRun: 10
```

### AI Configuration
```yaml
aiProvider:
  provider: anthropic
  model: claude-3-sonnet-20240229
  useVendedCredentials: true
  temperature: 0.2
```

### Security Settings
```yaml
securitySettings:
  requireCodeReview: true
  scanDependencies: true
  enableAstValidation: true  # Default: true
```

## Next Steps for Demo

1. Create test repository with intentional vulnerabilities
2. Record video showing complete flow
3. Highlight AST validation reducing false positives
4. Show TDD approach in generated fixes
5. Demonstrate educational explanations in PRs