# ExCoveralls configuration for RFC-068 billing test coverage
#
# Coverage Requirements:
# - Minimum: 60.1% across all modules (enforced in CI, excluding Mix tasks)
# - Target: 70% (next ratchet point)
# - Aspirational: 85% for overall codebase
# - Goal: 95% for critical paths (webhooks, billing, usage tracking)
# - Doctests: Enabled and counted in coverage
#
# Coverage History:
# - 2025-10-29: ~59% (all code)
# - 2025-10-30: 60% (all code, ratcheted from 59%)
# - 2025-11-01: 60.1% CI / 60.8% local (excluding Mix tasks - dev/ops tooling)
#
# Note on Mix Task Exclusion (dual approach):
# - mix.exs ignore_modules: Excludes Mix tasks during test execution (local runs)
# - .coveralls.exs skip_files: Excludes Mix tasks during report generation (CI merge)
# - This ensures consistent coverage calculation both locally and in CI
#
# Rationale for Mix Task Exclusion:
# - Mix tasks are CLI/dev tools that don't affect production users
# - They're difficult to test meaningfully (lots of IO/compilation)
# - Following common Elixir project practices
# - Gives more accurate view of actual application code coverage
#
# Strategy: Ratchet up coverage over time as we add tests
#
# See RFC-068 lines 362-370 for detailed requirements

import Config

config :excoveralls,
  # Include doctests in coverage analysis
  treat_no_relevant_lines_as_covered: true,
  minimum_coverage: 60.1,
  # Output directory for HTML reports
  output_dir: "cover/",
  # Terminal output format
  terminal_options: [
    file_column_width: 72
  ],
  # Skip coverage for generated and vendored code
  skip_files: [
    ~r/_build/,
    ~r/deps/,
    ~r/priv/,
    ~r|test/support/|,
    # Skip Phoenix-generated files
    ~r|lib/rsolv_web.ex|,
    ~r|lib/rsolv_web/views/error_helpers.ex|,
    ~r|lib/rsolv_web/telemetry.ex|,
    # Skip application startup files (hard to test)
    ~r|lib/rsolv/application.ex|,
    ~r|lib/rsolv/repo.ex|,
    # Skip Mix tasks - dev/ops tooling, not production code
    ~r|lib/mix/tasks/|
  ]
