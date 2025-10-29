# ExCoveralls configuration for RFC-068 billing test coverage
#
# Coverage Requirements:
# - Minimum: 70% across all modules (enforced in CI)
# - Aspirational: 85% for overall codebase
# - Goal: 95% for critical paths (webhooks, billing, usage tracking)
# - Doctests: Enabled and counted in coverage
#
# Current Coverage: ~59% (as of 2025-10-29)
# Strategy: Ratchet up coverage over time as we add tests
#
# See RFC-068 lines 362-370 for detailed requirements

import Config

config :excoveralls,
  # Include doctests in coverage analysis
  treat_no_relevant_lines_as_covered: true,
  minimum_coverage: 70.0,
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
    ~r|lib/rsolv/repo.ex|
  ]
