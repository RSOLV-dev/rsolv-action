# RSOLV Development Quick Reference

## Build/Test Commands

### Elixir Platform (root directory)
```bash
mix setup              # Full setup with .env wizard, deps, DB, assets
mix test               # Run all Elixir tests (~64s)
mix test path/to/test.exs:42  # Run single test at line 42
mix credo              # Lint + migration safety checks
mix format             # Format Elixir code
mix phx.server         # Start Phoenix server (port 4000)
```

### TypeScript Action (RSOLV-action/)
```bash
npm run test:memory    # REQUIRED - memory-safe test run (use this, not 'npm test')
npx vitest run path/to/test.ts  # Run single test file
npx tsc --noEmit       # ALWAYS run after TS changes - catches type errors
npm run lint           # ESLint check
npm run typecheck      # Full TypeScript validation
```

## Code Style Guidelines

- **TypeScript**: 2-space indent, single quotes, semicolons, Unix line endings
- **Elixir**: Use `mix format`, follow Credo rules, use doctests when practical
- **Imports**: Check existing code for library availability before adding new deps
- **Naming**: snake_case (Elixir), camelCase (TS), PascalCase (modules/components)
- **Error Handling**: Use pattern matching (Elixir), proper async/await (TS)
- **Tests**: TDD with red-green-refactor, use DataCase for DB tests (Elixir)
- **Migrations**: Run `mix credo` before committing to catch unsafe operations
- **Documentation**: Update RFCs/ADRs for architectural changes (see RFC-INDEX.md)
- **Git**: Test on staging first, never commit secrets, run lint/typecheck pre-commit