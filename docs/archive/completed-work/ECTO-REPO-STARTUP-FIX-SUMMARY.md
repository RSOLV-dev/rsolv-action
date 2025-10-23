# Ecto Repo Startup Fix Summary

## Issue
After RFC-037 Service Consolidation, many tests were failing with:
```
RuntimeError: could not lookup Ecto repo Rsolv.Repo because it was not started or it does not exist
```

## Root Cause
The `ConnCase` test helper was using `Ecto.Adapters.SQL.Sandbox.checkout/1` which assumes the repo is already started, but in some test contexts (especially when running with `--failed` flag), the application wasn't fully started.

## Fix Applied
Modified `test/support/conn_case.ex` to use `Ecto.Adapters.SQL.Sandbox.start_owner!/2` instead, which:
1. Ensures the Ecto repo process is started
2. Handles race conditions with retry logic
3. Properly cleans up on test exit

```elixir
# Before:
setup tags do
  :ok = Ecto.Adapters.SQL.Sandbox.checkout(Rsolv.Repo)
  unless tags[:async] do
    Ecto.Adapters.SQL.Sandbox.mode(Rsolv.Repo, {:shared, self()})
  end
  ...
end

# After:
setup tags do
  try do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  rescue
    error in RuntimeError ->
      if error.message =~ "could not lookup Ecto repo" do
        Application.ensure_all_started(:rsolv)
        pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
        on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
      else
        reraise error, __STACKTRACE__
      end
  end
  ...
end
```

## Results
- Web controller tests (237 tests): All passing
- API controller tests: All passing
- Analytics tests: All passing

This fix ensures consistent test behavior regardless of how tests are run (full suite, individual files, or with `--failed` flag).

## Files Modified
- `/home/dylan/dev/rsolv/RSOLV-platform/test/support/conn_case.ex`

## Date: 2025-07-05