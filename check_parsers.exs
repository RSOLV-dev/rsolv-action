#!/usr/bin/env elixir

# Check available parsers

{:ok, _} = Application.ensure_all_started(:rsolv_api)

parsers = Rsolv.AST.ParserRegistry.list_parsers()

IO.puts "Available parsers:"
Enum.each(parsers, fn {lang, config} ->
  IO.puts "  - #{lang}: #{inspect(config)}"
end)