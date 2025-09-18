alias Rsolv.Repo

IO.puts("Checking analytics_events table schema...")

result = Repo.query("""
  SELECT column_name, data_type
  FROM information_schema.columns
  WHERE table_name = 'analytics_events'
  ORDER BY ordinal_position
""")

case result do
  {:ok, %{rows: rows}} ->
    IO.puts("\nColumns in analytics_events table:")
    Enum.each(rows, fn [name, type] ->
      IO.puts("  #{name}: #{type}")
    end)
  {:error, error} ->
    IO.puts("Error: #{inspect(error)}")
end