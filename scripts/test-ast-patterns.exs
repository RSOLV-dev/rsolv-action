#!/usr/bin/env elixir

# Connect to running node
{:ok, _} = Node.start(:"test@127.0.0.1")
Node.set_cookie(:rsolv_cookie)
IO.puts("Connecting to running RSOLV node...")

case Node.connect(:"rsolv@127.0.0.1") do
  true ->
    IO.puts("✅ Connected to RSOLV node")
    
    # Test pattern loading
    patterns = :rpc.call(:"rsolv@127.0.0.1", Rsolv.AST.PatternAdapter, :load_patterns_for_language, ["javascript"])
    IO.puts("\nLoaded #{length(patterns)} JavaScript patterns")
    
    # Show SQL injection patterns
    sql_patterns = Enum.filter(patterns, fn p -> 
      String.contains?(to_string(p.id), "sql")
    end)
    
    IO.puts("\nSQL Injection patterns:")
    Enum.each(sql_patterns, fn p ->
      IO.puts("- #{p.id}: #{p.name}")
    end)
    
    # Test AST parsing
    vulnerable_code = """
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query);
    """
    
    IO.puts("\nTesting vulnerable code:")
    IO.puts(vulnerable_code)
    
    # Create test file
    test_file = %{
      path: "test.js",
      content: vulnerable_code,
      language: "javascript",
      metadata: %{}
    }
    
    # Run analysis
    result = :rpc.call(:"rsolv@127.0.0.1", Rsolv.AST.AnalysisService, :analyze_file, [
      test_file, 
      %{"includeSecurityPatterns" => true}
    ])
    
    case result do
      {:ok, findings} ->
        IO.puts("\n✅ Analysis succeeded!")
        IO.puts("Found #{length(findings)} vulnerabilities:")
        Enum.each(findings, fn f ->
          IO.puts("\n- #{f.patternName}")
          IO.puts("  Type: #{f.type}")
          IO.puts("  Severity: #{f.severity}")
          IO.puts("  Confidence: #{f.confidence}")
        end)
        
      {:badrpc, reason} ->
        IO.puts("\n❌ RPC failed: #{inspect(reason)}")
        
      error ->
        IO.puts("\n❌ Analysis failed: #{inspect(error)}")
    end
    
  false ->
    IO.puts("❌ Failed to connect to RSOLV node")
    IO.puts("Is the application running? Try: iex --sname rsolv@127.0.0.1 -S mix phx.server")
end