#!/bin/bash
# Test script to prove pattern loading hypothesis

echo "🧪 Testing Pattern Loading Hypothesis"
echo "===================================="

# Build test container without volume mounts
echo -e "\n1. Building test container without volume mounts..."
docker build -f Dockerfile.test -t rsolv-api-test .

# Start the container
echo -e "\n2. Starting test container..."
docker run -d --name rsolv-test -p 4002:4000 rsolv-api-test
sleep 5

# Test 1: Check if pattern module loads
echo -e "\n3. Testing pattern module loading..."
docker exec rsolv-test elixir -e "IO.puts(Code.ensure_loaded?(RsolvApi.Security.Patterns.Python.SqlInjectionConcat))"

# Test 2: Check if PatternAdapter returns patterns with ast_pattern
echo -e "\n4. Testing PatternAdapter..."
docker exec rsolv-test mix run -e '
patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
IO.puts("Patterns loaded: #{length(patterns)}")
sql = Enum.find(patterns, &(String.contains?(&1.id || "", "sql")))
if sql do
  IO.puts("SQL pattern found: #{sql.id}")
  IO.puts("Has ast_pattern? #{not is_nil(Map.get(sql, :ast_pattern))}")
end
'

# Test 3: Run E2E test
echo -e "\n5. Running E2E test..."
cd .. && bun RSOLV-api/test_local_ast_debug.ts --port 4002

# Cleanup
echo -e "\n6. Cleaning up..."
docker stop rsolv-test
docker rm rsolv-test

echo -e "\n✅ Test complete!"