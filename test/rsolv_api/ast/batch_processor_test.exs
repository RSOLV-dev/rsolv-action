defmodule RsolvApi.AST.BatchProcessorTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.BatchProcessor
  
  describe "parallel parsing" do
    test "processes multiple files concurrently" do
      files = [
        %{path: "file1.js", content: "function test1() { return 'hello'; }", language: "javascript"},
        %{path: "file2.py", content: "def test2():\n    return 'world'", language: "python"},
        %{path: "file3.rb", content: "def test3\n  'ruby'\nend", language: "ruby"},
        %{path: "file4.php", content: "<?php\nfunction test4() { return 'php'; }\n?>", language: "php"}
      ]
      
      {parse_time, results} = :timer.tc(fn ->
        BatchProcessor.parse_files_parallel(files, max_concurrency: 4)
      end)
      
      # All files should be parsed successfully
      assert length(results) == 4
      assert Enum.all?(results, fn result ->
        match?({:ok, %{ast: _, path: _, language: _, parse_time_ms: _}}, result)
      end)
      
      # Should be faster than sequential processing (rough estimate)
      assert parse_time < 2_000_000  # 2 seconds in microseconds
    end
    
    test "handles parsing errors gracefully" do
      files = [
        %{path: "good.js", content: "function good() { return 'ok'; }", language: "javascript"},
        %{path: "bad.js", content: "function bad( { invalid syntax", language: "javascript"},
        %{path: "good2.py", content: "def good2():\n    return 'ok'", language: "python"}
      ]
      
      results = BatchProcessor.parse_files_parallel(files, max_concurrency: 3)
      
      assert length(results) == 3
      
      # Check successful parses
      successful = Enum.filter(results, fn
        {:ok, _} -> true
        _ -> false
      end)
      assert length(successful) == 2
      
      # Check failed parse
      failed = Enum.filter(results, fn
        {:error, _} -> true
        _ -> false
      end)
      assert length(failed) == 1
    end
    
    test "respects max concurrency limit" do
      files = for i <- 1..10 do
        %{
          path: "file#{i}.js", 
          content: "function test#{i}() { return #{i}; }", 
          language: "javascript"
        }
      end
      
      # Test with concurrency limit of 3
      start_time = System.monotonic_time()
      results = BatchProcessor.parse_files_parallel(files, max_concurrency: 3)
      end_time = System.monotonic_time()
      
      # All should succeed
      assert length(results) == 10
      assert Enum.all?(results, fn {:ok, _} -> true; _ -> false end)
      
      # Should take longer than unlimited concurrency due to queuing
      duration_ms = System.convert_time_unit(end_time - start_time, :native, :millisecond)
      assert duration_ms > 100  # Should take some measurable time
    end
    
    test "provides progress callbacks" do
      files = for i <- 1..5 do
        %{path: "file#{i}.js", content: "var x = #{i};", language: "javascript"}
      end
      
      progress_events = []
      
      results = BatchProcessor.parse_files_parallel(files, 
        max_concurrency: 2,
        progress_callback: fn event ->
          send(self(), {:progress, event})
        end
      )
      
      # Collect progress events
      events = collect_progress_events([], 5)
      
      assert length(results) == 5
      assert length(events) >= 5  # At least one event per file
      
      # Should have started and completed events
      assert Enum.any?(events, fn event -> event.type == :started end)
      assert Enum.any?(events, fn event -> event.type == :completed end)
    end
  end
  
  describe "concurrent pattern matching" do
    test "analyzes multiple ASTs concurrently" do
      asts_with_context = [
        {
          %{"type" => "Program", "body" => [
            %{"type" => "ExpressionStatement", "expression" => 
              %{"type" => "AssignmentExpression", "left" => 
                %{"type" => "MemberExpression", "property" => %{"name" => "innerHTML"}},
                "right" => %{"type" => "Identifier", "name" => "userInput"}
              }
            }
          ]},
          %{path: "xss.js", language: "javascript"}
        },
        {
          %{"type" => "Module", "body" => [
            %{"type" => "FunctionDef", "name" => "get_user", "body" => [
              %{"type" => "Assign", "targets" => [%{"id" => "query"}],
                "value" => %{"type" => "JoinedStr", "values" => ["SELECT * FROM users WHERE id = ", %{"type" => "FormattedValue"}]}
              }
            ]}
          ]},
          %{path: "sql.py", language: "python"}
        }
      ]
      
      {analysis_time, results} = :timer.tc(fn ->
        BatchProcessor.analyze_asts_parallel(asts_with_context, max_concurrency: 2)
      end)
      
      assert length(results) == 2
      
      # Should find vulnerabilities
      js_result = Enum.find(results, fn {%{path: path}, _} -> path == "xss.js" end)
      {_, js_findings} = js_result
      assert length(js_findings) > 0
      assert Enum.any?(js_findings, fn finding -> finding.type == :xss end)
      
      py_result = Enum.find(results, fn {%{path: path}, _} -> path == "sql.py" end)
      {_, py_findings} = py_result
      assert length(py_findings) > 0
      assert Enum.any?(py_findings, fn finding -> finding.type == :sql_injection end)
      
      # Should be reasonably fast
      assert analysis_time < 1_000_000  # 1 second
    end
    
    test "handles pattern matching errors gracefully" do
      asts_with_context = [
        {%{"type" => "ValidAST"}, %{path: "good.js", language: "javascript"}},
        {%{"invalid" => "structure"}, %{path: "bad.js", language: "javascript"}},
        {nil, %{path: "null.js", language: "javascript"}}
      ]
      
      results = BatchProcessor.analyze_asts_parallel(asts_with_context, max_concurrency: 3)
      
      assert length(results) == 3
      
      # All should return results (empty findings for errors)
      Enum.each(results, fn {context, findings} ->
        assert is_map(context)
        assert is_list(findings)
      end)
    end
  end
  
  describe "end-to-end batch processing" do
    test "processes files from parse to analysis" do
      files = [
        %{
          path: "vulnerable.js", 
          content: """
          function displayMessage(userInput) {
            document.getElementById('output').innerHTML = userInput;
          }
          """, 
          language: "javascript"
        },
        %{
          path: "safe.js",
          content: """
          function displayMessage(userInput) {
            document.getElementById('output').textContent = userInput;
          }
          """,
          language: "javascript"
        }
      ]
      
      results = BatchProcessor.process_batch(files, 
        max_parse_concurrency: 2,
        max_analysis_concurrency: 2,
        enable_caching: true
      )
      
      assert length(results) == 2
      
      # Check vulnerable file
      vulnerable_result = Enum.find(results, fn %{path: path} -> path == "vulnerable.js" end)
      assert length(vulnerable_result.findings) > 0
      assert Enum.any?(vulnerable_result.findings, fn f -> f.type == :xss end)
      
      # Check safe file
      safe_result = Enum.find(results, fn %{path: path} -> path == "safe.js" end)
      assert length(safe_result.findings) == 0
      
      # Should have timing metrics
      assert is_number(vulnerable_result.metrics.total_time_ms)
      assert is_number(vulnerable_result.metrics.parse_time_ms)
      assert is_number(vulnerable_result.metrics.analysis_time_ms)
    end
    
    test "uses caching to avoid redundant parsing" do
      file_content = "function test() { return 'cached'; }"
      
      files = [
        %{path: "same1.js", content: file_content, language: "javascript"},
        %{path: "same2.js", content: file_content, language: "javascript"}  # Same content
      ]
      
      # First batch - should parse both
      {first_time, first_results} = :timer.tc(fn ->
        BatchProcessor.process_batch(files, enable_caching: true)
      end)
      
      # Second batch - should use cache for both
      {second_time, second_results} = :timer.tc(fn ->
        BatchProcessor.process_batch(files, enable_caching: true)
      end)
      
      assert length(first_results) == 2
      assert length(second_results) == 2
      
      # Second batch should be significantly faster due to caching
      assert second_time < first_time / 2
      
      # Results should be identical
      assert Enum.map(first_results, & &1.path) == Enum.map(second_results, & &1.path)
    end
    
    test "handles mixed success and failure gracefully" do
      files = [
        %{path: "good1.js", content: "var x = 1;", language: "javascript"},
        %{path: "bad.js", content: "invalid {{{ syntax", language: "javascript"},
        %{path: "good2.py", content: "x = 1", language: "python"},
        %{path: "unsupported.xyz", content: "content", language: "unknown"}
      ]
      
      results = BatchProcessor.process_batch(files, continue_on_error: true)
      
      assert length(results) == 4
      
      # Check success/failure distribution
      successful = Enum.filter(results, & &1.status == :success)
      failed = Enum.filter(results, & &1.status == :error)
      
      assert length(successful) >= 2  # At least the valid JS and Python files
      assert length(failed) >= 1     # At least the invalid syntax file
      
      # Failed results should have error information
      Enum.each(failed, fn result ->
        assert is_binary(result.error)
        assert result.findings == []
      end)
    end
  end
  
  describe "performance optimization" do
    test "scales linearly with CPU cores" do
      # Create enough files to show scaling benefits
      files = for i <- 1..16 do
        %{
          path: "scale_test_#{i}.js",
          content: """
          function complexFunction#{i}() {
            var data = [];
            for (var i = 0; i < 100; i++) {
              data.push(Math.random() * #{i});
            }
            return data.reduce((a, b) => a + b, 0);
          }
          """,
          language: "javascript"
        }
      end
      
      # Test with different concurrency levels
      {time_1, _} = :timer.tc(fn -> 
        BatchProcessor.process_batch(files, max_parse_concurrency: 1)
      end)
      
      {time_4, _} = :timer.tc(fn -> 
        BatchProcessor.process_batch(files, max_parse_concurrency: 4)
      end)
      
      {time_8, _} = :timer.tc(fn -> 
        BatchProcessor.process_batch(files, max_parse_concurrency: 8)
      end)
      
      # Higher concurrency should be faster (allowing for some variance)
      assert time_4 < time_1 * 0.8   # At least 20% improvement
      assert time_8 < time_4 * 0.8   # Further improvement
    end
    
    test "manages memory efficiently under load" do
      # Create a large batch to test memory management
      files = for i <- 1..50 do
        large_content = String.duplicate("var x#{i} = 'data'; ", 1000)
        %{path: "memory_test_#{i}.js", content: large_content, language: "javascript"}
      end
      
      # Monitor memory before and after
      :erlang.garbage_collect()
      initial_memory = :erlang.memory(:total)
      
      results = BatchProcessor.process_batch(files,
        max_parse_concurrency: 8,
        max_analysis_concurrency: 8,
        enable_memory_management: true
      )
      
      :erlang.garbage_collect()
      final_memory = :erlang.memory(:total)
      
      assert length(results) == 50
      
      # Memory growth should be reasonable (allowing for some overhead)
      memory_growth = final_memory - initial_memory
      assert memory_growth < 100 * 1024 * 1024  # Less than 100MB growth
    end
  end
  
  describe "stream processing" do
    test "processes file stream without loading all into memory" do
      # Simulate a large file stream
      file_stream = Stream.map(1..100, fn i ->
        %{
          path: "stream_#{i}.js",
          content: "var stream#{i} = #{i};",
          language: "javascript"
        }
      end)
      
      results = BatchProcessor.process_stream(file_stream,
        chunk_size: 10,
        max_concurrency: 4
      )
      
      # Should process all files
      result_list = Enum.to_list(results)
      assert length(result_list) == 100
      
      # All should be successful
      assert Enum.all?(result_list, & &1.status == :success)
    end
    
    test "handles backpressure in stream processing" do
      slow_stream = Stream.map(1..20, fn i ->
        # Simulate slow file generation
        Process.sleep(10)
        %{path: "slow_#{i}.js", content: "var x = #{i};", language: "javascript"}
      end)
      
      start_time = System.monotonic_time()
      
      results = BatchProcessor.process_stream(slow_stream,
        chunk_size: 5,
        max_concurrency: 3,
        backpressure_threshold: 10
      )
      
      result_list = Enum.to_list(results)
      end_time = System.monotonic_time()
      
      assert length(result_list) == 20
      
      # Should complete in reasonable time despite backpressure
      duration_ms = System.convert_time_unit(end_time - start_time, :native, :millisecond)
      assert duration_ms < 5000  # Should complete within 5 seconds
    end
  end
  
  # Helper functions
  
  defp collect_progress_events(events, 0), do: events
  defp collect_progress_events(events, remaining) do
    receive do
      {:progress, event} -> collect_progress_events([event | events], remaining - 1)
    after
      1000 -> events  # Timeout after 1 second
    end
  end
end