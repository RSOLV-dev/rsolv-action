#!/usr/bin/env elixir

# Performance baseline test for AST parsing
Mix.install([
  {:jason, "~> 1.4"}
])

alias RsolvApi.AST.{ParserRegistry, FallbackStrategy}

defmodule PerformanceTest do
  def run do
    IO.puts("=== AST Performance Baseline Test ===\n")
    
    # Test data
    test_cases = [
      {
        "javascript",
        """
        function vulnerable(userInput) {
          // SQL injection vulnerability
          const query = "SELECT * FROM users WHERE id = " + userInput;
          db.query(query);
          
          // Command injection
          exec("ls " + userInput);
          
          // XSS vulnerability
          document.getElementById('output').innerHTML = userInput;
        }
        """
      },
      {
        "python", 
        """
        import os
        import subprocess
        
        def vulnerable(user_input):
            # Command injection
            os.system("ls " + user_input)
            
            # SQL injection
            query = f"SELECT * FROM users WHERE id = {user_input}"
            cursor.execute(query)
            
            # Eval usage
            eval(user_input)
        """
      },
      {
        "ruby",
        """
        class VulnerableController < ApplicationController
          def index
            # SQL injection
            User.where("name = '" + params[:name] + "'")
            
            # Command injection
            system("echo " + params[:input])
            
            # Eval usage
            eval(params[:code])
          end
        end
        """
      }
    ]
    
    # Warm-up
    IO.puts("Warming up parsers...")
    Enum.each(test_cases, fn {lang, code} ->
      {:ok, _} = RsolvApi.AST.ParserRegistry.parse_code("test", "test", lang, code)
    end)
    
    IO.puts("\n=== Performance Results ===\n")
    
    # Run performance tests
    Enum.each(test_cases, fn {language, code} ->
      IO.puts("Language: #{language}")
      IO.puts("Code size: #{byte_size(code)} bytes")
      
      # Test AST parsing
      {ast_time, ast_result} = :timer.tc(fn ->
        RsolvApi.AST.ParserRegistry.parse_code("perf_test", "customer_123", language, code)
      end)
      
      ast_status = case ast_result do
        {:ok, %{ast: ast}} when ast != nil -> "✓ Success"
        {:ok, %{error: error}} when error != nil -> "✗ Failed: #{inspect(error)}"
        {:error, reason} -> "✗ Error: #{inspect(reason)}"
        _ -> "? Unknown"
      end
      
      IO.puts("  AST Parsing: #{format_time(ast_time)} - #{ast_status}")
      
      # Test with fallback strategy
      {fallback_time, fallback_result} = :timer.tc(fn ->
        RsolvApi.AST.FallbackStrategy.analyze_with_fallback(
          "perf_test", 
          "customer_123", 
          language, 
          code
        )
      end)
      
      fallback_status = case fallback_result do
        {:ok, %{strategy: :ast}} -> "✓ AST strategy"
        {:ok, %{strategy: :fallback}} -> "✓ Fallback strategy"
        {:error, reason} -> "✗ Error: #{inspect(reason)}"
        _ -> "? Unknown"
      end
      
      IO.puts("  With Fallback: #{format_time(fallback_time)} - #{fallback_status}")
      IO.puts("")
    end)
    
    # Test error handling
    IO.puts("=== Error Handling Tests ===\n")
    
    error_cases = [
      {"javascript", "function broken( { // syntax error"},
      {"python", "def broken(:\n  pass # syntax error"},
      {"ruby", "class Broken\n  def # syntax error"},
    ]
    
    Enum.each(error_cases, fn {language, code} ->
      IO.puts("Language: #{language} (syntax error)")
      
      {time, result} = :timer.tc(fn ->
        RsolvApi.AST.FallbackStrategy.analyze_with_fallback(
          "error_test",
          "customer_123", 
          language,
          code
        )
      end)
      
      strategy = case result do
        {:ok, %{strategy: strategy}} -> strategy
        _ -> :error
      end
      
      IO.puts("  Strategy used: #{strategy}")
      IO.puts("  Time: #{format_time(time)}")
      IO.puts("")
    end)
  end
  
  defp format_time(microseconds) do
    milliseconds = microseconds / 1000
    "#{:erlang.float_to_binary(milliseconds, decimals: 2)} ms"
  end
end

# Check if parsers are available before running
parsers_available = File.exists?("priv/parsers/javascript/parser.js") and
                   File.exists?("priv/parsers/python/parser.py") and
                   File.exists?("priv/parsers/ruby/parser.rb")

if parsers_available do
  PerformanceTest.run()
else
  IO.puts("Error: Parsers not found in priv/parsers/")
  IO.puts("Please ensure parsers are installed.")
end