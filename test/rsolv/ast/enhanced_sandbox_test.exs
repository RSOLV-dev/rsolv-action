defmodule Rsolv.AST.EnhancedSandboxTest do
  use ExUnit.Case, async: false

  alias Rsolv.AST.EnhancedSandbox

  describe "input validation" do
    test "accepts valid JavaScript code" do
      valid_code = """
      function hello() {
        return "Hello, World!";
      }
      """

      assert {:ok, ^valid_code} = EnhancedSandbox.validate_input(valid_code, "javascript")
    end

    test "rejects empty input" do
      assert {:error, :empty_input} = EnhancedSandbox.validate_input("", "javascript")
    end

    test "rejects files over 10MB" do
      large_input = String.duplicate("x", 11 * 1024 * 1024)
      assert {:error, :file_too_large} = EnhancedSandbox.validate_input(large_input, "javascript")
    end

    test "detects shell injection attempts" do
      malicious_code = """
      const cmd = `rm -rf /`;
      exec(cmd);
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(malicious_code, "javascript")
    end

    test "detects eval usage" do
      code_with_eval = """
      const userInput = getUserInput();
      eval(userInput);
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(code_with_eval, "javascript")
    end

    test "detects path traversal attempts" do
      malicious_code = """
      const file = fs.readFile('../../etc/passwd');
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(malicious_code, "javascript")
    end

    test "detects excessive nesting" do
      # Generate deeply nested brackets
      nested = String.duplicate("{", 60) <> String.duplicate("}", 60)

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(nested, "javascript")
    end

    test "detects Python-specific dangerous patterns" do
      python_code = """
      import os
      __import__('subprocess').call(['rm', '-rf', '/'])
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(python_code, "python")
    end

    test "detects Ruby-specific dangerous patterns" do
      ruby_code = """
      user_input = gets
      instance_eval(user_input)
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(ruby_code, "ruby")
    end

    test "detects PHP-specific dangerous patterns" do
      php_code = """
      <?php
      $cmd = $_GET['cmd'];
      shell_exec($cmd);
      ?>
      """

      assert {:error, ["suspicious_pattern", _pattern_data]} =
               EnhancedSandbox.validate_input(php_code, "php")
    end

    test "sanitizes null bytes" do
      input_with_nulls = "hello\0world\0"
      assert {:ok, "helloworld"} = EnhancedSandbox.validate_input(input_with_nulls, "javascript")
    end

    test "detects high complexity code" do
      # Generate high complexity input without triggering pattern detection
      complex_input =
        Enum.reduce(1..50, "", fn i, acc ->
          acc <> "function f#{i}() { " <> String.duplicate("x", 1000) <> " }\n"
        end) <> String.duplicate("var y = ", 100)

      assert {:error, {:complexity_too_high, _}} =
               EnhancedSandbox.validate_input(complex_input, "javascript")
    end
  end

  describe "enhanced configuration" do
    test "creates stricter configuration than base" do
      config = EnhancedSandbox.create_enhanced_config("javascript")

      # Check stricter limits
      # 128MB
      assert config.limits.max_heap_size == 32_000_000
      assert config.limits.max_reductions == 1_000_000
      assert config.limits.timeout_ms == 15_000
      assert config.limits.max_message_queue == 100
      assert config.limits.max_processes == 10

      # Check enhanced spawn options
      assert Keyword.get(config.spawn_opts, :priority) == :low
      assert config.strict_mode == true
    end

    test "sets low process priority" do
      config = EnhancedSandbox.create_enhanced_config("python")
      assert Keyword.get(config.spawn_opts, :priority) == :low
    end
  end

  describe "security metrics" do
    test "tracks security events" do
      # Clear any existing events
      case :ets.whereis(:security_events) do
        :undefined -> :ok
        table -> :ets.delete_all_objects(table)
      end

      # Trigger some validation failures
      EnhancedSandbox.validate_input("", "javascript")
      EnhancedSandbox.validate_input("eval(x)", "javascript")

      metrics = EnhancedSandbox.get_security_metrics()

      assert metrics[:input_validation_failed] >= 2
    end
  end

  describe "rate limiting" do
    test "enforces rate limits per language" do
      # Clear rate limit table
      case :ets.whereis(:parser_rate_limits) do
        :undefined -> :ok
        table -> :ets.delete_all_objects(table)
      end

      config = EnhancedSandbox.create_enhanced_config("javascript")

      # Should allow first request
      assert :ok = EnhancedSandbox.check_rate_limit(config)

      # Simulate hitting rate limit
      for _ <- 1..100 do
        EnhancedSandbox.check_rate_limit(config)
      end

      # 101st request should be rate limited
      assert {:error, :rate_limited} = EnhancedSandbox.check_rate_limit(config)
    end
  end
end
