defmodule Rsolv.AST.ValidatorsTest do
  use ExUnit.Case, async: true
  alias Rsolv.AST.Validators

  describe "validate_content/2" do
    test "validates Ruby content and returns :ok" do
      content = "def hello\n  puts 'world'\nend"
      assert :ok = Validators.validate_content("ruby", content)
    end

    test "validates Ruby content with CJK characters" do
      content = "def hello\n  puts '世界'\nend"
      assert :ok = Validators.validate_content("ruby", content)
    end

    test "validates Ruby content with emoji" do
      content = "def hello\n  puts '🌎'\nend"
      assert :ok = Validators.validate_content("ruby", content)
    end

    test "validates Ruby content with both CJK and emoji" do
      content = "def hello\n  puts '世界 🌎'\nend"
      assert :ok = Validators.validate_content("ruby", content)
    end

    test "passes through non-Ruby languages without validation" do
      assert :ok = Validators.validate_content("javascript", "const x = 1;")
      assert :ok = Validators.validate_content("python", "x = 1")
      assert :ok = Validators.validate_content("typescript", "const x: number = 1;")
    end

    test "passes through empty content" do
      assert :ok = Validators.validate_content("ruby", "")
      assert :ok = Validators.validate_content("javascript", "")
    end
  end

  describe "validate_ruby_content/1" do
    test "returns :ok for simple Ruby code" do
      assert :ok = Validators.validate_ruby_content("puts 'hello'")
    end

    test "returns :ok for Ruby with CJK characters" do
      assert :ok = Validators.validate_ruby_content("puts '你好'")
    end

    test "returns :ok for Ruby with emoji" do
      assert :ok = Validators.validate_ruby_content("puts '😀'")
    end

    test "returns :ok for Ruby with CJK + emoji combination" do
      # This combination previously caused parser issues
      assert :ok = Validators.validate_ruby_content("puts '世界 🌏'")
    end
  end
end
