defmodule RsolvApi.Security.Patterns.RubyTest do
  use ExUnit.Case
  doctest RsolvApi.Security.Patterns.Ruby
  
  alias RsolvApi.Security.Patterns.Ruby
  alias RsolvApi.Security.Pattern
  
  test "all/0 returns 20 patterns" do
    patterns = Ruby.all()
    assert length(patterns) == 20
    assert Enum.all?(patterns, &match?(%Pattern{}, &1))
  end
  
  test "patterns have correct language" do
    patterns = Ruby.all()
    assert Enum.all?(patterns, fn p -> p.languages == ["ruby"] end)
  end
  
  test "patterns have required fields" do
    patterns = Ruby.all()
    
    Enum.each(patterns, fn pattern ->
      assert pattern.id != nil
      assert pattern.name != nil
      assert pattern.type != nil
      assert pattern.severity != nil
      assert pattern.cwe_id != nil
      assert pattern.owasp_category != nil
    end)
  end
end