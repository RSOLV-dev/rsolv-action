defmodule Rsolv.Security.Patterns.DjangoTest do
  use ExUnit.Case
  doctest Rsolv.Security.Patterns.Django

  alias Rsolv.Security.Patterns.Django
  alias Rsolv.Security.Pattern

  test "all/0 returns 19 patterns" do
    patterns = Django.all()
    assert length(patterns) == 19
    assert Enum.all?(patterns, &match?(%Pattern{}, &1))
  end

  test "patterns have Django framework tag" do
    patterns = Django.all()
    assert Enum.all?(patterns, fn p -> p.frameworks == ["django"] end)
  end

  test "patterns have python language" do
    patterns = Django.all()
    assert Enum.all?(patterns, fn p -> "python" in p.languages end)
  end

  test "patterns have required fields" do
    patterns = Django.all()

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
