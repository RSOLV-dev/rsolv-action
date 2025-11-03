defmodule Rsolv.AST.Formatters.Ruby do
  @moduledoc """
  Ruby RSpec test formatting.

  Formats RED tests into RSpec test blocks with proper structure.
  """

  @doc """
  Formats a list of RED tests into Ruby RSpec test code.

  Returns formatted test code wrapped in a describe 'security' block.
  """
  def format_tests(red_tests, _insertion_point) do
    red_tests
    |> Enum.map(&format_single_test/1)
    |> wrap_in_describe_block()
  end

  # Format a single RSpec test block
  defp format_single_test(%{"testName" => name, "testCode" => code, "attackVector" => vector}) do
    trimmed = String.trim(code)

    # Check if code is already a complete test block
    if is_complete_test_block?(trimmed) do
      code
    else
      """
      it '#{name}' do
        # Attack vector: #{vector}
        #{indent_code(code, 2)}
      end
      """
    end
  end

  # Check if code is already a complete test block
  defp is_complete_test_block?(code) do
    String.starts_with?(code, "it ") or
      String.starts_with?(code, "specify ") or
      String.starts_with?(code, "example ")
  end

  # Wrap test blocks in describe 'security'
  defp wrap_in_describe_block(test_blocks) do
    indented_blocks =
      test_blocks
      |> Enum.map(&String.trim_trailing/1)
      |> Enum.map(fn block -> indent_lines(block, 2) end)
      |> Enum.join("\n\n")

    """
    describe 'security' do
    #{indented_blocks}
    end
    """
  end

  # Indent all lines in a string
  defp indent_lines(text, spaces) do
    indent = String.duplicate(" ", spaces)

    text
    |> String.split("\n")
    |> Enum.map(fn line ->
      if String.trim(line) == "", do: line, else: indent <> line
    end)
    |> Enum.join("\n")
  end

  # Indent code by adding spaces to each line
  defp indent_code(code, spaces) do
    indent = String.duplicate(" ", spaces)

    code
    |> String.split("\n")
    |> Enum.map(fn
      "" -> ""
      line -> indent <> line
    end)
    |> Enum.join("\n")
  end
end
