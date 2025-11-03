defmodule Rsolv.AST.Formatters.JavaScript do
  @moduledoc """
  JavaScript/TypeScript test formatting for Jest, Vitest, and Mocha.

  Formats RED tests into JavaScript test blocks with proper structure.
  """

  @doc """
  Formats a list of RED tests into JavaScript test code.

  Returns formatted test code wrapped in a describe('security') block.
  """
  def format_tests(red_tests, _insertion_point) do
    red_tests
    |> Enum.map(&format_single_test/1)
    |> wrap_in_describe_block()
  end

  # Format a single test block
  defp format_single_test(%{"testName" => name, "testCode" => code, "attackVector" => vector}) do
    trimmed = String.trim(code)

    # Check if code is already a complete test block
    if is_complete_test_block?(trimmed) do
      code
    else
      """
      it('#{name}', () => {
        // Attack vector: #{vector}
        #{indent_code(code, 2)}
      });
      """
    end
  end

  # Check if code is already a complete test block
  defp is_complete_test_block?(code) do
    String.starts_with?(code, "it(") or
      String.starts_with?(code, "test(") or
      String.starts_with?(code, "specify(")
  end

  # Wrap test blocks in describe('security')
  defp wrap_in_describe_block(test_blocks) do
    """
    describe('security', () => {
    #{Enum.join(test_blocks, "\n")}
    });
    """
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
