defmodule Rsolv.AST.Formatters.Python do
  @moduledoc """
  Python pytest test formatting.

  Formats RED tests into pytest test functions with proper structure.
  """

  @doc """
  Formats a list of RED tests into Python pytest test code.

  If inserting into an existing test class, returns functions without class wrapper.
  Otherwise, wraps in a TestSecurity class.
  """
  def format_tests(red_tests, insertion_point) do
    formatted_tests = Enum.map(red_tests, &format_single_test/1)

    if insertion_point.parent == "test_class" do
      Enum.join(formatted_tests, "\n\n")
    else
      wrap_in_test_class(formatted_tests)
    end
  end

  # Format a single pytest test function
  defp format_single_test(%{"testName" => name, "testCode" => code, "attackVector" => vector}) do
    trimmed = String.trim(code)

    # Check if code is already a complete function definition
    if is_complete_function?(trimmed) do
      """
      # Attack vector: #{vector}
      #{code}
      """
    else
      func_name = sanitize_function_name(name)

      """
      def test_#{func_name}(self):
          \"\"\"#{name}

          Attack vector: #{vector}
          \"\"\"
          #{indent_code(code, 4)}
      """
    end
  end

  # Check if code is already a complete function definition
  defp is_complete_function?(code) do
    String.starts_with?(code, "def ") or
      String.starts_with?(code, "async def ")
  end

  # Convert test name to valid Python function name
  defp sanitize_function_name(name) do
    name
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9_]/, "_")
    |> String.replace(~r/_+/, "_")
    |> String.trim("_")
  end

  # Wrap test functions in TestSecurity class
  defp wrap_in_test_class(test_functions) do
    """
    class TestSecurity:
        \"\"\"Security test suite for vulnerability validation\"\"\"

    #{Enum.join(test_functions, "\n")}
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
