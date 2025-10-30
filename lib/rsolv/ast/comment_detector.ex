defmodule Rsolv.AST.CommentDetector do
  @moduledoc """
  Detects if code snippets are within comments across multiple programming languages.

  Supports:
  - JavaScript: `//` and `/* */`
  - Python: `#` and `\"\"\"` docstrings
  - Ruby: `#` and `=begin/=end`

  Based on language specifications:
  - ECMAScript (JavaScript): https://tc39.es/ecma262/
  - PEP 257 (Python Docstrings): https://peps.python.org/pep-0257/
  - Ruby Syntax: https://docs.ruby-lang.org/en/master/syntax/comments_rdoc.html
  """

  @doc """
  Checks if a code snippet appears within a comment.

  ## Parameters
  - `code`: The code snippet to check
  - `file_content`: The full file content as a string
  - `line_number`: The 1-based line number where the code appears

  ## Returns
  `true` if the code is within a comment, `false` otherwise

  ## Examples

      iex> CommentDetector.in_comment?("eval(x)", "// eval(x)", 1)
      true

      iex> CommentDetector.in_comment?("eval(x)", "eval(x);", 1)
      false
  """
  def in_comment?(code, file_content, line_number) do
    lines = String.split(file_content, "\n")
    # Handle both 0-based and 1-based line numbers
    actual_line_number = if line_number == 0, do: 1, else: line_number
    line = Enum.at(lines, actual_line_number - 1, "")

    # Check for single-line comment
    cond do
      # If the entire line is the comment pattern (e.g., "// eval(userInput)")
      String.trim(line) == code and String.starts_with?(String.trim(code), "//") ->
        true

      # Check if code appears after // on the line
      String.contains?(line, "//") ->
        comment_start =
          case :binary.match(line, "//") do
            :nomatch -> nil
            {pos, _} -> pos
          end

        code_pos =
          case :binary.match(line, code) do
            :nomatch -> -1
            {pos, _} -> pos
          end

        comment_start != nil and code_pos >= comment_start

      # Check for Python/Ruby style comments
      String.trim(line) == code and String.starts_with?(String.trim(code), "#") ->
        true

      # Check if code starts with comment markers (not just contains them)
      # This handles cases like "/*" or "*/" as the actual code being flagged
      String.starts_with?(String.trim(code), ["/*", "*/", "=begin"]) ->
        true

      # Check if we're inside Python docstring/multi-line string
      true ->
        in_multiline_comment?(file_content, line_number)
    end
  end

  @doc """
  Checks if a line is within a multi-line comment block.

  Handles:
  - JavaScript `/* */` comments (including JSDoc `/** */`)
  - Python `\"\"\"` docstrings
  - Ruby `=begin/=end` blocks
  """
  def in_multiline_comment?(file_content, line_number) do
    lines = String.split(file_content, "\n")

    # Get all lines up to and including the current line
    check_lines = Enum.take(lines, line_number)

    # Check for JavaScript multi-line comments
    in_js_comment = in_js_multiline_comment?(check_lines)

    # Check if we're inside a Python docstring
    # Count triple quotes before our line
    before_lines = Enum.take(lines, line_number - 1)

    triple_quote_count =
      Enum.reduce(before_lines, 0, fn line, acc ->
        acc + length(Regex.scan(~r/"""/, line))
      end)

    in_python_docstring = rem(triple_quote_count, 2) == 1

    # Check if we're in a Ruby multi-line comment
    in_ruby_comment =
      Enum.any?(before_lines, fn line ->
        String.trim(line) == "=begin" or String.starts_with?(String.trim(line), "=begin ")
      end) and
        not Enum.any?(before_lines, fn line ->
          String.trim(line) == "=end" or String.starts_with?(String.trim(line), "=end ")
        end)

    in_js_comment or in_python_docstring or in_ruby_comment
  end

  @doc """
  Tracks state through JavaScript `/* */` comment blocks.

  Returns `true` if currently inside an unclosed comment block.

  ## Edge Cases
  - `/* */` on same line: properly tracks open/close
  - Nested `/*`: follows JS spec (not supported, first `*/` closes)
  - Multiple comments on different lines: tracks state correctly
  """
  def in_js_multiline_comment?(lines) do
    # Track if we're inside a /* */ comment
    {in_comment, _} =
      Enum.reduce(lines, {false, false}, fn line, {in_comment, _} ->
        cond do
          # If we're in a comment and find */, we're out
          in_comment and String.contains?(line, "*/") ->
            {false, true}

          # If we find /*, we're in a comment
          String.contains?(line, "/*") ->
            # Check if it also closes on same line
            if String.contains?(line, "*/") do
              # Check which comes last
              open_pos = :binary.match(line, "/*") |> elem(0)
              close_pos = :binary.match(line, "*/") |> elem(0)
              # If close comes before open, we end in-comment state
              {close_pos < open_pos, true}
            else
              {true, true}
            end

          true ->
            {in_comment, in_comment}
        end
      end)

    in_comment
  end
end
