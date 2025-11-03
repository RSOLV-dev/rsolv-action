defmodule Rsolv.AST.Validators do
  @moduledoc """
  Content validation for AST parsing.

  Validates source code content before parsing to catch known parser limitations.
  """

  require Logger

  @doc """
  Validates Ruby content for known parser limitations.

  Checks for CJK characters + emoji combinations that may cause issues
  with certain parser versions. Currently allows all content through
  for testing with Prism parser.
  """
  def validate_ruby_content(content) do
    # Temporarily disabled to test if Prism + working directory fix resolves unicode issues
    # Previously: parser-3.3.8.0 had issues with CJK + emoji
    # Now testing: parser-prism with Prism backend should handle unicode better

    if has_cjk_and_emoji?(content) do
      Logger.info(
        "Validators: Ruby code contains CJK characters + emoji, testing with Prism parser"
      )
    end

    # Allow through to test if Prism + working directory fix works
    :ok
  end

  @doc """
  Validates content for any language.

  Currently only performs validation for Ruby. Other languages pass through.
  """
  def validate_content("ruby", content), do: validate_ruby_content(content)
  def validate_content(_language, _content), do: :ok

  # Check if content has both CJK characters and emoji
  defp has_cjk_and_emoji?(content) do
    has_cjk_characters?(content) and has_emoji_characters?(content)
  end

  # Check for CJK (Chinese, Japanese, Korean) characters
  defp has_cjk_characters?(content) do
    content
    |> String.to_charlist()
    |> Enum.any?(&is_cjk_codepoint?/1)
  end

  # Check for emoji characters
  defp has_emoji_characters?(content) do
    content
    |> String.to_charlist()
    |> Enum.any?(&is_emoji_codepoint?/1)
  end

  # CJK Unified Ideographs: U+4E00 to U+9FFF
  defp is_cjk_codepoint?(codepoint) do
    codepoint >= 0x4E00 and codepoint <= 0x9FFF
  end

  # Emoji ranges
  defp is_emoji_codepoint?(codepoint) do
    # Emoticons: U+1F600 to U+1F64F
    # Misc Symbols and Pictographs: U+1F300 to U+1F5FF
    # Transport and Map Symbols: U+1F680 to U+1F6FF
    # Supplemental Symbols: U+1F900 to U+1F9FF
    # Misc Symbols: U+2600 to U+26FF
    # Dingbats: U+2700 to U+27BF
    (codepoint >= 0x1F600 and codepoint <= 0x1F64F) or
      (codepoint >= 0x1F300 and codepoint <= 0x1F5FF) or
      (codepoint >= 0x1F680 and codepoint <= 0x1F6FF) or
      (codepoint >= 0x1F900 and codepoint <= 0x1F9FF) or
      (codepoint >= 0x2600 and codepoint <= 0x26FF) or
      (codepoint >= 0x2700 and codepoint <= 0x27BF)
  end
end
