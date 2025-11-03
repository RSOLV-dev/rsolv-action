defmodule Rsolv.AST.Languages.Ruby do
  @moduledoc """
  Ruby AST navigation for RSpec test integration.

  Handles finding insertion points in Prism-parsed Ruby ASTs.
  Supports both old parser-prism and new Prism parser formats.
  """

  require Logger

  @describe_names ~w(describe context)
  @test_names ~w(it specify example)

  @doc """
  Finds the best insertion point in a Ruby RSpec AST.

  Returns insertion point metadata including line number, strategy, and parent context.
  Looks for the last test block (it/specify/example) inside the outermost describe/context block.
  """
  def find_insertion_point(ast) do
    Logger.debug("Finding insertion point for RSpec")

    with {:ok, describe_node} <- find_outermost_describe(ast),
         {:ok, last_test} <- find_last_test_block(describe_node) do
      line = get_node_end_line(last_test) + 1
      Logger.debug("Found RSpec insertion point at line #{line}")

      {:ok,
       %{
         line: line,
         strategy: "after_last_it_block",
         parent: "describe_block"
       }}
    else
      {:error, :no_describe_block} = error ->
        Logger.warning("No describe block found in RSpec file")
        error

      {:error, :no_test_blocks} ->
        # No tests in describe - insert at end of describe block
        with {:ok, describe_node} <- find_outermost_describe(ast) do
          {:ok,
           %{
             line: get_node_end_line(describe_node) - 1,
             strategy: "inside_describe_block",
             parent: "describe_block"
           }}
        end
    end
  end

  # Find outermost describe/context block in Ruby AST
  # Prism (new): "program" → "statements" → "call" (with "block")
  # Old parser-prism: "begin" → "block" with "send" as first child
  defp find_outermost_describe(%{"type" => "program", "children" => children})
       when is_list(children) do
    children
    |> Enum.find_value(&find_outermost_describe/1)
  end

  defp find_outermost_describe(%{"type" => "statements", "children" => children})
       when is_list(children),
       do: children |> Enum.find_value(&find_describe_in_node/1) |> wrap_result()

  defp find_outermost_describe(%{"type" => "begin", "children" => children})
       when is_list(children),
       do: children |> Enum.find_value(&find_describe_in_node/1) |> wrap_result()

  defp find_outermost_describe(%{"type" => "block"} = node),
    do: node |> find_describe_in_node() |> wrap_result()

  defp find_outermost_describe(%{"type" => "call", "children" => children} = node) do
    # Prism format: call nodes directly
    if has_child_of_type?(children, "block") do
      {:ok, node}
    else
      {:error, :no_describe_block}
    end
  end

  defp find_outermost_describe(_), do: {:error, :no_describe_block}

  # Find describe/context block
  # Prism: "call" node with "block" child
  # Old parser-prism: "block" node with "send" as first child
  defp find_describe_in_node(%{"type" => "call", "children" => children} = node) do
    if has_child_of_type?(children, "block"), do: node
  end

  defp find_describe_in_node(%{"type" => "block", "children" => [send_node | _]} = node) do
    case send_node do
      %{
        "type" => "send",
        "children" => [%{"type" => "const", "children" => [nil, "RSpec"]}, "describe" | _]
      } ->
        node

      %{"type" => "send", "children" => [nil, name | _]} when name in @describe_names ->
        node

      _ ->
        nil
    end
  end

  defp find_describe_in_node(_), do: nil

  # Find last it/specify/example block in Ruby describe
  # Prism: describe is a "call" node with "block" child containing "statements"
  # Old parser-prism: "block" with 3 children: [send_node, args_node, body_node]
  defp find_last_test_block(%{"type" => "call", "children" => children}) do
    # Prism format: block contains statements, statements contains call nodes
    with %{"children" => block_children} <- find_child_of_type(children, "block") do
      # The block's first child is statements
      case block_children do
        [%{"type" => "statements", "children" => statements} | _] ->
          case find_last_test_in_statements(statements) do
            nil -> {:error, :no_test_blocks}
            node -> {:ok, node}
          end

        _ ->
          {:error, :no_test_blocks}
      end
    else
      _ -> {:error, :no_test_blocks}
    end
  end

  defp find_last_test_block(%{"type" => "block", "children" => children})
       when is_list(children) and length(children) >= 3 do
    # Third child (index 2) is the body - usually a "begin" node
    case Enum.at(children, 2) do
      %{"type" => "begin", "children" => body_children} when is_list(body_children) ->
        case find_last_test_in_statements(body_children) do
          nil -> {:error, :no_test_blocks}
          node -> {:ok, node}
        end

      single_node ->
        case find_test_in_node(single_node) do
          nil -> {:error, :no_test_blocks}
          node -> {:ok, node}
        end
    end
  end

  defp find_last_test_block(_), do: {:error, :no_test_blocks}

  # Find last test in list of statements
  defp find_last_test_in_statements(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find_value(&find_test_in_node/1)
  end

  # Find it/specify/example block
  # Prism: "call" node with "block" child
  # Old parser-prism: "block" node with "send" as first child
  defp find_test_in_node(%{"type" => "call", "children" => children} = node) do
    # In Prism, test blocks are call nodes with a block child
    # We can't easily distinguish between it/describe without parsing the method name
    # So for now, assume any call with a block inside a describe is a test
    # (This works because we only call this from within a describe block's statements)
    if has_child_of_type?(children, "block"), do: node
  end

  defp find_test_in_node(%{"type" => "block", "children" => [send_node | _]} = node) do
    case send_node do
      %{"type" => "send", "children" => [nil, name | _]} when name in @test_names ->
        node

      _ ->
        nil
    end
  end

  defp find_test_in_node(_), do: nil

  # Get end line of a Ruby AST node
  defp get_node_end_line(%{"_end_lineno" => line}) when is_integer(line), do: line
  defp get_node_end_line(_), do: 1

  # Helper: Check if a list contains a child with the specified type
  defp has_child_of_type?(children, type) when is_list(children) do
    Enum.any?(children, &(is_map(&1) && &1["type"] == type))
  end

  defp has_child_of_type?(_, _), do: false

  # Helper: Find first child node with the specified type
  defp find_child_of_type(children, type) when is_list(children) do
    Enum.find(children, &(is_map(&1) && &1["type"] == type))
  end

  defp find_child_of_type(_, _), do: nil

  # Helper: Wrap nil/value in error/ok tuple
  defp wrap_result(nil), do: {:error, :no_describe_block}
  defp wrap_result(value), do: {:ok, value}
end
