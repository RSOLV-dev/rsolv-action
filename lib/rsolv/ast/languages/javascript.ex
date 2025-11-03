defmodule Rsolv.AST.Languages.JavaScript do
  @moduledoc """
  JavaScript/TypeScript AST navigation for test integration.

  Handles finding insertion points and navigating Babel-parsed ASTs
  for Jest, Vitest, and Mocha test frameworks.
  """

  require Logger

  @test_function_names ~w(it test specify)
  @describe_function_names ~w(describe context suite)

  @doc """
  Finds the best insertion point in a JavaScript/TypeScript AST.

  Returns insertion point metadata including line number, strategy, and parent context.
  Looks for the last test block (it/test) inside the outermost describe block.
  """
  def find_insertion_point(ast, framework) when framework in ~w(vitest jest mocha) do
    Logger.debug("Finding insertion point for #{framework}")

    with {:ok, describe_node} <- find_outermost_describe(ast),
         {:ok, last_test} <- find_last_test_block(describe_node) do
      line = get_node_end_line(last_test) + 1
      Logger.debug("Found insertion point at line #{line}")

      {:ok,
       %{
         line: line,
         strategy: "after_last_it_block",
         parent: "describe_block"
       }}
    else
      {:error, :no_describe_block} = error ->
        Logger.warning("No describe block found")
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

  # Find the outermost describe block in the AST
  defp find_outermost_describe(%{"type" => "File", "program" => program}),
    do: find_outermost_describe(program)

  defp find_outermost_describe(%{"type" => "Program", "body" => body}) when is_list(body) do
    case Enum.find_value(body, &find_describe_in_statement/1) do
      nil -> {:error, :no_describe_block}
      node -> {:ok, node}
    end
  end

  defp find_outermost_describe(_), do: {:error, :no_describe_block}

  # Find describe block in a statement
  defp find_describe_in_statement(%{"type" => "ExpressionStatement", "expression" => expr}),
    do: find_describe_in_expression(expr)

  defp find_describe_in_statement(_), do: nil

  # Find describe in call expression
  defp find_describe_in_expression(
         %{
           "type" => "CallExpression",
           "callee" => %{"type" => "Identifier", "name" => name}
         } = node
       )
       when name in @describe_function_names,
       do: node

  defp find_describe_in_expression(_), do: nil

  # Find the last test block (it/test) within a describe
  defp find_last_test_block(%{"arguments" => arguments}) when is_list(arguments) do
    with %{"type" => type, "body" => body}
         when type in ["FunctionExpression", "ArrowFunctionExpression"] <- Enum.at(arguments, 1),
         %{"type" => "BlockStatement", "body" => statements} <- body do
      case find_last_test_in_statements(statements) do
        nil -> {:error, :no_test_blocks}
        node -> {:ok, node}
      end
    else
      _ -> {:error, :no_test_blocks}
    end
  end

  defp find_last_test_block(_), do: {:error, :no_test_blocks}

  # Find last test in list of statements
  defp find_last_test_in_statements(statements) when is_list(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find_value(&find_test_in_statement/1)
  end

  # Find test in statement
  defp find_test_in_statement(%{
         "type" => "ExpressionStatement",
         "expression" =>
           %{
             "type" => "CallExpression",
             "callee" => %{"type" => "Identifier", "name" => name}
           } = node
       })
       when name in @test_function_names,
       do: node

  defp find_test_in_statement(_), do: nil

  # Get end line of a JavaScript AST node
  defp get_node_end_line(%{"_loc" => %{"end" => %{"line" => line}}}), do: line
  defp get_node_end_line(%{"loc" => %{"end" => %{"line" => line}}}), do: line
  defp get_node_end_line(_), do: 1
end
