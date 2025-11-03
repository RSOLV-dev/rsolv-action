defmodule Rsolv.AST.Languages.Python do
  @moduledoc """
  Python AST navigation for pytest test integration.

  Handles finding insertion points in Python ASTs parsed by the ast module.
  Supports both class-based and module-level test functions.
  """

  require Logger

  @test_prefix "test_"

  @doc """
  Finds the best insertion point in a Python pytest AST.

  Returns insertion point metadata including line number, strategy, and parent context.
  Looks for test classes or module-level test functions.
  """
  def find_insertion_point(ast) do
    Logger.debug("Finding insertion point for pytest")

    case find_test_container(ast) do
      {:ok, container_type, container_node, last_test} ->
        line =
          if last_test,
            do: get_node_end_line(last_test) + 1,
            else: get_node_end_line(container_node) - 1

        Logger.debug("Found pytest insertion point at line #{line} (#{container_type})")

        {:ok,
         %{
           line: line,
           strategy: "after_last_test_function",
           parent: container_type
         }}

      {:error, _} = error ->
        Logger.warning("No test class or function found in pytest file")
        error
    end
  end

  # Find test container (class or module-level) in Python AST
  defp find_test_container(%{"type" => "Module", "body" => body}) when is_list(body) do
    # Look for test class first, then fall back to module-level test functions
    case find_test_class(body) do
      {:ok, class_node, last_test} ->
        {:ok, "test_class", class_node, last_test}

      {:error, :no_test_class} ->
        case find_last_module_test(body) do
          nil -> {:error, :no_test_container}
          last_test -> {:ok, "module", %{"type" => "Module"}, last_test}
        end
    end
  end

  defp find_test_container(_), do: {:error, :no_test_container}

  # Find test class (ClassDef starting with "Test")
  defp find_test_class(statements) do
    test_class =
      Enum.find(statements, fn
        %{"type" => "ClassDef", "name" => name} when is_binary(name) ->
          String.starts_with?(name, "Test")

        _ ->
          false
      end)

    case test_class do
      nil ->
        {:error, :no_test_class}

      %{"body" => body} when is_list(body) ->
        last_test = find_last_test_in_class(body)
        {:ok, test_class, last_test}
    end
  end

  # Find last test function in class body
  defp find_last_test_in_class(body) do
    body
    |> Enum.reverse()
    |> Enum.find(&is_test_function?/1)
  end

  # Find last module-level test function
  defp find_last_module_test(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find(&is_test_function?/1)
  end

  # Check if node is a test function (starts with test_)
  defp is_test_function?(%{"type" => type, "name" => name})
       when type in ["FunctionDef", "AsyncFunctionDef"] and is_binary(name) do
    String.starts_with?(name, @test_prefix)
  end

  defp is_test_function?(_), do: false

  # Get end line of a Python AST node
  defp get_node_end_line(%{"_end_lineno" => line}) when is_integer(line), do: line
  defp get_node_end_line(_), do: 1
end
