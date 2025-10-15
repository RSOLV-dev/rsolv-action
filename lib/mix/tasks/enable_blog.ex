defmodule Mix.Tasks.EnableBlog do
  use Mix.Task

  @shortdoc "Enables the blog feature flag"
  def run(_) do
    Mix.Task.run("app.start")

    case FunWithFlags.enable(:blog) do
      {:ok, _} ->
        IO.puts("✅ Blog feature flag enabled successfully")

      {:error, reason} ->
        IO.puts("❌ Failed to enable blog: #{inspect(reason)}")
    end
  end
end
