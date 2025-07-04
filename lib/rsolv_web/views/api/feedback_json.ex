defmodule RsolvWeb.API.FeedbackJSON do
  # Modern Phoenix way - using a regular module for JSON views
  
  # All render functions grouped together by name and arity
  # Function to handle index view (list of feedback items)
  def render("index.json", %{feedback: feedback}) do
    %{
      success: true,
      data: Enum.map(feedback, &render_feedback/1)
    }
  end
  
  # Function to handle show view (single feedback item)
  def render("show.json", %{feedback: feedback}) do
    %{
      success: true,
      data: render_feedback(feedback)
    }
  end
  
  # Function to handle a single feedback item
  def render("feedback.json", %{feedback: feedback}) do
    render_feedback(feedback)
  end
  
  # Function to render stats
  def render("stats.json", %{stats: stats}) do
    %{
      success: true,
      data: stats
    }
  end
  
  # Function to render error
  def render("error.json", %{error: error}) do
    case error do
      # For simple string errors (like "not found"), return as "error"
      error when is_binary(error) ->
        %{
          success: false,
          error: error
        }
      # For changesets and other complex errors, return as "errors"
      _ ->
        %{
          success: false,
          errors: format_errors(error)
        }
    end
  end
  
  # Helper function to render a single feedback item
  defp render_feedback(feedback) do
    %{
      id: feedback.id,
      email: feedback.email,
      message: feedback.message,
      rating: feedback.rating,
      tags: feedback.tags || [],
      source: feedback.source,
      created_at: feedback.inserted_at
    }
  end
  
  # Helper to format errors
  defp format_errors(changeset) when is_map(changeset) do
    case changeset do
      %Ecto.Changeset{} ->
        Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
          Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
            opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
          end)
        end)
      errors when is_map(errors) ->
        errors
      _ ->
        %{base: ["Unknown error"]}
    end
  end
  
  defp format_errors(error) when is_binary(error) do
    %{base: [error]}
  end
  
  defp format_errors(_), do: %{base: ["Unknown error"]}
end