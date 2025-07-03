defmodule RsolvWeb.API.FeedbackView do
  # Modern Phoenix way - using a regular module for JSON views
  
  # All render functions grouped together by name and arity
  # Function to handle index view (list of feedback items)
  def render("index.json", %{feedback: feedback}) do
    %{
      data: Enum.map(feedback, &render_feedback/1)
    }
  end
  
  # Function to handle show view (single feedback item)
  def render("show.json", %{feedback: feedback}) do
    %{
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
      data: stats
    }
  end
  
  # Function to render error
  def render("error.json", %{error: error}) do
    %{
      error: %{
        message: error
      }
    }
  end
  
  # Helper function to render a single feedback item
  defp render_feedback(feedback) do
    # Convert string keys to atoms if needed
    feedback = case feedback do
      %{id: _} -> feedback
      %{"id" => _} -> atomize_keys(feedback)
    end
    
    %{
      id: feedback.id,
      user_id: feedback[:user_id],
      email: feedback[:email],
      feedback_type: feedback[:feedback_type],
      content: feedback[:content],
      created_at: feedback[:created_at],
      priority: feedback[:priority],
      status: feedback[:status],
      source: feedback[:source],
      sentiment_score: feedback[:sentiment_score],
      sentiment: feedback[:sentiment]
    }
  end
  
  # Helper to convert string keys to atoms
  defp atomize_keys(map) do
    Map.new(map, fn
      {key, value} when is_binary(key) -> {String.to_atom(key), value}
      {key, value} -> {key, value}
    end)
  end
end