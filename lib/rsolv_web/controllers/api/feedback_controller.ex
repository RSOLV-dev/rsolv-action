defmodule RsolvWeb.API.FeedbackController do
  use RsolvWeb, :controller
  require Logger
  alias Rsolv.Feedback
  
  @doc """
  Create a new feedback entry.
  """
  def create(conn, params) do
    Logger.info("Received feedback submission", metadata: %{params: params})
    
    # Transform params to match our schema
    attrs = %{
      email: params["email"],
      message: params["content"] || params["message"],
      rating: params["rating"],
      tags: params["tags"] || [],
      source: params["source"] || "api"
    }
    
    case Feedback.create_entry(attrs) do
      {:ok, feedback} ->
        conn
        |> put_status(:created)
        |> json(%{
          success: true,
          data: %{
            id: feedback.id,
            email: feedback.email,
            message: feedback.message,
            rating: feedback.rating,
            tags: feedback.tags,
            created_at: feedback.inserted_at
          }
        })
        
      {:error, changeset} ->
        errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
          Enum.reduce(opts, msg, fn {key, value}, acc ->
            String.replace(acc, "%{#{key}}", to_string(value))
          end)
        end)
        
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          success: false,
          errors: errors
        })
    end
  end
  
  @doc """
  Get all feedback entries.
  """
  def index(conn, _params) do
    feedback = Feedback.list_entries()
    
    conn
    |> json(%{
      success: true,
      data: Enum.map(feedback, &serialize_feedback/1)
    })
  end
  
  @doc """
  Get a specific feedback entry.
  """
  def show(conn, %{"id" => id}) do
    try do
      feedback = Feedback.get_entry!(id)
      
      conn
      |> json(%{
        success: true,
        data: serialize_feedback(feedback)
      })
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{
          success: false,
          error: "Feedback not found"
        })
    end
  end
  
  @doc """
  Get a summary of feedback statistics.
  """
  def stats(conn, _params) do
    # Generate statistics from the database
    total_count = Feedback.count_entries()
    recent_entries = Feedback.list_recent_entries(10)
    
    # Calculate rating distribution if we have ratings
    all_entries = Feedback.list_entries()
    rating_distribution = calculate_rating_distribution(all_entries)
    
    # Get recent feedback summary
    recent_feedback = Enum.map(recent_entries, fn entry ->
      %{
        id: entry.id,
        email: entry.email,
        message: String.slice(entry.message || "", 0, 100),
        rating: entry.rating,
        created_at: entry.inserted_at
      }
    end)
    
    stats = %{
      total_feedback: total_count,
      rating_distribution: rating_distribution,
      recent_feedback: recent_feedback,
      generated_at: DateTime.utc_now()
    }
    
    conn
    |> json(%{
      success: true,
      data: stats
    })
  end
  
  defp calculate_rating_distribution(entries) do
    entries
    |> Enum.filter(& &1.rating)
    |> Enum.group_by(& &1.rating)
    |> Enum.map(fn {rating, items} -> {rating, length(items)} end)
    |> Map.new()
  end
  
  defp serialize_feedback(feedback) do
    %{
      id: feedback.id,
      email: feedback.email,
      message: feedback.message,
      rating: feedback.rating,
      tags: feedback.tags,
      source: feedback.source,
      created_at: feedback.inserted_at,
      updated_at: feedback.updated_at
    }
  end
end