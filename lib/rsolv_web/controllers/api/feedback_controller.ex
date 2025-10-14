defmodule RsolvWeb.API.FeedbackController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger
  alias Rsolv.Feedback
  alias RsolvWeb.Services.Metrics
  alias RsolvWeb.Schemas.Feedback.{FeedbackRequest, FeedbackResponse, FeedbackListResponse, FeedbackStats}
  alias RsolvWeb.Schemas.Error.{ErrorResponse, ValidationError}

  tags ["Feedback"]

  operation(:create,
    summary: "Submit user feedback",
    description: """
    Submit product feedback, feature requests, or bug reports.

    **No Authentication Required** - Open for all users.

    **Use Cases:**
    - Product feedback and suggestions
    - Feature requests
    - Bug reports
    - User experience insights
    - Customer satisfaction ratings

    **Prometheus Metrics:**
    This endpoint tracks feedback submissions for monitoring:
    - Total submissions by type
    - Success/error rates
    - User satisfaction trends

    **Email Collection:**
    Email addresses are used to follow up on feedback and notify users
    of feature implementations or bug fixes related to their submissions.
    """,
    request_body: {
      "Feedback submission",
      "application/json",
      FeedbackRequest,
      required: true
    },
    responses: [
      created: {"Feedback submitted successfully", "application/json", FeedbackResponse},
      unprocessable_entity: {
        "Invalid feedback data",
        "application/json",
        ValidationError
      }
    ],
    security: []
  )

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
        # Track metrics for Prometheus
        feedback_type = params["feedback_type"] || "general"
        Metrics.count_feedback_submission(feedback_type, "success")
        
        conn
        |> put_status(:created)
        |> render("show.json", feedback: feedback)
        
      {:error, reason} ->
        # Track error metrics for Prometheus
        feedback_type = Map.get(params, :feedback_type) || Map.get(params, "feedback_type") || "general"
        Metrics.count_feedback_submission(feedback_type, "error")
        
        conn
        |> put_status(:unprocessable_entity)
        |> render("error.json", error: reason)
    end
  end
  
  operation(:index,
    summary: "List all feedback entries",
    description: """
    Retrieve all feedback submissions.

    **Authentication Required** - Admin/Staff access only.

    **Use Cases:**
    - Review all customer feedback
    - Analyze feedback trends
    - Export feedback data for analysis
    - Moderate and respond to feedback

    **Response Format:**
    Returns all feedback entries with complete details including email,
    message, rating, tags, source, and timestamps.

    **Privacy Note:**
    This endpoint returns full feedback content including email addresses.
    Access should be restricted to authorized staff only.
    """,
    responses: [
      ok: {"All feedback entries retrieved successfully", "application/json", FeedbackListResponse},
      unauthorized: {"Invalid or missing authentication", "application/json", ErrorResponse}
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  def index(conn, _params) do
    feedback = Feedback.list_entries()
    render(conn, "index.json", feedback: feedback)
  end
  
  operation(:show,
    summary: "Get a specific feedback entry",
    description: """
    Retrieve a single feedback submission by ID.

    **Authentication Required** - Admin/Staff access only.

    **Use Cases:**
    - View complete feedback details
    - Investigate specific user feedback
    - Track feedback resolution
    - Link to customer records

    **Response Format:**
    Returns complete feedback details including:
    - User email address
    - Full message content
    - Rating and tags
    - Source and timestamps
    """,
    parameters: [
      id: [
        in: :path,
        description: "Unique feedback entry ID (UUID format)",
        type: :string,
        required: true,
        example: "550e8400-e29b-41d4-a716-446655440000"
      ]
    ],
    responses: [
      ok: {"Feedback entry retrieved successfully", "application/json", FeedbackResponse},
      not_found: {"Feedback entry not found", "application/json", ErrorResponse},
      unauthorized: {"Invalid or missing authentication", "application/json", ErrorResponse}
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  def show(conn, %{"id" => id}) do
    try do
      feedback = Feedback.get_entry!(id)
      render(conn, "show.json", feedback: feedback)
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> render("error.json", error: "Feedback not found")
    end
  end
  
  @doc """
  Update a feedback entry.
  """
  def update(conn, %{"id" => _id} = _params) do
    # For now, we don't have an update function, so return unimplemented
    conn
    |> put_status(:not_implemented)
    |> render("error.json", error: "Update not implemented")
  end
  
  operation(:stats,
    summary: "Get feedback statistics",
    description: """
    Retrieve aggregate statistics and recent feedback submissions.

    **No Authentication Required** - Public for transparency.

    **Statistics Included:**
    - Total feedback count
    - Rating distribution (1-5 stars)
    - Recent 10 feedback submissions (truncated)
    - Generation timestamp

    **Privacy:**
    Recent feedback messages are truncated to 100 characters to respect
    user privacy while providing insights into common themes.

    **Use Cases:**
    - Public feedback transparency
    - Product satisfaction metrics
    - Community engagement tracking
    """,
    responses: [
      ok: {"Feedback statistics retrieved successfully", "application/json", FeedbackStats}
    ],
    security: []
  )

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
    
    render(conn, "stats.json", stats: stats)
  end
  
  defp calculate_rating_distribution(entries) do
    entries
    |> Enum.filter(& &1.rating)
    |> Enum.group_by(& &1.rating)
    |> Enum.map(fn {rating, items} -> {rating, length(items)} end)
    |> Map.new()
  end
end