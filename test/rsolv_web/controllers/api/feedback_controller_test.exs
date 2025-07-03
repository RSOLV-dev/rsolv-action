defmodule RsolvWeb.API.FeedbackControllerTest do
  use RsolvWeb.ConnCase
  alias Rsolv.Feedback

  @valid_attrs %{
    "email" => "test@example.com",
    "message" => "Great product!",
    "rating" => 5,
    "tags" => ["ui", "performance"]
  }

  describe "create/2" do
    test "creates feedback with valid data", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/feedback", @valid_attrs)
      
      assert %{
        "success" => true,
        "data" => %{
          "id" => id,
          "email" => "test@example.com",
          "message" => "Great product!",
          "rating" => 5,
          "tags" => ["ui", "performance"]
        }
      } = json_response(conn, 201)
      
      assert is_integer(id)
    end
    
    test "accepts 'content' field as alias for 'message'", %{conn: conn} do
      attrs = Map.put(@valid_attrs, "content", "Content field test")
             |> Map.delete("message")
             
      conn = post(conn, ~p"/api/v1/feedback", attrs)
      
      assert %{
        "success" => true,
        "data" => %{"message" => "Content field test"}
      } = json_response(conn, 201)
    end
    
    test "returns errors with invalid data", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/feedback", %{"email" => "invalid"})
      
      assert %{
        "success" => false,
        "errors" => errors
      } = json_response(conn, 422)
      
      assert errors["email"]
    end
  end
  
  describe "index/2" do
    test "lists all feedback entries", %{conn: conn} do
      {:ok, _} = Feedback.create_entry(%{
        email: "user1@example.com",
        message: "Feedback 1",
        source: "test"
      })
      {:ok, _} = Feedback.create_entry(%{
        email: "user2@example.com",
        message: "Feedback 2",
        source: "test"
      })
      
      conn = get(conn, ~p"/api/v1/feedback")
      
      assert %{
        "success" => true,
        "data" => entries
      } = json_response(conn, 200)
      
      assert length(entries) == 2
      assert Enum.any?(entries, &(&1["email"] == "user1@example.com"))
      assert Enum.any?(entries, &(&1["email"] == "user2@example.com"))
    end
  end
  
  describe "show/2" do
    test "returns a specific feedback entry", %{conn: conn} do
      {:ok, entry} = Feedback.create_entry(%{
        email: "test@example.com",
        message: "Test feedback",
        source: "test"
      })
      
      conn = get(conn, ~p"/api/v1/feedback/#{entry.id}")
      
      response = json_response(conn, 200)
      
      assert %{
        "success" => true,
        "data" => %{
          "id" => id,
          "email" => "test@example.com",
          "message" => "Test feedback"
        }
      } = response
      
      assert id == entry.id
    end
    
    test "returns 404 for non-existent entry", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/feedback/999999")
      
      assert %{
        "success" => false,
        "error" => "Feedback not found"
      } = json_response(conn, 404)
    end
  end
  
  describe "stats/2" do
    test "returns feedback statistics", %{conn: conn} do
      # Create some test data
      {:ok, _} = Feedback.create_entry(%{
        email: "user1@example.com",
        rating: 5,
        source: "test"
      })
      {:ok, _} = Feedback.create_entry(%{
        email: "user2@example.com",
        rating: 4,
        source: "test"
      })
      {:ok, _} = Feedback.create_entry(%{
        email: "user3@example.com",
        rating: 5,
        source: "test"
      })
      
      conn = get(conn, ~p"/api/v1/feedback/stats")
      
      assert %{
        "success" => true,
        "data" => %{
          "total_feedback" => 3,
          "rating_distribution" => %{
            "4" => 1,
            "5" => 2
          },
          "recent_feedback" => recent
        }
      } = json_response(conn, 200)
      
      assert length(recent) == 3
    end
  end
end