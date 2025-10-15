defmodule Rsolv.Feedback.Schema do
  @moduledoc """
  Defines the schema for the feedback system.
  These are used for both CSV storage and future database migration.
  """

  @doc """
  Schema definition for feedback entries.
  """
  def feedback_schema do
    %{
      # Unique ID for the feedback
      id: :string,
      # ID of the user who submitted the feedback
      user_id: :string,
      # Email of the user (optional if user_id is provided)
      email: :string,
      # Type of feedback (e.g., bug, feature, usability)
      feedback_type: :string,
      # The actual feedback content
      content: :string,
      # Additional metadata (e.g., browser, OS, etc.)
      metadata: :map,
      # When the feedback was created
      created_at: :utc_datetime,
      # Priority level (1-5, where 1 is highest)
      priority: :integer,
      # Status of the feedback (e.g., new, in_progress, resolved)
      status: :string,
      # Source of the feedback (e.g., website, email, etc.)
      source: :string
    }
  end

  @doc """
  Schema definition for feedback tags.
  """
  def feedback_tag_schema do
    %{
      # Unique ID for the tag
      id: :string,
      # ID of the feedback this tag is associated with
      feedback_id: :string,
      # The tag content
      tag: :string,
      # When the tag was created
      created_at: :utc_datetime
    }
  end

  @doc """
  Schema definition for users.
  """
  def user_schema do
    %{
      # Unique ID for the user
      id: :string,
      # Email of the user
      email: :string,
      # Name of the user (optional)
      name: :string,
      # Company of the user (optional)
      company: :string,
      # When the user signed up
      signup_date: :utc_datetime,
      # When the user was last active
      last_active: :utc_datetime,
      # Additional metadata about the user
      metadata: :map
    }
  end

  @doc """
  Schema definition for issues.
  """
  def issue_schema do
    %{
      # Unique ID for the issue
      id: :string,
      # Repository the issue is associated with
      repository: :string,
      # Title of the issue
      title: :string,
      # Description of the issue
      description: :string,
      # When the issue was created
      created_at: :utc_datetime,
      # Status of the issue
      status: :string,
      # Additional metadata about the issue
      metadata: :map
    }
  end

  @doc """
  Schema definition for solutions.
  """
  def solution_schema do
    %{
      # Unique ID for the solution
      id: :string,
      # ID of the issue this solution is for
      issue_id: :string,
      # The actual solution content
      content: :string,
      # When the solution was created
      created_at: :utc_datetime,
      # Status of the solution
      status: :string,
      # Additional metadata about the solution
      metadata: :map
    }
  end

  @doc """
  Returns a list of all schemas.
  """
  def all_schemas do
    %{
      feedback: feedback_schema(),
      feedback_tag: feedback_tag_schema(),
      user: user_schema(),
      issue: issue_schema(),
      solution: solution_schema()
    }
  end

  @doc """
  Generate an Ecto migration string for a given schema.
  This is useful for future database migrations.
  """
  def generate_migration_string(schema_name) do
    schema = Map.get(all_schemas(), schema_name)

    if is_nil(schema) do
      {:error, "Schema not found: #{schema_name}"}
    else
      fields =
        Enum.map(schema, fn {field, type} ->
          "      add :#{field}, :#{type}"
        end)

      # For IDs, always use UUID primary keys
      fields = [
        "      add :id, :uuid, primary_key: true"
        | Enum.filter(fields, fn field -> not String.contains?(field, ":id, ") end)
      ]

      """
      defmodule Rsolv.Repo.Migrations.Create#{String.capitalize(to_string(schema_name))}Table do
        use Ecto.Migration

        def change do
          create table(:#{schema_name}s, primary_key: false) do
      #{Enum.join(fields, "\n")}

            timestamps()
          end

          create index(:#{schema_name}s, [:id])
          # Additional indexes would be defined here
        end
      end
      """
    end
  end

  @doc """
  Generate a CSV header string for a given schema.
  Used for CSV storage before database implementation.
  """
  def generate_csv_header(schema_name) do
    schema = Map.get(all_schemas(), schema_name)

    if is_nil(schema) do
      {:error, "Schema not found: #{schema_name}"}
    else
      fields = Map.keys(schema) |> Enum.map(&to_string/1)
      Enum.join(fields, ",")
    end
  end

  @doc """
  Validate that data matches a given schema.
  Returns :ok if valid, or {:error, reason} if invalid.
  """
  def validate(data, schema_name) do
    schema = Map.get(all_schemas(), schema_name)

    if is_nil(schema) do
      {:error, "Schema not found: #{schema_name}"}
    else
      # Check that all required fields are present
      required_fields = [:id, :created_at]

      missing_fields =
        Enum.filter(required_fields, fn field ->
          is_nil(Map.get(data, field)) && is_nil(Map.get(data, to_string(field)))
        end)

      if length(missing_fields) > 0 do
        {:error, "Missing required fields: #{Enum.join(missing_fields, ", ")}"}
      else
        # Could add additional validation here
        :ok
      end
    end
  end
end
