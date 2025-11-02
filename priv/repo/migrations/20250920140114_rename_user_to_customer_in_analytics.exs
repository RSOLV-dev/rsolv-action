defmodule Rsolv.Repo.Migrations.RenameUserToCustomerInAnalytics do
  use Ecto.Migration

  def up do
    # Only migrate analytics_page_views if it exists
    if table_exists?(:analytics_page_views) do
      # Rename user_id to customer_id in analytics_page_views
      rename table(:analytics_page_views), :user_id, to: :customer_id

      # Drop the old foreign key constraint if it exists
      drop_if_exists constraint(:analytics_page_views, "analytics_page_views_user_id_fkey")

      # Add new foreign key constraint to customers table
      alter table(:analytics_page_views) do
        modify :customer_id, references(:customers, on_delete: :delete_all)
      end
    end

    # Only migrate analytics_conversions if it exists
    if table_exists?(:analytics_conversions) do
      # Rename user_id to customer_id in analytics_conversions
      rename table(:analytics_conversions), :user_id, to: :customer_id

      # Drop the old foreign key constraint if it exists
      drop_if_exists constraint(:analytics_conversions, "analytics_conversions_user_id_fkey")

      # Add new foreign key constraint to customers table
      alter table(:analytics_conversions) do
        modify :customer_id, references(:customers, on_delete: :delete_all)
      end
    end
  end

  def down do
    # Only reverse analytics_conversions if it exists
    if table_exists?(:analytics_conversions) do
      # Reverse changes for analytics_conversions
      # Drop the customer foreign key constraint
      drop_if_exists constraint(:analytics_conversions, "analytics_conversions_customer_id_fkey")

      # Rename customer_id back to user_id
      rename table(:analytics_conversions), :customer_id, to: :user_id

      # Add back the user foreign key constraint
      alter table(:analytics_conversions) do
        modify :user_id, references(:users, on_delete: :delete_all)
      end
    end

    # Only reverse analytics_page_views if it exists
    if table_exists?(:analytics_page_views) do
      # Reverse changes for analytics_page_views
      # Drop the customer foreign key constraint
      drop_if_exists constraint(:analytics_page_views, "analytics_page_views_customer_id_fkey")

      # Rename customer_id back to user_id
      rename table(:analytics_page_views), :customer_id, to: :user_id

      # Add back the user foreign key constraint
      alter table(:analytics_page_views) do
        modify :user_id, references(:users, on_delete: :delete_all)
      end
    end
  end

  defp table_exists?(table_name) do
    query = """
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public'
      AND table_name = '#{table_name}'
    )
    """
    {:ok, %{rows: [[exists]]}} = Ecto.Adapters.SQL.query(Rsolv.Repo, query)
    exists
  end
end