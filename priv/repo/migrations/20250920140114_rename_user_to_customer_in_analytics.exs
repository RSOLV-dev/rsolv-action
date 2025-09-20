defmodule Rsolv.Repo.Migrations.RenameUserToCustomerInAnalytics do
  use Ecto.Migration

  def change do
    # Rename user_id to customer_id in analytics_page_views
    rename table(:analytics_page_views), :user_id, to: :customer_id

    # Drop the old foreign key constraint if it exists
    drop_if_exists constraint(:analytics_page_views, "analytics_page_views_user_id_fkey")

    # Add new foreign key constraint to customers table
    alter table(:analytics_page_views) do
      modify :customer_id, references(:customers, on_delete: :delete_all)
    end

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