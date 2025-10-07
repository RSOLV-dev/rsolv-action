defmodule Rsolv.EmailManagementTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]

  alias Rsolv.EmailManagement

  describe "unsubscribes" do
    test "create_unsubscribe/1 with valid data creates an unsubscribe" do
      valid_attrs = %{
        email: unique_email(),
        reason: "User request via unsubscribe page"
      }

      assert {:ok, unsubscribe} = EmailManagement.create_unsubscribe(valid_attrs)
      assert unsubscribe.email == valid_attrs.email
      assert unsubscribe.reason == "User request via unsubscribe page"
    end

    test "create_unsubscribe/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = EmailManagement.create_unsubscribe(%{})
    end

    test "is_unsubscribed?/1 returns true for unsubscribed email" do
      EmailManagement.create_unsubscribe(%{email: "unsub@example.com"})
      assert EmailManagement.is_unsubscribed?("unsub@example.com")
      assert EmailManagement.is_unsubscribed?("UNSUB@EXAMPLE.COM") # case insensitive
    end

    test "is_unsubscribed?/1 returns false for non-unsubscribed email" do
      refute EmailManagement.is_unsubscribed?("notunsubscribed@example.com")
    end

    test "get_unsubscribe_by_email/1 returns the unsubscribe" do
      test_email = unique_email()
      EmailManagement.create_unsubscribe(%{email: test_email})
      unsubscribe = EmailManagement.get_unsubscribe_by_email(test_email)
      assert unsubscribe.email == test_email
    end

    test "list_unsubscribes/0 returns all unsubscribes" do
      {:ok, _older} = EmailManagement.create_unsubscribe(%{email: "older@example.com"})
      {:ok, _newer} = EmailManagement.create_unsubscribe(%{email: "newer@example.com"})

      unsubscribes = EmailManagement.list_unsubscribes()
      assert length(unsubscribes) == 2
      emails = Enum.map(unsubscribes, & &1.email)
      assert "older@example.com" in emails
      assert "newer@example.com" in emails
    end

    test "export_unsubscribes_to_csv/0 returns CSV formatted data" do
      EmailManagement.create_unsubscribe(%{email: "test1@example.com", reason: "No longer interested"})
      EmailManagement.create_unsubscribe(%{email: "test2@example.com"})

      csv = EmailManagement.export_unsubscribes_to_csv()
      assert csv =~ "email,reason,unsubscribed_at"
      assert csv =~ "test1@example.com"
      assert csv =~ "test2@example.com"
      assert csv =~ "No longer interested"
    end
  end

  describe "failed_emails" do
    test "create_failed_email/1 with valid data creates a failed email record" do
      valid_attrs = %{
        to_email: unique_email(),
        subject: "Test Subject",
        template: "welcome",
        error_message: "Connection timeout",
        email_data: %{foo: "bar"}
      }

      assert {:ok, failed_email} = EmailManagement.create_failed_email(valid_attrs)
      assert failed_email.to_email == "test@example.com"
      assert failed_email.subject == "Test Subject"
      assert failed_email.attempts == 1
    end

    test "list_recent_failed_emails/1 returns limited results" do
      for i <- 1..5 do
        EmailManagement.create_failed_email(%{
          to_email: "test#{i}@example.com",
          error_message: "Test error"
        })
      end

      recent = EmailManagement.list_recent_failed_emails(3)
      assert length(recent) == 3
    end

    test "increment_failed_email_attempts/1 increments the attempt count" do
      {:ok, failed_email} = EmailManagement.create_failed_email(%{
        to_email: unique_email(),
        error_message: "Initial error"
      })

      assert failed_email.attempts == 1

      {:ok, updated} = EmailManagement.increment_failed_email_attempts(failed_email)
      assert updated.attempts == 2
    end
  end
end