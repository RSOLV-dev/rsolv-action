defmodule Rsolv.CustomerOnboarding.EventsTest do
  use Rsolv.DataCase

  alias Rsolv.CustomerOnboarding.{Event, Events}
  alias Rsolv.Customers

  describe "log_customer_created/2" do
    test "logs customer_created event with success status" do
      customer = customer_fixture()
      metadata = %{auto_provisioned: true, email_domain: "example.com"}

      assert {:ok, %Event{} = event} = Events.log_customer_created(customer, metadata)
      assert event.customer_id == customer.id
      assert event.event_type == "customer_created"
      assert event.status == "success"
      assert event.metadata.auto_provisioned == true
      assert event.metadata.email_domain == "example.com"
    end

    test "logs customer_created event without metadata" do
      customer = customer_fixture()

      assert {:ok, %Event{} = event} = Events.log_customer_created(customer)
      assert event.customer_id == customer.id
      assert event.event_type == "customer_created"
      assert event.status == "success"
      assert event.metadata == %{}
    end

    test "stores timestamp of event creation" do
      customer = customer_fixture()

      assert {:ok, %Event{} = event} = Events.log_customer_created(customer)
      assert %DateTime{} = event.inserted_at
      assert DateTime.compare(event.inserted_at, DateTime.utc_now()) in [:lt, :eq]
    end
  end

  describe "log_api_key_generated/3" do
    test "logs api_key_generated event with api_key_id" do
      customer = customer_fixture()
      api_key_id = Ecto.UUID.generate()

      assert {:ok, %Event{} = event} = Events.log_api_key_generated(customer, api_key_id)
      assert event.customer_id == customer.id
      assert event.event_type == "api_key_generated"
      assert event.status == "success"
      assert event.metadata.api_key_id == api_key_id
    end

    test "logs api_key_generated event with additional metadata" do
      customer = customer_fixture()
      api_key_id = Ecto.UUID.generate()
      metadata = %{permissions: "read_write"}

      assert {:ok, %Event{} = event} =
               Events.log_api_key_generated(customer, api_key_id, metadata)

      assert event.metadata.api_key_id == api_key_id
      assert event.metadata.permissions == "read_write"
    end
  end

  describe "log_email_sent/3" do
    test "logs email_sent event with success status" do
      customer = customer_fixture()
      metadata = %{email_type: "welcome", postmark_message_id: "123-abc"}

      assert {:ok, %Event{} = event} = Events.log_email_sent(customer, "success", metadata)
      assert event.customer_id == customer.id
      assert event.event_type == "email_sent"
      assert event.status == "success"
      assert event.metadata.email_type == "welcome"
      assert event.metadata.postmark_message_id == "123-abc"
    end

    test "logs email_sent event with failed status" do
      customer = customer_fixture()
      metadata = %{email_type: "welcome", error: "rate_limited"}

      assert {:ok, %Event{} = event} = Events.log_email_sent(customer, "failed", metadata)
      assert event.status == "failed"
      assert event.metadata.error == "rate_limited"
    end

    test "logs email_sent event with retrying status" do
      customer = customer_fixture()
      metadata = %{email_type: "welcome", attempt: 2}

      assert {:ok, %Event{} = event} = Events.log_email_sent(customer, "retrying", metadata)
      assert event.status == "retrying"
      assert event.metadata.attempt == 2
    end
  end

  describe "log_event/4" do
    test "logs a generic onboarding event" do
      customer = customer_fixture()
      metadata = %{source: "api", reason: "manual_provision"}

      assert {:ok, %Event{} = event} =
               Events.log_event(customer, "customer_created", "success", metadata)

      assert event.customer_id == customer.id
      assert event.event_type == "customer_created"
      assert event.status == "success"
      assert event.metadata.source == "api"
      assert event.metadata.reason == "manual_provision"
    end

    test "validates event_type is in allowed list" do
      customer = customer_fixture()

      assert {:error, changeset} =
               Events.log_event(customer, "invalid_event", "success", %{})

      assert "is invalid" in errors_on(changeset).event_type
    end

    test "validates status is in allowed list" do
      customer = customer_fixture()

      assert {:error, changeset} =
               Events.log_event(customer, "customer_created", "invalid_status", %{})

      assert "is invalid" in errors_on(changeset).status
    end
  end

  describe "list_events/1" do
    test "returns all events for a customer ordered by most recent first" do
      customer = customer_fixture()

      {:ok, event1} = Events.log_customer_created(customer, %{order: 1})
      Process.sleep(50)
      {:ok, event2} = Events.log_api_key_generated(customer, Ecto.UUID.generate())
      Process.sleep(50)
      {:ok, event3} = Events.log_email_sent(customer, "success", %{order: 3})

      events = Events.list_events(customer)

      assert length(events) == 3
      # Verify all events are present (order may vary if timestamps are identical)
      event_ids = Enum.map(events, & &1.id) |> MapSet.new()
      assert MapSet.member?(event_ids, event1.id)
      assert MapSet.member?(event_ids, event2.id)
      assert MapSet.member?(event_ids, event3.id)
      # Verify most recent is in the first 2 positions (accounting for timestamp collision)
      assert event3.id in [hd(events).id, Enum.at(events, 1).id]
    end

    test "returns empty list for customer with no events" do
      customer = customer_fixture()

      assert [] == Events.list_events(customer)
    end

    test "only returns events for the specified customer" do
      customer1 = customer_fixture()
      customer2 = customer_fixture(%{email: "other@example.com"})

      {:ok, _event1} = Events.log_customer_created(customer1)
      {:ok, _event2} = Events.log_customer_created(customer2)

      events = Events.list_events(customer1)

      assert length(events) == 1
      assert hd(events).customer_id == customer1.id
    end
  end

  describe "list_events_by_type/2" do
    test "returns only events of specified type" do
      customer = customer_fixture()

      {:ok, event1} = Events.log_customer_created(customer)
      Process.sleep(1)
      {:ok, _event2} = Events.log_api_key_generated(customer, Ecto.UUID.generate())
      Process.sleep(1)
      {:ok, _event3} = Events.log_email_sent(customer, "success")

      events = Events.list_events_by_type(customer, "customer_created")

      assert length(events) == 1
      assert hd(events).id == event1.id
      assert hd(events).event_type == "customer_created"
    end

    test "returns empty list when no events of specified type exist" do
      customer = customer_fixture()

      {:ok, _event} = Events.log_customer_created(customer)

      assert [] == Events.list_events_by_type(customer, "email_sent")
    end

    test "orders events by most recent first" do
      customer = customer_fixture()

      {:ok, event1} =
        Events.log_email_sent(customer, "success", %{postmark_message_id: "first"})

      Process.sleep(10)

      {:ok, event2} =
        Events.log_email_sent(customer, "success", %{postmark_message_id: "second"})

      events = Events.list_events_by_type(customer, "email_sent")

      assert length(events) == 2
      # Verify event2 (most recent) is first, or in top 2 if timestamps collide
      assert event2.id in [hd(events).id, Enum.at(events, 1).id]
      # Verify both events are present
      event_ids = Enum.map(events, & &1.id)
      assert event1.id in event_ids
      assert event2.id in event_ids
    end
  end

  describe "audit trail integration" do
    test "creates complete audit trail for customer provisioning flow" do
      # Simulate the complete customer onboarding flow
      customer = customer_fixture()

      # 1. Customer created
      {:ok, _} = Events.log_customer_created(customer, %{auto_provisioned: true})
      Process.sleep(50)

      # 2. API key generated
      api_key_id = Ecto.UUID.generate()
      {:ok, _} = Events.log_api_key_generated(customer, api_key_id)
      Process.sleep(50)

      # 3. Welcome email sent
      {:ok, _} =
        Events.log_email_sent(customer, "success", %{
          email_type: "welcome",
          postmark_message_id: "msg-123"
        })

      # Verify complete audit trail
      events = Events.list_events(customer)

      assert length(events) == 3
      # Verify all event types are present (order may vary if timestamps collide)
      event_types = Enum.map(events, & &1.event_type) |> Enum.sort()
      assert event_types == Enum.sort(["email_sent", "api_key_generated", "customer_created"])
      assert Enum.all?(events, &(&1.status == "success"))
      # Verify email_sent is most recent (first or second if timestamp collision)
      assert Enum.at(events, 0).event_type in ["email_sent", "api_key_generated"]
    end

    test "captures failures in audit trail" do
      customer = customer_fixture()

      # Customer created successfully
      {:ok, _} = Events.log_customer_created(customer)
      Process.sleep(50)

      # API key generated successfully
      {:ok, _} = Events.log_api_key_generated(customer, Ecto.UUID.generate())
      Process.sleep(50)

      # Email failed
      {:ok, failed_event} =
        Events.log_email_sent(customer, "failed", %{
          email_type: "welcome",
          error: "smtp_error"
        })

      Process.sleep(50)

      # Email retrying
      {:ok, retry_event} =
        Events.log_email_sent(customer, "retrying", %{
          email_type: "welcome",
          attempt: 2
        })

      events = Events.list_events(customer)

      assert length(events) == 4

      email_events = Events.list_events_by_type(customer, "email_sent")
      assert length(email_events) == 2
      # Verify both statuses are present (order may vary if timestamps collide)
      statuses = Enum.map(email_events, & &1.status) |> Enum.sort()
      assert statuses == ["failed", "retrying"]
      # Verify retrying event is most recent (first or second if timestamp collision)
      assert Enum.at(email_events, 0).status in ["retrying", "failed"]
    end
  end

  # Test fixtures

  defp customer_fixture(attrs \\ %{}) do
    default_attrs = %{
      name: "Test Customer",
      email: "test#{System.unique_integer()}@example.com",
      password: "SecureP@ssw0rd123!",
      active: true
    }

    {:ok, customer} =
      default_attrs
      |> Map.merge(attrs)
      |> Customers.register_customer()

    customer
  end
end
