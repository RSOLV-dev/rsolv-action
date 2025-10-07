defmodule Rsolv.AnalyticsTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]
  
  alias Rsolv.Analytics
  alias Rsolv.Analytics.{PageView, Event, Conversion}
  alias RsolvWeb.Services.Analytics, as: WebAnalytics
  
  describe "Analytics service" do
    test "tracks page views with UTM parameters" do
      utm_params = %{
        utm_source: "twitter",
        utm_medium: "social",
        utm_campaign: "security_awareness"
      }
      
      # Track a page view using WebAnalytics
      WebAnalytics.track_page_view("/blog/security-patterns", "https://twitter.com", utm_params)
      
      # Verify it was tracked in the database
      Process.sleep(100) # Give async task time to complete
      events = Analytics.list_events_by_type("page_view")
      assert length(events) >= 1
    end
    
    test "tracks conversion events" do
      # Track a conversion using WebAnalytics
      test_email = unique_email()
      WebAnalytics.track_conversion("early_access_signup", %{email: test_email})

      # Verify it was tracked in the database
      Process.sleep(100) # Give async task time to complete
      events = Analytics.list_events_by_type("conversion")
      assert length(events) >= 1

      # Verify it's persisted to analytics_events table as conversion type
      # Give it a moment for the async task to complete
      Process.sleep(100)

      conversion_events = Analytics.list_events_by_type("conversion")
      assert length(conversion_events) >= 1

      conversion = List.first(conversion_events)
      assert conversion.event_type == "conversion"
      assert conversion.metadata["email"] == test_email
      assert conversion.metadata["conversion_type"] == "early_access_signup"
    end
    
    test "tracks custom events" do
      # Track a custom event using WebAnalytics
      WebAnalytics.track("button_click", %{button_id: "cta_signup", page: "/pricing"})
      
      # Verify it was tracked in the database
      Process.sleep(100) # Give async task time to complete
      events = Analytics.list_events_by_type("button_click")
      assert length(events) >= 1
    end
    
    test "provides event tracking functionality" do
      # Track some sample data using WebAnalytics
      WebAnalytics.track_page_view("/", "https://google.com")
      WebAnalytics.track_page_view("/blog", "https://google.com")
      WebAnalytics.track("search", %{query: "security"})
      WebAnalytics.track_conversion("newsletter_signup", %{})
      
      # Give async tasks time to complete
      Process.sleep(100)
      
      # Verify events were created
      all_events = Analytics.list_events()
      assert length(all_events) >= 4
      
      # Check we can query by visitor
      visitor_events = Analytics.list_events() |> Enum.group_by(& &1.visitor_id)
      assert map_size(visitor_events) >= 1
    end
    
    test "tracks events with metadata" do
      # Track events with various metadata
      WebAnalytics.track_page_view("/test", "https://example.com", %{"user_id" => "12345"})
      WebAnalytics.track_page_view("/test", nil, %{})
      WebAnalytics.track_page_view("/test", "", %{"campaign" => "test"})
      
      # Give async tasks time to complete
      Process.sleep(100)
      
      # Verify events were created
      events = Analytics.list_events_by_type("page_view")
      assert length(events) >= 3
      
      # Check metadata was preserved
      event_with_user = Enum.find(events, fn e -> e.metadata["user_id"] == "12345" end)
      assert event_with_user != nil
    end
    
    test "handles event queries by date range" do
      # Create a test event
      {:ok, event} = Analytics.create_event(%{
        event_type: "test_dated_event",
        visitor_id: "test_visitor_456",
        metadata: %{test: true}
      })
      
      # Query events within date range
      start_date = Date.utc_today() |> Date.add(-7)
      end_date = Date.utc_today()
      
      # Use the actual available query functions
      all_events = Analytics.list_events()
      recent_events = Enum.filter(all_events, fn e -> 
        event_date = NaiveDateTime.to_date(e.inserted_at)
        Date.compare(event_date, start_date) != :lt
      end)
      
      assert length(recent_events) >= 1
      assert event.id in Enum.map(recent_events, & &1.id)
    end
  end
  
  describe "PageView schema" do
    test "validates required fields" do
      changeset = PageView.changeset(%PageView{}, %{})
      refute changeset.valid?
      assert %{path: ["can't be blank"]} = errors_on(changeset)
    end
    
    test "validates field lengths" do
      long_string = String.duplicate("a", 3000)
      
      changeset = PageView.changeset(%PageView{}, %{
        path: long_string,
        utm_source: long_string
      })
      
      refute changeset.valid?
      assert %{path: ["should be at most 2048 character(s)"]} = errors_on(changeset)
      assert %{utm_source: ["should be at most 255 character(s)"]} = errors_on(changeset)
    end
    
    test "accepts valid page view data" do
      attrs = %{
        path: "/blog/security-patterns",
        user_ip: "192.168.1.0",
        utm_source: "twitter",
        utm_medium: "social",
        utm_campaign: "security_awareness",
        session_id: "session_123",
        user_agent: "Mozilla/5.0"
      }
      
      changeset = PageView.changeset(%PageView{}, attrs)
      assert changeset.valid?
    end
  end
  
  describe "Event schema" do
    test "validates required fields" do
      changeset = Event.changeset(%Event{}, %{})
      refute changeset.valid?
      assert %{event_type: ["can't be blank"]} = errors_on(changeset)
    end
    
    test "accepts valid event data" do
      attrs = %{
        event_type: "button_click",
        visitor_id: "visitor_123",
        metadata: %{button_id: "cta_signup"},
        session_id: "session_456"
      }
      
      changeset = Event.changeset(%Event{}, attrs)
      assert changeset.valid?
    end
  end
  
  describe "Conversion schema" do
    test "validates required fields" do
      changeset = Conversion.changeset(%Conversion{}, %{})
      refute changeset.valid?
      assert %{event_name: ["can't be blank"]} = errors_on(changeset)
    end
    
    test "validates monetary value" do
      changeset = Conversion.changeset(%Conversion{}, %{
        event_name: "purchase",
        value: -10.00
      })
      
      refute changeset.valid?
      assert %{value: ["must be greater than or equal to 0"]} = errors_on(changeset)
    end
    
    test "accepts valid conversion data" do
      attrs = %{
        event_name: "early_access_signup",
        properties: %{email: unique_email()},
        session_id: "session_789",
        value: Decimal.new("29.99")
      }
      
      changeset = Conversion.changeset(%Conversion{}, attrs)
      assert changeset.valid?
    end
  end
end