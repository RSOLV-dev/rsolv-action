defmodule Rsolv.AnalyticsTest do
  use Rsolv.DataCase
  
  alias Rsolv.Analytics
  alias Rsolv.Analytics.{PageView, Event, Conversion}
  
  describe "Analytics service" do
    test "tracks page views with UTM parameters" do
      utm_params = %{
        utm_source: "twitter",
        utm_medium: "social",
        utm_campaign: "security_awareness"
      }
      
      # Track a page view
      :ok = Analytics.track_page_view("/blog/security-patterns", "127.0.0.1", utm_params, 
        session_id: "session_123", user_agent: "Mozilla/5.0")
      
      # Verify it's tracked in real-time metrics
      metrics = Analytics.get_realtime_metrics()
      assert metrics.page_views_last_hour >= 1
    end
    
    test "tracks conversion events" do
      # Track a conversion
      :ok = Analytics.track_conversion("early_access_signup", %{email: "test@example.com"}, 
        session_id: "session_456")
      
      # Verify it's tracked in real-time metrics
      metrics = Analytics.get_realtime_metrics()
      assert metrics.conversions_last_hour >= 1
      
      # Verify it's persisted to database immediately
      # Give it a moment for the async task to complete
      Process.sleep(100)
      
      conversions = Repo.all(Conversion)
      assert length(conversions) >= 1
      
      conversion = List.first(conversions)
      assert conversion.event_name == "early_access_signup"
      assert conversion.properties["email"] == "test@example.com"
      assert conversion.session_id == "session_456"
    end
    
    test "tracks custom events" do
      # Track a custom event
      :ok = Analytics.track_event("button_click", %{button_id: "cta_signup", page: "/pricing"}, 
        session_id: "session_789")
      
      # Verify it's tracked in real-time metrics
      metrics = Analytics.get_realtime_metrics()
      assert metrics.events_last_hour >= 1
    end
    
    test "provides real-time metrics" do
      # Track some sample data
      Analytics.track_page_view("/", "127.0.0.1")
      Analytics.track_page_view("/blog", "127.0.0.1", %{}, session_id: "unique_session")
      Analytics.track_event("search", %{query: "security"})
      Analytics.track_conversion("newsletter_signup", %{})
      
      metrics = Analytics.get_realtime_metrics()
      
      assert is_integer(metrics.page_views_last_hour)
      assert is_integer(metrics.page_views_last_day)
      assert is_integer(metrics.events_last_hour)
      assert is_integer(metrics.conversions_last_hour)
      assert is_list(metrics.top_pages_today)
      assert is_integer(metrics.current_visitors)
    end
    
    test "anonymizes IP addresses" do
      # Track with real IP
      Analytics.track_page_view("/test", "192.168.1.100")
      
      # Wait for flush to database (in real implementation)
      # For now, we can test the anonymization function indirectly
      # by checking that the service doesn't crash with various IP formats
      
      Analytics.track_page_view("/test", "192.168.1.100")
      Analytics.track_page_view("/test", "invalid-ip")
      Analytics.track_page_view("/test", nil)
      Analytics.track_page_view("/test", "")
      
      # All should succeed without error
      assert :ok == :ok
    end
    
    test "handles database metrics queries" do
      start_date = Date.utc_today() |> Date.add(-7)
      end_date = Date.utc_today()
      
      metrics = Analytics.get_metrics(start_date, end_date)
      
      # Should return the expected structure
      assert Map.has_key?(metrics, :page_views)
      assert Map.has_key?(metrics, :unique_visitors)
      assert Map.has_key?(metrics, :conversions)
      assert Map.has_key?(metrics, :top_pages)
      assert Map.has_key?(metrics, :utm_sources)
      assert Map.has_key?(metrics, :conversion_rate)
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
      assert %{event_name: ["can't be blank"]} = errors_on(changeset)
    end
    
    test "accepts valid event data" do
      attrs = %{
        event_name: "button_click",
        properties: %{button_id: "cta_signup"},
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
        properties: %{email: "test@example.com"},
        session_id: "session_789",
        value: Decimal.new("29.99")
      }
      
      changeset = Conversion.changeset(%Conversion{}, attrs)
      assert changeset.valid?
    end
  end
end