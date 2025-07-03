# RSOLV Customer Metrics Implementation

This document outlines the implementation approach for collecting and tracking customer metrics during the Early Access Program, with a focus on onboarding stages. This implementation is a simplified CSV-based approach that allows for rapid development while the full database implementation is built.

## Implementation Approach

For the Early Access phase, we'll use a lightweight approach:

1. CSV-based data storage for initial tracking
2. Elixir modules in the Phoenix application for data collection and processing
3. LiveView dashboard for visualizing customer progress
4. GitHub Action hooks for automated metric collection
5. ConvertKit integration for email milestone tracking

This approach allows us to quickly implement tracking without requiring a complex database setup initially. The data can later be migrated to the full PostgreSQL schema defined in `customer-success-tracking-schema.md`.

## CSV Data Structure

### customers.csv
```
id,email,organization,github_username,signup_date,cohort,industry,team_size,status
c1001,john@example.com,Acme Inc,acme-dev,2025-05-01,VIP,SaaS,12,active
c1002,sarah@example.com,TechCorp,techcorp-dev,2025-05-03,VIP,FinTech,25,active
```

### onboarding.csv
```
id,customer_id,welcome_email_sent,account_created,github_action_installed,first_issue_tagged,first_pr_generated,completed_date,days_to_complete,blocker_type,notes
o1001,c1001,true,true,true,true,false,,,,Authentication issues resolved
o1002,c1002,true,true,true,false,false,,,github_config,Needs help with repository permissions
```

### engagement.csv
```
id,customer_id,date,issues_tagged,prs_generated,prs_merged,prs_rejected,support_requests
e1001,c1001,2025-05-02,5,3,2,1,1
e1002,c1001,2025-05-03,7,4,3,1,0
e1003,c1002,2025-05-04,3,0,0,0,2
```

## Elixir Implementation

### Analytics Context Module

```elixir
defmodule RSOLV.Analytics do
  @moduledoc """
  The Analytics context handles customer metrics tracking and reporting.
  """
  
  alias RSOLV.Analytics.CSVStore
  
  # Customer Onboarding Tracking
  
  @doc """
  Tracks a completed onboarding step for a customer.
  """
  def track_onboarding_step(customer_id, step) when step in [
    :welcome_email_sent, 
    :account_created, 
    :github_action_installed, 
    :first_issue_tagged, 
    :first_pr_generated
  ] do
    # Get current onboarding record
    onboarding = get_onboarding(customer_id)
    
    # Update the specific step
    updated = Map.put(onboarding, step, true)
    
    # Calculate completion if all steps are done
    updated = maybe_mark_onboarding_complete(updated)
    
    # Save the updated record
    CSVStore.update_onboarding(updated)
    
    # Trigger completion notification if newly completed
    if updated.completed_date && !onboarding.completed_date do
      trigger_onboarding_completion(customer_id)
    end
    
    {:ok, updated}
  end
  
  @doc """
  Gets the current onboarding status for a customer.
  """
  def get_onboarding(customer_id) do
    case CSVStore.get_onboarding(customer_id) do
      nil -> create_onboarding(customer_id)
      onboarding -> onboarding
    end
  end
  
  @doc """
  Creates a new onboarding record for a customer.
  """
  def create_onboarding(customer_id) do
    onboarding = %{
      id: "o#{System.unique_integer([:positive])}",
      customer_id: customer_id,
      welcome_email_sent: false,
      account_created: false,
      github_action_installed: false,
      first_issue_tagged: false,
      first_pr_generated: false,
      completed_date: nil,
      days_to_complete: nil,
      blocker_type: nil,
      notes: ""
    }
    
    CSVStore.create_onboarding(onboarding)
    onboarding
  end
  
  @doc """
  Records a blocker in the onboarding process.
  """
  def record_onboarding_blocker(customer_id, blocker_type, notes \\ "") do
    onboarding = get_onboarding(customer_id)
    updated = onboarding
              |> Map.put(:blocker_type, blocker_type)
              |> Map.put(:notes, notes)
    
    CSVStore.update_onboarding(updated)
    {:ok, updated}
  end
  
  @doc """
  Gets onboarding completion percentage.
  """
  def get_onboarding_percentage(customer_id) do
    onboarding = get_onboarding(customer_id)
    total_steps = 5 # Total number of onboarding steps
    completed_steps = [
      onboarding.welcome_email_sent,
      onboarding.account_created,
      onboarding.github_action_installed,
      onboarding.first_issue_tagged,
      onboarding.first_pr_generated
    ] |> Enum.count(&(&1 == true))
    
    trunc(completed_steps / total_steps * 100)
  end
  
  # Engagement Tracking
  
  @doc """
  Records daily engagement metrics for a customer.
  """
  def record_engagement(customer_id, metrics) do
    engagement = %{
      id: "e#{System.unique_integer([:positive])}",
      customer_id: customer_id,
      date: Date.utc_today(),
      issues_tagged: metrics[:issues_tagged] || 0,
      prs_generated: metrics[:prs_generated] || 0,
      prs_merged: metrics[:prs_merged] || 0,
      prs_rejected: metrics[:prs_rejected] || 0,
      support_requests: metrics[:support_requests] || 0
    }
    
    CSVStore.create_engagement(engagement)
    {:ok, engagement}
  end
  
  @doc """
  Gets customer engagement summary.
  """
  def get_customer_engagement(customer_id) do
    engagements = CSVStore.list_engagements(customer_id)
    
    %{
      total_issues_tagged: Enum.sum(Enum.map(engagements, & &1.issues_tagged)),
      total_prs_generated: Enum.sum(Enum.map(engagements, & &1.prs_generated)),
      total_prs_merged: Enum.sum(Enum.map(engagements, & &1.prs_merged)),
      success_rate: calculate_success_rate(engagements),
      days_active: length(Enum.uniq(Enum.map(engagements, & &1.date)))
    }
  end
  
  # Reports and Metrics
  
  @doc """
  Gets all metrics for a customer dashboard.
  """
  def get_customer_metrics(customer_id) do
    onboarding = get_onboarding(customer_id)
    engagement = get_customer_engagement(customer_id)
    onboarding_percent = get_onboarding_percentage(customer_id)
    
    %{
      onboarding: onboarding,
      onboarding_percent: onboarding_percent,
      engagement: engagement,
      health_score: calculate_health_score(onboarding, engagement)
    }
  end
  
  @doc """
  Lists customers by onboarding stage for management dashboard.
  """
  def list_customers_by_stage do
    customers = CSVStore.list_customers()
    onboardings = CSVStore.list_all_onboardings()
    
    customers_with_stages = Enum.map(customers, fn customer ->
      onboarding = Enum.find(onboardings, & &1.customer_id == customer.id) || 
                   create_onboarding(customer.id)
      
      stage = determine_stage(onboarding)
      Map.put(customer, :stage, stage)
    end)
    
    # Group by stage
    Enum.group_by(customers_with_stages, & &1.stage)
  end
  
  # Private helpers
  
  defp maybe_mark_onboarding_complete(onboarding) do
    all_complete = onboarding.welcome_email_sent && 
                  onboarding.account_created && 
                  onboarding.github_action_installed && 
                  onboarding.first_issue_tagged && 
                  onboarding.first_pr_generated
                  
    if all_complete && !onboarding.completed_date do
      signup_date = CSVStore.get_customer_signup_date(onboarding.customer_id)
      days_to_complete = Date.diff(Date.utc_today(), signup_date)
      
      onboarding
      |> Map.put(:completed_date, Date.utc_today())
      |> Map.put(:days_to_complete, days_to_complete)
    else
      onboarding
    end
  end
  
  defp calculate_success_rate(engagements) do
    total_generated = Enum.sum(Enum.map(engagements, & &1.prs_generated))
    total_merged = Enum.sum(Enum.map(engagements, & &1.prs_merged))
    
    if total_generated > 0 do
      trunc(total_merged / total_generated * 100)
    else
      0
    end
  end
  
  defp calculate_health_score(onboarding, engagement) do
    # Simple health score calculation (0-100)
    onboarding_score = if onboarding.completed_date, do: 30, else: get_onboarding_percentage(onboarding.customer_id) * 0.3
    
    activity_score = min(engagement.days_active * 5, 30)
    success_score = engagement.success_rate * 0.25
    volume_score = min(engagement.total_prs_generated * 2, 15)
    
    total_score = trunc(onboarding_score + activity_score + success_score + volume_score)
    
    # Determine status based on score
    status = cond do
      total_score >= 85 -> :champion
      total_score >= 70 -> :healthy
      total_score >= 50 -> :needs_attention
      true -> :at_risk
    end
    
    %{
      score: total_score,
      status: status
    }
  end
  
  defp determine_stage(onboarding) do
    cond do
      onboarding.completed_date -> :regular_usage
      onboarding.first_issue_tagged -> :initial_adoption
      onboarding.github_action_installed -> :onboarding
      onboarding.account_created -> :onboarding
      onboarding.welcome_email_sent -> :new_signup
      true -> :new_signup
    end
  end
  
  defp trigger_onboarding_completion(customer_id) do
    # Notify customer success team
    # Send completion email
    # Record milestone
    customer = CSVStore.get_customer(customer_id)
    RSOLV.Mailer.deliver_onboarding_completion(customer)
    Phoenix.PubSub.broadcast(RSOLV.PubSub, "customer:#{customer_id}", {:onboarding_complete, customer_id})
  end
end
```

### CSV Store Module

```elixir
defmodule RSOLV.Analytics.CSVStore do
  @moduledoc """
  Simple CSV-based storage for early access metrics.
  Will be replaced by database storage later.
  """
  
  @customers_path "priv/data/customers.csv"
  @onboarding_path "priv/data/onboarding.csv"
  @engagement_path "priv/data/engagement.csv"
  
  # Customer operations
  
  def list_customers do
    read_csv(@customers_path)
  end
  
  def get_customer(customer_id) do
    list_customers()
    |> Enum.find(&(&1.id == customer_id))
  end
  
  def get_customer_signup_date(customer_id) do
    customer = get_customer(customer_id)
    if customer, do: Date.from_iso8601!(customer.signup_date), else: Date.utc_today()
  end
  
  # Onboarding operations
  
  def list_all_onboardings do
    read_csv(@onboarding_path)
  end
  
  def get_onboarding(customer_id) do
    read_csv(@onboarding_path)
    |> Enum.find(&(&1.customer_id == customer_id))
  end
  
  def create_onboarding(onboarding) do
    append_csv(@onboarding_path, onboarding)
    onboarding
  end
  
  def update_onboarding(onboarding) do
    onboardings = list_all_onboardings()
    
    updated = Enum.map(onboardings, fn record ->
      if record.id == onboarding.id, do: onboarding, else: record
    end)
    
    write_csv(@onboarding_path, updated)
    onboarding
  end
  
  # Engagement operations
  
  def list_engagements(customer_id) do
    read_csv(@engagement_path)
    |> Enum.filter(&(&1.customer_id == customer_id))
  end
  
  def create_engagement(engagement) do
    append_csv(@engagement_path, engagement)
    engagement
  end
  
  # CSV helpers
  
  defp read_csv(path) do
    ensure_file(path)
    
    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> parse_csv()
  end
  
  defp write_csv(path, records) do
    ensure_file(path)
    
    content = records_to_csv(records)
    File.write!(path, content)
  end
  
  defp append_csv(path, record) do
    ensure_file(path)
    
    records = read_csv(path)
    updated = records ++ [record]
    write_csv(path, updated)
  end
  
  defp ensure_file(path) do
    directory = Path.dirname(path)
    
    unless File.exists?(directory) do
      File.mkdir_p!(directory)
    end
    
    unless File.exists?(path) do
      header = path
               |> Path.basename()
               |> String.replace(".csv", "")
               |> csv_header()
               
      File.write!(path, header <> "\n")
    end
  end
  
  defp csv_header("customers"), do: "id,email,organization,github_username,signup_date,cohort,industry,team_size,status"
  defp csv_header("onboarding"), do: "id,customer_id,welcome_email_sent,account_created,github_action_installed,first_issue_tagged,first_pr_generated,completed_date,days_to_complete,blocker_type,notes"
  defp csv_header("engagement"), do: "id,customer_id,date,issues_tagged,prs_generated,prs_merged,prs_rejected,support_requests"
  
  defp parse_csv([header | rows]) do
    headers = header |> String.split(",") |> Enum.map(&String.to_atom/1)
    
    Enum.map(rows, fn row ->
      values = String.split(row, ",")
      Enum.zip(headers, values) |> Map.new()
    end)
  end
  defp parse_csv([]), do: []
  
  defp records_to_csv([]) do
    ""
  end
  defp records_to_csv([first | _] = records) do
    headers = first |> Map.keys() |> Enum.join(",")
    
    rows = Enum.map(records, fn record ->
      record
      |> Map.values()
      |> Enum.map(&to_string/1)
      |> Enum.join(",")
    end)
    
    [headers | rows] |> Enum.join("\n")
  end
  
  defp to_string(nil), do: ""
  defp to_string(true), do: "true"
  defp to_string(false), do: "false"
  defp to_string(value), do: Kernel.to_string(value)
end
```

## LiveView Implementation

The metrics tracking will be integrated into the existing LiveView dashboard:

```elixir
defmodule RSOLVWeb.DashboardLive.OnboardingComponent do
  use RSOLVWeb, :live_component
  alias RSOLV.Analytics
  
  def update(assigns, socket) do
    {:ok,
     socket
     |> assign(assigns)
     |> assign_onboarding_data()}
  end
  
  defp assign_onboarding_data(socket) do
    customer_id = socket.assigns.customer_id
    metrics = Analytics.get_customer_metrics(customer_id)
    
    assign(socket,
      onboarding: metrics.onboarding,
      onboarding_percent: metrics.onboarding_percent
    )
  end
  
  def render(assigns) do
    ~H"""
    <div class="bg-white p-6 rounded-lg shadow-md">
      <h3 class="text-lg font-medium text-gray-900 mb-4">Onboarding Progress</h3>
      
      <div class="mb-6">
        <div class="flex justify-between mb-1">
          <span class="text-sm font-medium text-blue-600">Progress</span>
          <span class="text-sm font-medium text-blue-600"><%= @onboarding_percent %>%</span>
        </div>
        <div class="w-full bg-gray-200 rounded-full h-2.5">
          <div class="bg-blue-600 h-2.5 rounded-full" style={"width: #{@onboarding_percent}%"}></div>
        </div>
      </div>
      
      <div class="space-y-4">
        <div class="flex items-center">
          <div class={"w-5 h-5 rounded-full mr-3 #{if @onboarding.welcome_email_sent, do: "bg-green-500", else: "bg-gray-300"}"}>
            <%= if @onboarding.welcome_email_sent do %>
              <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
              </svg>
            <% end %>
          </div>
          <div>
            <p class="font-medium">Welcome Email</p>
            <p class="text-sm text-gray-500">Initial welcome and account setup</p>
          </div>
        </div>
        
        <div class="flex items-center">
          <div class={"w-5 h-5 rounded-full mr-3 #{if @onboarding.account_created, do: "bg-green-500", else: "bg-gray-300"}"}>
            <%= if @onboarding.account_created do %>
              <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
              </svg>
            <% end %>
          </div>
          <div>
            <p class="font-medium">Account Setup</p>
            <p class="text-sm text-gray-500">Created and configured account</p>
          </div>
        </div>
        
        <div class="flex items-center">
          <div class={"w-5 h-5 rounded-full mr-3 #{if @onboarding.github_action_installed, do: "bg-green-500", else: "bg-gray-300"}"}>
            <%= if @onboarding.github_action_installed do %>
              <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
              </svg>
            <% end %>
          </div>
          <div>
            <p class="font-medium">GitHub Action Installed</p>
            <p class="text-sm text-gray-500">Connected to your repository</p>
          </div>
        </div>
        
        <div class="flex items-center">
          <div class={"w-5 h-5 rounded-full mr-3 #{if @onboarding.first_issue_tagged, do: "bg-green-500", else: "bg-gray-300"}"}>
            <%= if @onboarding.first_issue_tagged do %>
              <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
              </svg>
            <% end %>
          </div>
          <div>
            <p class="font-medium">First Issue Tagged</p>
            <p class="text-sm text-gray-500">Tagged your first issue for resolution</p>
          </div>
        </div>
        
        <div class="flex items-center">
          <div class={"w-5 h-5 rounded-full mr-3 #{if @onboarding.first_pr_generated, do: "bg-green-500", else: "bg-gray-300"}"}>
            <%= if @onboarding.first_pr_generated do %>
              <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
              </svg>
            <% end %>
          </div>
          <div>
            <p class="font-medium">First PR Generated</p>
            <p class="text-sm text-gray-500">RSOLV created a fix for your issue</p>
          </div>
        </div>
      </div>
      
      <%= if @onboarding.completed_date do %>
        <div class="mt-6 p-4 bg-green-50 rounded-md">
          <p class="text-green-800 font-medium">
            Onboarding completed on <%= @onboarding.completed_date %>
          </p>
          <p class="text-sm text-green-700">
            Completed in <%= @onboarding.days_to_complete %> days
          </p>
        </div>
      <% end %>
      
      <%= if @onboarding.blocker_type do %>
        <div class="mt-6 p-4 bg-yellow-50 rounded-md">
          <p class="text-yellow-800 font-medium">
            Action needed: <%= @onboarding.blocker_type %>
          </p>
          <p class="text-sm text-yellow-700">
            <%= @onboarding.notes %>
          </p>
          <button phx-click="contact_support" phx-target={@myself} class="mt-2 text-sm text-blue-600 hover:text-blue-800">
            Get Help
          </button>
        </div>
      <% end %>
    </div>
    """
  end
  
  def handle_event("contact_support", _params, socket) do
    # Trigger support contact flow
    {:noreply, socket}
  end
end
```

## Integration with GitHub Action

To automatically track metrics from the GitHub Action:

```typescript
// In RSOLV-action/src/tracking/metrics.ts

import axios from 'axios';
import { config } from '../config';

interface MetricsPayload {
  customer_id: string;
  event_type: string;
  metadata: Record<string, any>;
}

/**
 * Sends metric events to the RSOLV API for customer tracking
 */
export async function trackEvent(
  customer_id: string, 
  event_type: string,
  metadata: Record<string, any> = {}
): Promise<void> {
  try {
    if (!config.metricsEnabled) {
      return;
    }
    
    const payload: MetricsPayload = {
      customer_id,
      event_type,
      metadata
    };
    
    // During early access, we'll use a simple webhook endpoint
    // Later this will be replaced with a more robust queue system
    await axios.post(`${config.apiBaseUrl}/metrics/track`, payload, {
      headers: {
        'x-api-key': config.apiKey,
        'Content-Type': 'application/json'
      }
    });
  } catch (error) {
    // Log but don't fail the action
    console.error('Failed to send metrics', error);
  }
}

/**
 * Tracks onboarding milestones
 */
export async function trackOnboardingStep(
  customer_id: string,
  step: 'github_action_installed' | 'first_issue_tagged' | 'first_pr_generated'
): Promise<void> {
  return trackEvent(customer_id, `onboarding_step_${step}`, { step });
}

/**
 * Tracks issue resolution metrics
 */
export async function trackIssueResolution(
  customer_id: string,
  issue_url: string,
  pr_url: string | null,
  success: boolean,
  duration_ms: number
): Promise<void> {
  return trackEvent(customer_id, 'issue_resolution', {
    issue_url,
    pr_url,
    success,
    duration_ms
  });
}
```

## Management Dashboard

The management dashboard will provide customer success metrics for the RSOLV team:

```elixir
defmodule RSOLVWeb.Admin.CustomerSuccessLive.Index do
  use RSOLVWeb, :live_view
  alias RSOLV.Analytics
  
  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      :timer.send_interval(60_000, self(), :refresh_data)
    end
    
    {:ok, socket
    |> assign_data()}
  end
  
  defp assign_data(socket) do
    customers_by_stage = Analytics.list_customers_by_stage()
    
    metrics = %{
      total_customers: Enum.count(List.flatten(Map.values(customers_by_stage))),
      completed_onboarding: Enum.count(customers_by_stage[:regular_usage] || []),
      onboarding_completion_rate: calculate_completion_rate(customers_by_stage),
      at_risk_customers: Enum.count(customers_by_stage[:at_risk] || []),
      average_days_to_complete: calculate_average_days(customers_by_stage[:regular_usage] || [])
    }
    
    assign(socket,
      customers_by_stage: customers_by_stage,
      metrics: metrics,
      selected_customer: nil
    )
  end
  
  @impl true
  def handle_event("select_customer", %{"id" => customer_id}, socket) do
    metrics = Analytics.get_customer_metrics(customer_id)
    
    {:noreply, assign(socket, 
      selected_customer: customer_id,
      customer_metrics: metrics
    )}
  end
  
  @impl true
  def handle_info(:refresh_data, socket) do
    {:noreply, assign_data(socket)}
  end
  
  defp calculate_completion_rate(customers_by_stage) do
    completed = Enum.count(customers_by_stage[:regular_usage] || [])
    total = Enum.count(List.flatten(Map.values(customers_by_stage)))
    
    if total > 0, do: trunc(completed / total * 100), else: 0
  end
  
  defp calculate_average_days(customers) do
    if Enum.empty?(customers) do
      0
    else
      customers
      |> Enum.map(fn customer -> 
        onboarding = RSOLV.Analytics.get_onboarding(customer.id)
        onboarding.days_to_complete || 0
      end)
      |> Enum.sum()
      |> Kernel./(Enum.count(customers))
      |> trunc()
    end
  end
end
```

## CSV Export Tool

To enable easy analysis in spreadsheet software, we'll implement a CSV export tool:

```elixir
defmodule RSOLV.Analytics.Exporter do
  @moduledoc """
  Exports customer metrics data as CSV files for analysis.
  """
  
  alias RSOLV.Analytics.CSVStore
  
  @doc """
  Exports all metrics data to a ZIP file containing CSV files.
  """
  def export_all_metrics do
    # Create temporary directory
    tmp_dir = Path.join(System.tmp_dir!(), "rsolv_metrics_#{DateTime.utc_now() |> DateTime.to_unix()}")
    File.mkdir_p!(tmp_dir)
    
    try do
      # Export each data set
      export_customers(tmp_dir)
      export_onboarding(tmp_dir)
      export_engagement(tmp_dir)
      export_combined_metrics(tmp_dir)
      
      # Create ZIP file
      zip_path = Path.join(System.tmp_dir!(), "rsolv_metrics_#{Date.utc_today()}.zip")
      :zip.create(zip_path, files_in_dir(tmp_dir), cwd: tmp_dir)
      
      {:ok, zip_path}
    after
      # Cleanup temp directory
      File.rm_rf(tmp_dir)
    end
  end
  
  defp export_customers(dir) do
    file_path = Path.join(dir, "customers.csv")
    CSVStore.list_customers()
    |> records_to_csv()
    |> write_file(file_path)
  end
  
  defp export_onboarding(dir) do
    file_path = Path.join(dir, "onboarding.csv")
    CSVStore.list_all_onboardings()
    |> records_to_csv()
    |> write_file(file_path)
  end
  
  defp export_engagement(dir) do
    file_path = Path.join(dir, "engagement.csv")
    
    # Get all customer IDs
    customer_ids = CSVStore.list_customers() |> Enum.map(& &1.id)
    
    # Get engagement for all customers
    engagements = Enum.flat_map(customer_ids, &CSVStore.list_engagements/1)
    
    engagements
    |> records_to_csv()
    |> write_file(file_path)
  end
  
  defp export_combined_metrics(dir) do
    file_path = Path.join(dir, "combined_metrics.csv")
    
    # Get all customer IDs
    customers = CSVStore.list_customers()
    
    # Build combined metrics for each customer
    records = Enum.map(customers, fn customer ->
      metrics = RSOLV.Analytics.get_customer_metrics(customer.id)
      onboarding = metrics.onboarding
      engagement = metrics.engagement
      
      %{
        customer_id: customer.id,
        organization: customer.organization, 
        cohort: customer.cohort,
        signup_date: customer.signup_date,
        onboarding_complete: if(onboarding.completed_date, do: "yes", else: "no"),
        onboarding_percent: metrics.onboarding_percent,
        days_to_complete: onboarding.days_to_complete || "",
        blocker_type: onboarding.blocker_type || "",
        total_issues_tagged: engagement.total_issues_tagged,
        total_prs_generated: engagement.total_prs_generated,
        total_prs_merged: engagement.total_prs_merged,
        success_rate: engagement.success_rate,
        days_active: engagement.days_active,
        health_score: metrics.health_score.score,
        health_status: metrics.health_score.status
      }
    end)
    
    records
    |> records_to_csv()
    |> write_file(file_path)
  end
  
  defp records_to_csv([]) do
    ""
  end
  defp records_to_csv([first | _] = records) do
    headers = first |> Map.keys() |> Enum.join(",")
    
    rows = Enum.map(records, fn record ->
      record
      |> Map.values()
      |> Enum.map(&to_string/1)
      |> Enum.join(",")
    end)
    
    [headers | rows] |> Enum.join("\n")
  end
  
  defp to_string(nil), do: ""
  defp to_string(true), do: "true"
  defp to_string(false), do: "false"
  defp to_string(value), do: Kernel.to_string(value)
  
  defp write_file(content, path) do
    File.write!(path, content)
  end
  
  defp files_in_dir(dir) do
    dir
    |> File.ls!()
    |> Enum.map(fn file -> String.to_charlist(file) end)
  end
end
```

## ConvertKit Integration

For tracking email milestones, we'll integrate with ConvertKit:

```elixir
defmodule RSOLV.Notifications.ConvertKit do
  @moduledoc """
  Integration with ConvertKit for customer email tracking.
  """
  
  @doc """
  Adds a tag to a subscriber in ConvertKit.
  Used for tracking email milestones.
  """
  def add_tag(email, tag_name) do
    case get_tag_id(tag_name) do
      {:ok, tag_id} -> tag_subscriber(email, tag_id)
      error -> error
    end
  end
  
  @doc """
  Marks an onboarding milestone in ConvertKit.
  """
  def track_onboarding_milestone(email, milestone) when milestone in [
    :welcome_email_sent,
    :account_created,
    :github_action_installed,
    :first_issue_tagged,
    :first_pr_generated,
    :onboarding_completed
  ] do
    tag_name = "milestone_#{milestone}"
    add_tag(email, tag_name)
  end
  
  # Private API interaction functions
  
  defp get_tag_id(tag_name) do
    # Implementation for ConvertKit API
    # Returns {:ok, tag_id} or {:error, reason}
  end
  
  defp tag_subscriber(email, tag_id) do
    # Implementation for ConvertKit API
    # Returns {:ok, subscriber_id} or {:error, reason}
  end
end
```

## Metrics Integration Points

### GitHub Action Integration

The GitHub Action will call the metrics API to record key events:

1. When installed (`github_action_installed`)
2. When an issue is tagged (`first_issue_tagged`)
3. When a PR is generated (`first_pr_generated`)
4. For ongoing engagement metrics (issues, PRs, etc.)

### Landing Page Integration

The landing page will track initial onboarding steps:

1. When a welcome email is sent (`welcome_email_sent`)
2. When an account is created (`account_created`)

### Email Integration

Email flows will track customer communication:

1. Triggered based on onboarding progress
2. Success milestone celebrations
3. Re-engagement for at-risk customers

## Implementation Timeline

1. **Day 1**: Set up CSV storage structure and core metrics modules
2. **Day 2**: Implement onboarding tracking and API endpoints
3. **Day 3**: Create dashboard visualization components
4. **Day 4**: Integrate with GitHub Action for automatic tracking
5. **Day 5**: Implement export tools and reporting

## Next Steps (Post-Day 10)

1. Migrate from CSV storage to PostgreSQL database
2. Implement advanced analytics with time-series reporting
3. Create prediction models for customer success
4. Build automated intervention workflows for at-risk customers
5. Implement full feedback collection and analysis