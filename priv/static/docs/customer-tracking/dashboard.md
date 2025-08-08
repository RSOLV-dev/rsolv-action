# RSOLV Customer Success Dashboard

This document outlines the customer success dashboard implementation for the RSOLV Early Access Program. The dashboard will help track customer onboarding progress, engagement metrics, and overall health scores.

## Dashboard Overview

The dashboard will consist of several key components:

1. **Onboarding Progress Tracker**: Visual representation of customer onboarding stages
2. **Engagement Metrics**: Charts and graphs showing usage patterns
3. **Customer Health Scores**: Indicators of overall customer health
4. **At-Risk Customer Alerts**: Highlighting customers needing attention
5. **Cohort Analysis**: Comparing metrics across different customer cohorts

## Implementation Approach

For the MVP implementation during the Early Access Program, we'll use:

1. A LiveView dashboard in the RSOLV-landing application
2. CSV-based data storage (to be replaced with PostgreSQL later)
3. Basic charting with LiveView and TailwindCSS
4. Daily data exports for manual analysis

## Dashboard Mockups

### Main Dashboard View

```
+------------------------------------------------------+
|                                                      |
|  RSOLV Customer Success Dashboard         [Export]   |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  SUMMARY                                   [Refresh] |
|                                                      |
|  Total Customers: 12       Onboarding Rate: 75%      |
|  Active Today: 8           Success Rate: 82%         |
|  At Risk: 2                Avg Time to Value: 3.5d   |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  ONBOARDING PROGRESS                                 |
|                                                      |
|  [███████████████████████████████]  75% Complete     |
|                                                      |
|  ● Welcome Email     9/12  (75%)                     |
|  ● Account Setup     9/12  (75%)                     |
|  ● GitHub Action     8/12  (67%)                     |
|  ● First Issue       7/12  (58%)                     |
|  ● First PR          6/12  (50%)                     |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  CUSTOMER HEALTH                                     |
|                                                      |
|  Champions    [██████]       3 (25%)                 |
|  Healthy      [████████████] 6 (50%)                 |
|  At Risk      [████]         2 (17%)                 |
|  Inactive     [█]            1 (8%)                  |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  CUSTOMER LIST                           [Filter ▼]  |
|                                                      |
|  Name             Status    Progress   Last Active   |
|  ---------------- --------- ---------- ------------- |
|  Acme Inc. ⚠️      At Risk   60%        3 days ago   |
|  TechCorp         Healthy   80%        Today         |
|  DevSolutions     Champion  100%       Today         |
|  ...                                                 |
|                                                      |
+------------------------------------------------------+
```

### Individual Customer View

```
+------------------------------------------------------+
|                                                      |
|  ← Back to Dashboard    |    Acme Inc.      ⚠️       |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  CUSTOMER DETAILS                                    |
|                                                      |
|  Contact: john@acme.com            Team Size: 15     |
|  GitHub: acme-dev                  Cohort: VIP       |
|  Signup Date: May 3, 2025          Status: At Risk   |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  ONBOARDING PROGRESS                                 |
|                                                      |
|  [██████████████████]  60% Complete                  |
|                                                      |
|  ✓ Welcome Email     Completed on May 3              |
|  ✓ Account Setup     Completed on May 3              |
|  ✓ GitHub Action     Completed on May 4              |
|  ✓ First Issue       Tagged 5 issues                 |
|  ✗ First PR          Blocked: GitHub permissions     |
|                                                      |
|  BLOCKER: Customer needs help with repository        |
|  permissions to allow PR creation                    |
|                                                      |
|  [Contact Customer]                                  |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  ENGAGEMENT METRICS                                  |
|                                                      |
|  Activity Last 7 Days                                |
|                                                      |
|  [Chart: Daily activity over time]                   |
|                                                      |
|  Issues Tagged: 5     PRs Generated: 0               |
|  PRs Merged: 0        Support Requests: 2            |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  HEALTH SCORE: 45/100  (At Risk)                     |
|                                                      |
|  [████████████████████████████████]                  |
|                                                      |
|  Components:                                         |
|  - Activity Level: 20/30                             |
|  - PR Success Rate: 0/25                             |
|  - Feature Adoption: 15/20                           |
|  - Support Satisfaction: 10/15                       |
|  - NPS Score: N/A                                    |
|                                                      |
|  TREND: ↓ Declining (Last 7 days)                    |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  ACTIVITY TIMELINE                                   |
|                                                      |
|  May 7 - Support request: "How do I create PRs?"     |
|  May 6 - Tagged 2 issues                             |
|  May 5 - Tagged 3 issues                             |
|  May 4 - Installed GitHub Action                     |
|  May 3 - Created account                             |
|  May 3 - Welcome email sent                          |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  RECOMMENDED ACTIONS                                 |
|                                                      |
|  ► Schedule technical call to resolve GitHub issue    |
|  ► Share documentation on repository permissions      |
|  ► Send follow-up email about PR generation           |
|                                                      |
|  [Take Action]                                       |
|                                                      |
+------------------------------------------------------+
```

## LiveView Implementation

The dashboard will be implemented as a LiveView component in the RSOLV-landing Phoenix application:

```elixir
# Admin dashboard for customer success tracking
defmodule RSOLVWeb.Admin.CustomerSuccessLive do
  use RSOLVWeb, :live_view
  alias RSOLV.Analytics
  
  @refresh_interval 60_000 # 1 minute refresh
  
  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      :timer.send_interval(@refresh_interval, self(), :refresh)
    end
    
    {:ok, assign_dashboard_data(socket)}
  end
  
  @impl true
  def handle_params(%{"id" => id}, _uri, socket) do
    {:noreply, assign_customer_details(socket, id)}
  end
  
  @impl true 
  def handle_params(_, _uri, socket) do
    {:noreply, assign_dashboard_data(socket)}
  end
  
  @impl true
  def handle_event("view_customer", %{"id" => id}, socket) do
    {:noreply, push_patch(socket, to: Routes.admin_customer_success_path(socket, :show, id))}
  end
  
  @impl true
  def handle_event("contact_customer", %{"id" => id}, socket) do
    # Logic to trigger customer contact
    {:noreply, socket}
  end
  
  @impl true
  def handle_event("export_data", _params, socket) do
    case Analytics.Exporter.export_all_metrics() do
      {:ok, path} ->
        {:noreply, 
         socket
         |> put_flash(:info, "Data exported successfully")
         |> push_event("download", %{path: path})}
      
      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Export failed: #{reason}")}
    end
  end
  
  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, assign_dashboard_data(socket)}
  end
  
  defp assign_dashboard_data(socket) do
    assign(socket,
      customers: Analytics.list_customers(),
      summary: get_summary_metrics(),
      onboarding_progress: get_onboarding_progress(),
      health_distribution: get_health_distribution(),
      page_title: "Customer Success Dashboard",
      selected_customer: nil
    )
  end
  
  defp assign_customer_details(socket, customer_id) do
    case Analytics.get_customer(customer_id) do
      nil ->
        socket
        |> put_flash(:error, "Customer not found")
        |> push_patch(to: Routes.admin_customer_success_path(socket, :index))
      
      customer ->
        metrics = Analytics.get_customer_metrics(customer_id)
        engagement = Analytics.get_customer_engagement(customer_id)
        timeline = Analytics.get_customer_timeline(customer_id)
        
        socket
        |> assign(:selected_customer, customer)
        |> assign(:customer_metrics, metrics)
        |> assign(:customer_engagement, engagement)
        |> assign(:activity_timeline, timeline)
        |> assign(:recommended_actions, get_recommended_actions(customer, metrics))
        |> assign(:page_title, "#{customer.organization} - Customer Details")
    end
  end
  
  # Helper functions for dashboard metrics
  
  defp get_summary_metrics do
    customers = Analytics.list_customers()
    total = length(customers)
    
    active_today = Enum.count(customers, fn c -> 
      Analytics.was_active_today?(c.id)
    end)
    
    at_risk = Enum.count(customers, fn c ->
      metrics = Analytics.get_customer_metrics(c.id)
      metrics.health_score.status == :at_risk
    end)
    
    onboarding_complete = Enum.count(customers, fn c ->
      onboarding = Analytics.get_onboarding(c.id)
      onboarding.completed_date != nil
    end)
    
    onboarding_rate = if total > 0, do: trunc(onboarding_complete / total * 100), else: 0
    
    success_rate = Analytics.get_overall_success_rate()
    
    avg_time = Analytics.get_average_time_to_value()
    
    %{
      total_customers: total,
      active_today: active_today,
      at_risk: at_risk,
      onboarding_rate: onboarding_rate,
      success_rate: success_rate,
      avg_time_to_value: avg_time
    }
  end
  
  defp get_onboarding_progress do
    customers = Analytics.list_customers()
    total = length(customers)
    
    welcome_email = count_step_completion(customers, :welcome_email_sent)
    account_setup = count_step_completion(customers, :account_created)
    github_action = count_step_completion(customers, :github_action_installed)
    first_issue = count_step_completion(customers, :first_issue_tagged)
    first_pr = count_step_completion(customers, :first_pr_generated)
    
    total_steps = welcome_email + account_setup + github_action + first_issue + first_pr
    max_steps = total * 5
    
    overall_percentage = if max_steps > 0, do: trunc(total_steps / max_steps * 100), else: 0
    
    %{
      overall_percentage: overall_percentage,
      steps: [
        %{name: "Welcome Email", completed: welcome_email, total: total, percentage: percentage(welcome_email, total)},
        %{name: "Account Setup", completed: account_setup, total: total, percentage: percentage(account_setup, total)},
        %{name: "GitHub Action", completed: github_action, total: total, percentage: percentage(github_action, total)},
        %{name: "First Issue", completed: first_issue, total: total, percentage: percentage(first_issue, total)},
        %{name: "First PR", completed: first_pr, total: total, percentage: percentage(first_pr, total)}
      ]
    }
  end
  
  defp get_health_distribution do
    customers = Analytics.list_customers()
    total = length(customers)
    
    champions = count_health_status(customers, :champion)
    healthy = count_health_status(customers, :healthy)
    needs_attention = count_health_status(customers, :needs_attention)
    at_risk = count_health_status(customers, :at_risk)
    
    %{
      champions: %{count: champions, percentage: percentage(champions, total)},
      healthy: %{count: healthy, percentage: percentage(healthy, total)},
      needs_attention: %{count: needs_attention, percentage: percentage(needs_attention, total)},
      at_risk: %{count: at_risk, percentage: percentage(at_risk, total)}
    }
  end
  
  defp get_recommended_actions(customer, metrics) do
    # Logic to generate recommended actions based on customer status
    # This would be expanded in the full implementation
    cond do
      metrics.health_score.status == :at_risk ->
        ["Schedule technical call", "Send follow-up email", "Share documentation"]
      
      metrics.health_score.status == :needs_attention ->
        ["Check in via email", "Offer additional resources"]
      
      metrics.health_score.status == :healthy ->
        ["Regular check-in", "Suggest advanced features"]
      
      metrics.health_score.status == :champion ->
        ["Request testimonial", "Discuss expansion opportunities"]
      
      true ->
        []
    end
  end
  
  # Helper utility functions
  
  defp count_step_completion(customers, step) do
    Enum.count(customers, fn c ->
      onboarding = Analytics.get_onboarding(c.id)
      Map.get(onboarding, step) == true
    end)
  end
  
  defp count_health_status(customers, status) do
    Enum.count(customers, fn c ->
      metrics = Analytics.get_customer_metrics(c.id)
      metrics.health_score.status == status
    end)
  end
  
  defp percentage(part, total) do
    if total > 0, do: trunc(part / total * 100), else: 0
  end
end
```

## Dashboard Templates

The LiveView templates will include:

1. `index.html.heex` - Main dashboard view
2. `show.html.heex` - Individual customer view
3. `_summary_component.html.heex` - Summary metrics component
4. `_onboarding_progress.html.heex` - Onboarding progress visualization
5. `_health_distribution.html.heex` - Health score distribution 
6. `_customer_list.html.heex` - List of customers with key metrics

## Data Visualization Components

For the MVP, we'll implement basic visualization components using TailwindCSS:

1. Progress bars for onboarding stages
2. Bar charts for health score distribution 
3. Trend indicators for customer health
4. Activity timelines for customer engagement

## CSV to Dashboard Integration

The dashboard will read data from the CSV files using the `CSVStore` module:

```elixir
# In lib/rsolv/analytics/csv_store.ex

defmodule RSOLV.Analytics.CSVStore do
  @moduledoc """
  Simple CSV-based storage for early access metrics.
  Will be replaced by database storage later.
  """
  
  @data_dir "priv/data"
  @customers_path Path.join(@data_dir, "customers.csv")
  @onboarding_path Path.join(@data_dir, "onboarding.csv")
  @engagement_path Path.join(@data_dir, "engagement.csv")
  
  # Implementation of CSV reading functions...
end
```

## Data Export Feature

The dashboard will include an export feature that generates CSV files for offline analysis:

```elixir
# In lib/rsolv/analytics/exporter.ex

defmodule RSOLV.Analytics.Exporter do
  @moduledoc """
  Exports customer metrics data for analysis.
  """
  
  # Implementation of export functions...
end
```

## Future Improvements (Post Day-10)

1. **Database Migration**: Move from CSV storage to PostgreSQL
2. **Advanced Analytics**: Predictive analytics for customer health
3. **Real-time Updates**: WebSocket updates when metrics change
4. **Custom Reports**: Allow filtering and custom report generation
5. **Automated Alerts**: Email notifications for at-risk customers
6. **Integration with CRM**: Connect with customer relationship tools
7. **Mobile Optimization**: Responsive design for mobile devices

## Implementation Plan

1. **Day 1**: Set up basic CSV structure and data collection
2. **Day 2**: Implement core dashboard layout and metrics display
3. **Day 3**: Create customer detail view and health score visualization
4. **Day 4**: Build export functionality and data refresh
5. **Day 5**: Test with sample data and refine UI/UX

## Conclusion

This simplified customer success dashboard will provide essential visibility into early access customer onboarding and engagement. The CSV-based approach allows for rapid implementation during the Early Access Program, with a clear path to a more robust database-backed solution post-Day 10.

The dashboard will enable the RSOLV team to:

1. Track overall onboarding progress
2. Identify at-risk customers quickly
3. Monitor engagement metrics 
4. Prioritize customer success activities
5. Make data-driven decisions about the early access program

This implementation balances immediate needs with future scalability, providing essential customer success tracking for the Day 8 deliverable.