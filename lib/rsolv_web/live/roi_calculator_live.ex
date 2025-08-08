defmodule RsolvWeb.RoiCalculatorLive do
  use RsolvWeb, :live_component

  @impl true
  def mount(socket) do
    require Logger
    Logger.info("ROI Calculator LiveComponent mounting...")
    
    # Initialize with default values
    socket = assign_defaults(socket)
    
    Logger.info("ROI Calculator LiveComponent mounted")
    {:ok, socket}
  end

  @impl true
  def handle_event("update_calculator", params, socket) do
    # Update the calculator with new values
    monthly_issues = String.to_integer(params["monthly_issues"] || "50")
    hours_per_fix = case params["hours_per_fix"] || "3" do
      str when is_binary(str) ->
        if String.contains?(str, ".") do
          String.to_float(str)
        else
          String.to_integer(str) * 1.0
        end
      val -> val * 1.0
    end
    hourly_rate = String.to_integer(params["hourly_rate"] || "150")
    fix_deployment_rate = String.to_integer(params["fix_deployment_rate"] || "80")

    socket = calculate_roi(socket, monthly_issues, hours_per_fix, hourly_rate, fix_deployment_rate)
    
    {:noreply, socket}
  end

  defp assign_defaults(socket) do
    socket
    |> assign(:monthly_issues, 50)
    |> assign(:hours_per_fix, 3.0)
    |> assign(:hourly_rate, 150)
    |> assign(:fix_deployment_rate, 80)
    |> calculate_roi(50, 3.0, 150, 80)
  end

  defp calculate_roi(socket, monthly_issues, hours_per_fix, hourly_rate, fix_deployment_rate) do
    # Calculate actual fixes deployed
    fixes_deployed = trunc(monthly_issues * (fix_deployment_rate / 100))
    
    # Value calculations
    time_saved_hours = fixes_deployed * hours_per_fix
    time_saved_cost = trunc(time_saved_hours * hourly_rate)
    
    # Add security value (30% premium for security fixes)
    security_value_multiplier = 1.3
    total_value_created = trunc(time_saved_cost * security_value_multiplier)
    
    # Pricing calculations
    pay_as_you_go_cost = fixes_deployed * 15
    teams_plan_cost = 499
    
    # Teams plan calculation with rollover
    teams_fixes_included = 60
    teams_additional_fixes = max(0, fixes_deployed - teams_fixes_included)
    teams_total_cost = teams_plan_cost + (teams_additional_fixes * 8)
    teams_rollover = max(0, teams_fixes_included - fixes_deployed)
    
    # Determine best plan
    {recommended_plan, recommended_cost} = cond do
      fixes_deployed > 120 -> {"Enterprise", 0}  # Custom pricing
      fixes_deployed > 33 && teams_total_cost < pay_as_you_go_cost -> {"Teams Plan", teams_total_cost}
      true -> {"Pay As You Go", pay_as_you_go_cost}
    end
    
    # Teams plan savings
    teams_monthly_savings = if fixes_deployed > 33 && pay_as_you_go_cost > teams_plan_cost do
      pay_as_you_go_cost - teams_total_cost
    else
      0
    end
    teams_annual_savings = teams_monthly_savings * 12
    
    # ROI calculation
    roi = if recommended_cost > 0 do
      trunc(((total_value_created - recommended_cost) / recommended_cost) * 100)
    else
      0
    end
    
    # Time to value (payback period in months)
    payback_months = if total_value_created > recommended_cost && recommended_cost > 0 do
      Float.round(recommended_cost / (total_value_created - recommended_cost), 1)
    else
      0.0
    end
    
    socket
    |> assign(:monthly_issues, monthly_issues)
    |> assign(:hours_per_fix, hours_per_fix)
    |> assign(:hourly_rate, hourly_rate)
    |> assign(:fix_deployment_rate, fix_deployment_rate)
    |> assign(:fixes_deployed, fixes_deployed)
    |> assign(:time_saved_hours, time_saved_hours)
    |> assign(:time_saved_cost, time_saved_cost)
    |> assign(:total_value_created, total_value_created)
    |> assign(:pay_as_you_go_cost, pay_as_you_go_cost)
    |> assign(:teams_plan_cost, teams_plan_cost)
    |> assign(:teams_total_cost, teams_total_cost)
    |> assign(:teams_rollover, teams_rollover)
    |> assign(:teams_monthly_savings, teams_monthly_savings)
    |> assign(:teams_annual_savings, teams_annual_savings)
    |> assign(:recommended_plan, recommended_plan)
    |> assign(:recommended_cost, recommended_cost)
    |> assign(:roi, roi)
    |> assign(:payback_months, payback_months)
    |> assign(:show_teams_savings, fixes_deployed > 33 && teams_monthly_savings > 0)
    |> assign(:show_enterprise, fixes_deployed > 120)
  end

  # Helper function to format currency
  def format_currency(amount) when amount == 0, do: "$0"
  def format_currency(amount) do
    Number.Currency.number_to_currency(amount)
  end
end