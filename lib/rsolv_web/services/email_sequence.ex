defmodule RsolvWeb.Services.EmailSequence do
  @moduledoc """
  Service for managing email sequences and automation using Oban.
  Handles scheduling and tracking of email sequences.
  """
  require Logger
  alias Rsolv.EmailService
  alias RsolvWeb.Services.ConvertKit
  alias Rsolv.Workers.EmailWorker

  @doc """
  Sequence definitions with timing
  """
  def sequences do
    %{
      onboarding: [
        %{id: :welcome, days: 0, template: "welcome"},
        %{id: :getting_started, days: 1, template: "getting_started"},
        %{id: :setup_verification, days: 2, template: "setup_verification"},
        %{id: :first_issue, days: 3, template: "first_issue"},
        %{id: :feature_deep_dive, days: 5, template: "feature_deep_dive"},
        %{id: :feedback_request, days: 7, template: "feedback_request"},
        %{id: :success_checkin, days: 14, template: "success_checkin"}
      ],
      early_access_onboarding: [
        %{id: :early_access_welcome, days: 0, template: "early_access_welcome"},
        %{id: :early_access_guide, days: 1, template: "early_access_guide"},
        %{id: :setup_verification, days: 3, template: "setup_verification"},
        %{id: :feature_deep_dive, days: 5, template: "feature_deep_dive"},
        %{id: :feedback_request, days: 7, template: "feedback_request"},
        %{id: :success_checkin, days: 14, template: "success_checkin"}
      ],
      re_engagement: [
        %{id: :re_engage_1, days: 0, template: "re_engage_1"},
        %{id: :re_engage_2, days: 3, template: "re_engage_2"},
        %{id: :re_engage_3, days: 7, template: "re_engage_3"}
      ],
      expiring_trial: [
        %{id: :trial_reminder, days: 0, template: "trial_reminder"},
        %{id: :trial_ending, days: 3, template: "trial_ending"},
        %{id: :trial_expired, days: 7, template: "trial_expired"}
      ]
    }
  end

  @doc """
  Start the onboarding sequence for a new subscriber.
  This should be triggered upon successful signup.
  """
  def start_onboarding_sequence(email, first_name \\ nil) do
    Logger.info("Starting onboarding sequence", 
      metadata: %{
        email: email,
        first_name: first_name
      }
    )
    
    # Send the welcome email immediately
    EmailService.send_welcome_email(email, first_name)
    
    # Add sequence tag in ConvertKit
    tag_for_sequence(email, :onboarding)
    
    # Schedule the remaining emails using Oban
    EmailWorker.schedule_sequence(email, first_name, :onboarding)
    
    {:ok, %{status: "started", sequence: :onboarding}}
  end
  
  @doc """
  Start the early access onboarding sequence for a new early access subscriber.
  This should be triggered upon successful early access signup.
  """
  def start_early_access_onboarding_sequence(email, first_name \\ nil) do
    timestamp = DateTime.utc_now() |> DateTime.to_string()
    
    Logger.info("[EMAIL SEQUENCE] Starting early access onboarding sequence", 
      email: email,
      first_name: first_name,
      timestamp: timestamp
    )
    
    # Send the early access welcome email immediately
    Logger.info("[EMAIL SEQUENCE] About to call EmailService.send_early_access_welcome_email",
      email: email,
      first_name: first_name,
      timestamp: timestamp
    )
    
    result = EmailService.send_early_access_welcome_email(email, first_name)
    
    Logger.info("[EMAIL SEQUENCE] EmailService.send_early_access_welcome_email returned",
      result: inspect(result),
      timestamp: timestamp
    )
    
    # Add sequence tag in ConvertKit
    tag_for_sequence(email, :early_access_onboarding)
    
    # Schedule the remaining emails using Oban
    EmailWorker.schedule_sequence(email, first_name, :early_access_onboarding)
    
    {:ok, %{status: "started", sequence: :early_access_onboarding}}
  end

  @doc """
  Start the re-engagement sequence for an inactive user.
  This should be triggered when a user hasn't used the service for a while.
  """
  def start_re_engagement_sequence(email, first_name \\ nil, inactive_days \\ 30) do
    Logger.info("Starting re-engagement sequence", 
      metadata: %{
        email: email, 
        first_name: first_name,
        inactive_days: inactive_days
      }
    )
    
    # Add sequence tag in ConvertKit
    tag_for_sequence(email, :re_engagement)
    
    # Schedule the emails using Oban
    EmailWorker.schedule_sequence(email, first_name, :re_engagement)
    
    {:ok, %{status: "started", sequence: :re_engagement}}
  end

  @doc """
  Start the expiring trial sequence for a user whose trial is about to end.
  This should be triggered a few days before the trial expiration.
  """
  def start_expiring_trial_sequence(email, first_name \\ nil, days_remaining \\ 7) do
    Logger.info("Starting expiring trial sequence", 
      metadata: %{
        email: email, 
        first_name: first_name,
        days_remaining: days_remaining
      }
    )
    
    # Add sequence tag in ConvertKit
    tag_for_sequence(email, :expiring_trial)
    
    # Schedule the emails using Oban
    EmailWorker.schedule_sequence(email, first_name, :expiring_trial)
    
    {:ok, %{status: "started", sequence: :expiring_trial}}
  end

  # Add appropriate tags in ConvertKit based on the sequence
  defp tag_for_sequence(email, sequence_name) do
    # Get ConvertKit config
    config = Application.get_env(:rsolv, :convertkit)
    
    # Define sequence-specific tags
    # These tag IDs would need to be created in ConvertKit
    sequence_tags = %{
      onboarding: config[:tag_onboarding] || "7700607",
      early_access_onboarding: config[:early_access_tag_id] || "7700607",
      re_engagement: config[:tag_re_engagement] || "7700608",
      expiring_trial: config[:tag_expiring_trial] || "7700609"
    }
    
    # Get the tag for this sequence
    tag_id = Map.get(sequence_tags, sequence_name)
    
    if tag_id do
      # Add the tag
      ConvertKit.add_tag_to_subscriber(email, tag_id)
    else
      Logger.error("No tag ID configured for sequence", 
        metadata: %{
          sequence: sequence_name,
          email: email
        }
      )
    end
  end
end