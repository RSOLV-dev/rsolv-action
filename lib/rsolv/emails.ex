defmodule Rsolv.Emails do
  @moduledoc """
  Module for composing emails to be sent by the Mailer.
  """
  import Bamboo.Email
  require Logger
  alias RsolvWeb.EmailsHTML

  @doc """
  Creates a welcome email for new subscribers.
  """
  def welcome_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Welcome to RSOLV - Let's fix your first issue in 10 minutes",
      "welcome"
    )
  end

  @doc """
  Creates an early access welcome email for new early access subscribers.
  """
  def early_access_welcome_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Welcome to RSOLV Early Access Program",
      "early-access"
    )
  end

  @doc """
  Creates a getting started email for subscribers.
  """
  def getting_started_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Getting Started with RSOLV - Feature Overview",
      "getting-started"
    )
  end

  @doc """
  Creates a setup verification email for subscribers.
  """
  def setup_verification_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Verify Your RSOLV Setup - Need Any Help?",
      "setup-verification"
    )
  end

  @doc """
  Creates a first issue email for subscribers.
  """
  def first_issue_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Submit Your First Issue with RSOLV",
      "first-issue"
    )
  end

  @doc """
  Creates a feature deep dive email for subscribers.
  """
  def feature_deep_dive_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Advanced RSOLV Features You Might Have Missed",
      "feature-deep-dive"
    )
  end

  @doc """
  Creates a feedback request email for subscribers.
  """
  def feedback_request_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "How's Your Experience with RSOLV?",
      "feedback-request"
    )
  end

  @doc """
  Creates a success checkin email for subscribers.
  """
  def success_checkin_email(to_email, first_name \\ nil, usage_stats \\ nil) do
    # Get default usage stats if none provided
    stats =
      usage_stats ||
        %{
          issues_fixed: 0,
          prs_created: 0,
          time_saved: "0 hours"
        }

    # Create email with usage stats
    create_email(
      to_email,
      first_name,
      "Your RSOLV Success Report",
      "success-checkin",
      stats
    )
  end

  @doc """
  Creates a contact form notification email for admins.
  """
  def contact_form_notification(contact_data) do
    subject = "🏢 New Contact Form Submission: #{contact_data.email}"

    # Get email configuration
    config =
      Application.get_env(:rsolv, :email_config, %{
        sender_email: "support@rsolv.dev",
        sender_name: "RSOLV Team",
        reply_to: "support@rsolv.dev"
      })

    sender_email = Map.get(config, :sender_email, "support@rsolv.dev")
    sender_name = Map.get(config, :sender_name, "RSOLV Team")

    # Get admin emails
    admin_emails = get_admin_emails()

    # Build email
    new_email()
    |> to(admin_emails)
    |> from({sender_name, sender_email})
    |> subject(subject)
    |> html_body(contact_form_notification_html(contact_data))
    |> text_body(contact_form_notification_text(contact_data))
    |> put_header("X-Postmark-Tag", "contact-form")
    |> put_header("X-Priority", "1")
    |> put_header("Message-ID", generate_message_id())
    |> put_private(:tag, "contact-form")
  end

  @doc """
  Creates an early access guide email for subscribers.
  """
  def early_access_guide_email(to_email, first_name \\ nil) do
    create_email(
      to_email,
      first_name,
      "Your RSOLV Early Access Guide",
      "early-access-guide"
    )
  end

  @doc """
  Creates an admin notification email for new signups.
  """
  def admin_signup_notification(signup_data) do
    subject = "🎉 New RSOLV Signup: #{signup_data.email}"

    # Get email configuration
    config =
      Application.get_env(:rsolv, :email_config, %{
        sender_email: "support@rsolv.dev",
        sender_name: "RSOLV Team",
        reply_to: "support@rsolv.dev"
      })

    sender_email = Map.get(config, :sender_email, "support@rsolv.dev")
    sender_name = Map.get(config, :sender_name, "RSOLV Team")

    # Get admin emails and filter for @rsolv.dev during Postmark trial
    admin_emails = get_admin_emails()

    # Build email
    new_email()
    |> to(admin_emails)
    |> from({sender_name, sender_email})
    |> subject(subject)
    |> html_body(admin_signup_notification_html(signup_data))
    |> text_body(admin_signup_notification_text(signup_data))
    |> put_header("X-Postmark-Tag", "admin-notification")
    |> put_header("X-Priority", "1")
    |> put_header("Message-ID", generate_message_id())
    |> put_private(:tag, "admin-notification")
  end

  # Helper function to create standard email structure
  defp create_email(to_email, first_name, subject, tag, usage_stats \\ %{}) do
    # Get email configuration
    config =
      Application.get_env(:rsolv, :email_config, %{
        sender_email: "support@rsolv.dev",
        sender_name: "RSOLV Team",
        reply_to: "support@rsolv.dev"
      })

    sender_email = Map.get(config, :sender_email, "support@rsolv.dev")
    sender_name = Map.get(config, :sender_name, "RSOLV Team")

    # Format first name (fallback to "there" if not provided)
    name = if first_name && String.trim(first_name) != "", do: first_name, else: "there"

    # Get HTML and text bodies based on template tag
    {html, text} =
      case tag do
        "welcome" ->
          {welcome_html_body(name, to_email), welcome_text_body(name, to_email)}

        "early-access" ->
          {early_access_welcome_html_body(name, to_email),
           early_access_welcome_text_body(name, to_email)}

        "getting-started" ->
          {getting_started_html_body(name, to_email), getting_started_text_body(name, to_email)}

        "setup-verification" ->
          html_body = EmailsHTML.render_setup_verification(%{first_name: name, email: to_email})
          {html_body, setup_verification_text_body(name, to_email)}

        "first-issue" ->
          html_body = EmailsHTML.render_first_issue(%{first_name: name, email: to_email})
          {html_body, first_issue_text_body(name, to_email)}

        "feature-deep-dive" ->
          html_body = EmailsHTML.render_feature_deep_dive(%{first_name: name, email: to_email})
          {html_body, feature_deep_dive_text_body(name, to_email)}

        "feedback-request" ->
          html_body = EmailsHTML.render_feedback_request(%{first_name: name, email: to_email})
          {html_body, feedback_request_text_body(name, to_email)}

        "success-checkin" ->
          html_body =
            EmailsHTML.render_success_checkin(%{
              first_name: name,
              email: to_email,
              usage_stats: usage_stats
            })

          {html_body, success_checkin_text_body(name, to_email)}

        "early-access-guide" ->
          html_body = EmailsHTML.render_early_access_guide(%{first_name: name, email: to_email})
          {html_body, early_access_guide_text_body(name, to_email)}

        # Fallback to welcome template
        _ ->
          {welcome_html_body(name, to_email), welcome_text_body(name, to_email)}
      end

    # Build email
    new_email()
    |> to(to_email)
    |> from({sender_name, sender_email})
    |> subject(subject)
    |> html_body(html)
    |> text_body(text)
    |> put_header("X-Postmark-Tag", tag)
    |> put_private(:tag, tag)
  end

  # Email templates - HTML versions

  defp welcome_html_body(first_name, email) do
    """
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h1 style="color: #2C3E50; margin-bottom: 20px;">Welcome to RSOLV!</h1>

      <p>Hi #{first_name},</p>

      <p>Thanks for trying RSOLV! You're just a few minutes away from automating away your backlog.</p>

      <p>Here's how to get started:</p>

      <ol>
        <li>Install our GitHub Action (copy & paste the code below)</li>
        <li>Set up your repository secrets</li>
        <li>Tag your first issues with "rsolv:automate"</li>
      </ol>

      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <pre style="margin: 0; overflow-x: auto; white-space: pre-wrap; font-family: monospace;">name: RSOLV AutoFix
    on:
      issues:
        types: [opened, edited, labeled]

    jobs:
      autofix:
        runs-on: ubuntu-latest
        if: contains(github.event.issue.labels.*.name, 'rsolv:automate')
        steps:
          - uses: RSOLV-dev/rsolv-action@v1
            with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              rsolv-api-key: ${{ secrets.RSOLV_API_KEY }}</pre>
      </div>

      <p>Need help? Contact us at <a href="mailto:support@rsolv.dev">support@rsolv.dev</a> and we'll personally assist you.</p>

      <p>Your first 10 fixes are free! After that, you only pay $15 per fix that gets deployed - no credit card required to start.</p>

      <p>Best,<br>The RSOLV Team</p>

      <div class="footer" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 0.9em; color: #666;">
        <p>
          P.S. Here's a <a href="https://rsolv.dev/docs/getting-started">2-minute video walkthrough</a> if you prefer.
        </p>
        <p>
          RSOLV, Inc. • support@rsolv.dev • © 2025
        </p>
        <p>
          <a href="https://rsolv.dev/unsubscribe?email=#{email}">Unsubscribe</a> from these emails.
        </p>
      </div>
    </div>
    """
  end

  defp getting_started_html_body(first_name, email) do
    """
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h1 style="color: #2C3E50; margin-bottom: 20px;">Getting Started with RSOLV</h1>

      <p>Hi #{first_name},</p>

      <p>We hope you're enjoying RSOLV so far. Here's a quick overview of what you can do:</p>

      <ul>
        <li>🔒 <strong>Security-First Approach</strong> - Every fix is analyzed for security vulnerabilities</li>
        <li>🚀 <strong>AI-Powered Solutions</strong> - Generate PRs for issues with a single "rsolv:automate" tag</li>
        <li>💰 <strong>Success-Based Billing</strong> - Only pay $15 when fixes are merged (after 10 free fixes)</li>
      </ul>

      <p>For detailed instructions, check out our <a href="https://rsolv.dev/docs/getting-started">documentation</a>.</p>

      <p>If you have any questions, just reply to this email.</p>

      <p>Best,<br>The RSOLV Team</p>

      <div class="footer" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 0.9em; color: #666;">
        <p>
          RSOLV, Inc. • support@rsolv.dev • © 2025
        </p>
        <p>
          <a href="https://rsolv.dev/unsubscribe?email=#{email}">Unsubscribe</a> from these emails.
        </p>
      </div>
    </div>
    """
  end

  # Email templates - Text versions

  defp welcome_text_body(first_name, email) do
    """
    Welcome to RSOLV!

    Hi #{first_name},

    Thanks for trying RSOLV! You're just a few minutes away from automating away your backlog.

    Here's how to get started:

    1. Install our GitHub Action (check the HTML version for the code snippet)
    2. Set up your repository secrets
    3. Tag your first issues with "rsolv:automate"

    Need help? Contact us at support@rsolv.dev and we'll personally assist you.

    Your first 10 fixes are free! After that, you only pay $15 per fix that gets deployed - no credit card required to start.

    Best,
    The RSOLV Team

    P.S. Check out our 2-minute video walkthrough at https://rsolv.dev/docs/getting-started

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  defp getting_started_text_body(first_name, email) do
    """
    Getting Started with RSOLV

    Hi #{first_name},

    We hope you're enjoying RSOLV so far. Here's a quick overview of what you can do:

    * Security-First Approach - Every fix is analyzed for security vulnerabilities
    * AI-Powered Solutions - Generate PRs for issues with a single "rsolv:automate" tag
    * Success-Based Billing - Only pay $15 when fixes are merged (after 10 free fixes)

    For detailed instructions, check out our documentation at https://rsolv.dev/docs/getting-started

    If you have any questions, just reply to this email.

    Best,
    The RSOLV Team

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  # Early Access Welcome Email Templates

  defp early_access_welcome_html_body(first_name, email) do
    """
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h1 style="color: #2C3E50; margin-bottom: 20px;">Welcome to RSOLV Early Access Program!</h1>

      <p>Hi #{first_name},</p>

      <p>Thank you for joining our Early Access Program! You're now part of an exclusive group getting first access to RSOLV.</p>

      <p>Here's what you need to know:</p>

      <ul>
        <li>You have full access to all current features</li>
        <li>Your feedback is incredibly valuable to us during this phase</li>
        <li>You'll receive priority support via email</li>
      </ul>

      <p>To get started with RSOLV:</p>

      <ol>
        <li><strong>Your API key will be sent in a follow-up email within 24 hours</strong></li>
        <li>Once you receive your API key, install our GitHub Action (code below)</li>
        <li>Set up your repository secrets with your API key</li>
        <li>Tag your first issues with "rsolv:automate"</li>
      </ol>

      <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 5px; margin: 15px 0;">
        <strong>⏳ API Key Coming Soon:</strong> We'll send your personal API key within 24 hours. Look for an email with subject "Your RSOLV API Key".
      </div>

      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <pre style="margin: 0; overflow-x: auto; white-space: pre-wrap; font-family: monospace;">name: RSOLV AutoFix
    on:
      issues:
        types: [opened, edited, labeled]

    jobs:
      autofix:
        runs-on: ubuntu-latest
        if: contains(github.event.issue.labels.*.name, 'rsolv:automate')
        steps:
          - uses: RSOLV-dev/rsolv-action@v1
            with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              rsolv-api-key: ${{ secrets.RSOLV_API_KEY }}</pre>
      </div>

      <p>Need help? As an Early Access member, you have priority support - contact us at <a href="mailto:support@rsolv.dev">support@rsolv.dev</a> and we'll personally assist you.</p>

      <p>Your trial includes unlimited automated fixes during the Early Access period.</p>

      <div style="margin-top: 30px; padding: 15px; border: 1px solid #e0e0e0; border-radius: 5px; background-color: #f9f9f9;">
        <h3 style="margin-top: 0; color: #2C3E50;">Early Access Program Benefits</h3>
        <ul>
          <li>Unlimited usage during Early Access</li>
          <li>Priority support and feature requests</li>
          <li>Exclusive pricing when we launch</li>
          <li>Direct access to our development team</li>
        </ul>
      </div>

      <p>Best,<br>The RSOLV Team</p>

      <div class="footer" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 0.9em; color: #666;">
        <p>
          You're receiving this email because you joined the RSOLV Early Access Program.
          <br>
          If you have any questions, simply reply to this email.
        </p>
        <p>
          RSOLV, Inc. • support@rsolv.dev • © 2025
        </p>
        <p>
          <a href="https://rsolv.dev/unsubscribe?email=#{email}">Unsubscribe</a> from these emails.
        </p>
      </div>
    </div>
    """
  end

  defp early_access_welcome_text_body(first_name, email) do
    """
    Welcome to RSOLV Early Access Program!

    Hi #{first_name},

    Thank you for joining our Early Access Program! You're now part of an exclusive group getting first access to RSOLV.

    Here's what you need to know:
    - You have full access to all current features
    - Your feedback is incredibly valuable to us during this phase
    - You'll receive priority support via email

    To get started with RSOLV:
    1. Your API key will be sent in a follow-up email within 24 hours
    2. Once you receive your API key, install our GitHub Action
    3. Set up your repository secrets with your API key
    4. Tag your first issues with "AUTOFIX"

    ⏳ API KEY COMING SOON: We'll send your personal API key within 24 hours. Look for an email with subject "Your RSOLV API Key".

    Need help? As an Early Access member, you have priority support - contact us at support@rsolv.dev and we'll personally assist you.

    Your trial includes unlimited automated fixes during the Early Access period.

    EARLY ACCESS PROGRAM BENEFITS:
    * Unlimited usage during Early Access
    * Priority support and feature requests
    * Exclusive pricing when we launch
    * Direct access to our development team

    Best,
    The RSOLV Team

    ---
    You're receiving this email because you joined the RSOLV Early Access Program.
    If you have any questions, simply reply to this email.

    RSOLV, Inc. • support@rsolv.dev

    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  # Text body function for early access guide
  defp early_access_guide_text_body(first_name, email) do
    """
    Your RSOLV Early Access Guide

    Hi #{first_name},

    Thank you for joining our early access program! This guide will help you get the most out of RSOLV's security-first approach to automated issue resolution.

    How RSOLV Works:
    1. Security Analysis - RSOLV scans for over 80 security patterns across JavaScript, TypeScript, Python, Ruby, and Java
    2. AI-Powered Solution - Our AI generates secure fixes with comprehensive documentation
    3. Pull Request Creation - A well-documented PR is created with the fix and security assessment
    4. You Deploy, You Pay - Review and merge when ready. Only charged $15 when deployed (after 10 free fixes)

    How to Write Effective Issues:
    - Be Specific: Clearly describe what's broken and how it should work
    - Include Context: Mention which components, files, or functions are involved
    - Show Steps: List step-by-step instructions to reproduce the issue
    - Use the Right Label: Always use the "rsolv:automate" label to trigger RSOLV

    Early Access Features:
    - Security-First Approach: Every fix is analyzed for vulnerabilities
    - Code Context Understanding: AI analyzes your entire repository
    - Success-Based Billing: Only pay when fixes are merged
    - Educational Insights: Each PR includes security explanations

    Setup Instructions:
    Add this GitHub Action workflow to your repository:

    name: RSOLV Automation
    on:
      issues:
        types: [labeled]
    jobs:
      resolve:
        if: contains(github.event.issue.labels.*.name, 'rsolv:automate')
        runs-on: ubuntu-latest
        steps:
          - uses: rsolv-dev/rsolv-action@v1
            with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              rsolv-api-key: ${{ secrets.RSOLV_API_KEY }}

    For detailed setup instructions, visit: https://rsolv.dev/docs/getting-started

    Early Access Note: As an early access user, you may occasionally encounter limitations. Your feedback is invaluable—please share any issues by replying to this email.

    Ready to start? Visit https://rsolv.dev

    Best regards,
    The RSOLV Team

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  # Text body functions for new templates
  defp setup_verification_text_body(first_name, email) do
    """
    Let's Verify Your RSOLV Setup

    Hi #{first_name},

    It's been a few days since you signed up for RSOLV. We want to make sure you're all set up and ready to automate your issue resolution!

    Quick Setup Checklist:
    [ ] Added the GitHub Action workflow to your repository
    [ ] Set up your RSOLV_API_KEY as a repository secret
    [ ] Tagged your first issue with "rsolv:automate"
    [ ] Reviewed and merged your first automated PR

    Need Help with Setup?
    If you haven't completed setup yet, visit: https://rsolv.dev/docs/getting-started

    Remember: Your first 10 fixes are completely free! No credit card required. After that, you only pay $15 per fix that gets deployed.

    Common Questions:
    - Where do I get my API key? Check your welcome email or visit your dashboard
    - Can I use RSOLV on private repos? Yes! RSOLV works with both public and private repositories
    - What types of issues can RSOLV fix? Bug fixes, security vulnerabilities, performance issues, and more
    - How secure is it? We analyze every fix for security vulnerabilities before creating PRs

    Pro Tip: Start with a simple issue first - something like "Fix typo in README" or "Update deprecated function calls".

    Ready to get started? Tag an issue with "rsolv:automate" and watch the magic happen!

    If you're stuck or have questions, just reply to this email.

    Best regards,
    The RSOLV Team

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  defp first_issue_text_body(first_name, email) do
    """
    Ready to Submit Your First Issue?

    Hi #{first_name},

    You've been set up with RSOLV for a few days now. It's time to experience the magic of automated issue resolution!

    🚀 Your First Automated Fix Awaits
    Choose any issue in your repository and tag it with "rsolv:automate" to watch RSOLV create a comprehensive fix with a pull request.

    Perfect First Issues to Try:
    - Documentation fixes: "Fix typo in README.md"
    - Code cleanup: "Remove unused imports in UserService.js"
    - Dependency updates: "Update lodash to latest version"
    - Bug fixes: "Fix null pointer exception in login function"
    - Security issues: "Remove hardcoded API key from config"

    📝 Example Issue Template

    Title: Fix deprecated function usage in payment processor

    Description:
    The payment processor in `src/services/PaymentService.js` is using deprecated function `calculateTax()` which was replaced with `computeTax()` in version 2.0.

    **Expected behavior:** Use the new `computeTax()` function
    **Current behavior:** Uses deprecated `calculateTax()` function
    **File location:** `src/services/PaymentService.js` lines 45-67

    Labels: rsolv:automate

    💡 Pro Tips for Better Fixes
    - Be specific about which files and functions are affected
    - Include error messages or stack traces when available
    - Describe the expected behavior clearly
    - Start with smaller issues to get familiar with RSOLV's capabilities

    How RSOLV Works:
    Once you tag an issue with "rsolv:automate":
    1. Security Analysis: RSOLV scans your codebase for security vulnerabilities
    2. Context Understanding: AI analyzes your entire repository structure
    3. Solution Generation: Creates a comprehensive fix with documentation
    4. Pull Request: Submits a well-documented PR for your review

    Remember: Your first 10 fixes are completely free! After that, you only pay $15 per fix that gets successfully deployed.

    Need help getting started? Just reply to this email and I'll personally assist you with your first automated fix.

    Setup Guide: https://rsolv.dev/docs/getting-started
    Writing Better Issues: https://rsolv.dev/docs/writing-effective-issues

    Best regards,
    Dylan & The RSOLV Team

    P.S. Once you see your first RSOLV-generated PR, you'll understand why teams are saving hours every week with automated issue resolution!

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  defp feature_deep_dive_text_body(first_name, email) do
    """
    Unlock the Full Power of RSOLV

    Hi #{first_name},

    You've been using RSOLV for a few days now. Here are some advanced features and techniques:

    1. Writing Better Issues for Better Fixes:
       - Include error messages: Copy the full stack trace
       - Specify the file/function: "Fix pagination in UserList.js"
       - Describe expected behavior: "Should show 10 users per page"
       - Add context: "This broke after upgrading to React 18"

    2. Security-First Fixes:
       RSOLV automatically scans for:
       - SQL injection vulnerabilities
       - Cross-site scripting (XSS) risks
       - Authentication/authorization issues
       - Insecure dependencies
       - Hardcoded secrets or API keys

    3. Batch Processing:
       Tag multiple issues with "rsolv:automate" and RSOLV creates separate PRs for each.

    4. Customizing RSOLV Behavior:
       Add these tags to your issues:
       - [performance] - Optimize for speed
       - [security] - Extra security focus
       - [minimal] - Smallest possible change
       - [refactor] - Clean up while fixing

    Coming Soon:
    - Support for more languages (Go, Rust, PHP)
    - Custom fix preferences per repository
    - Team collaboration features
    - Integration with more platforms

    Have a feature request? Just reply to this email!

    View advanced documentation: https://rsolv.dev/docs/advanced

    Best regards,
    The RSOLV Team

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  defp feedback_request_text_body(first_name, email) do
    """
    Quick Check-In: How's RSOLV Working for You?

    Hi #{first_name},

    You've been using RSOLV for a week now, and we'd love to hear about your experience!

    How likely are you to recommend RSOLV to a colleague?
    Rate us from 1-10: https://rsolv.dev/feedback?email=#{email}

    Three Quick Questions:
    1. What's been your favorite RSOLV fix so far?
    2. What feature would you like to see next?
    3. Any challenges or friction points?

    Just hit reply and share your thoughts - we read every response!

    Did You Know?
    Here are some ways other teams are using RSOLV:
    - Security audits: Tag all security-related issues for automated fixes
    - Tech debt cleanup: Fix deprecated function calls across the codebase
    - Onboarding tool: Let new devs see how fixes should be implemented
    - Weekend warrior: Queue up fixes on Friday, review on Monday

    Thanks for being an early adopter!

    Best regards,
    Dylan & The RSOLV Team

    P.S. If RSOLV has saved you time this week, we'd love to hear about it!

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  defp success_checkin_text_body(first_name, email) do
    """
    Your 2-Week RSOLV Success Report

    Hi #{first_name},

    Congratulations! You've been using RSOLV for two weeks. Here's what we've accomplished together:

    Your Stats:
    - Issues Fixed: Check your dashboard
    - PRs Created: Check your dashboard
    - Time Saved: Check your dashboard
    - Security Issues Found: Check your dashboard

    Your Trial Status:
    Check how many free fixes you have remaining at: https://rsolv.dev/dashboard

    What's Next?
    - Expand to more repositories
    - Automate security audits
    - Clean up tech debt
    - Train your team

    Need Help Scaling Up?
    I'd love to help you get even more value from RSOLV:
    - Schedule a 15-minute optimization call
    - Get best practices for your specific tech stack
    - Learn about volume discounts for teams

    Just reply to this email and let me know how I can help!

    Thanks for being part of the RSOLV community.

    Best regards,
    Dylan Fitzgerald
    Founder, RSOLV

    P.S. If RSOLV has been valuable to your team, I'd be grateful if you could share a quick testimonial.

    ---
    To unsubscribe, visit: https://rsolv.dev/unsubscribe?email=#{email}
    """
  end

  # Helper functions

  # Get admin emails from runtime configuration
  defp get_admin_emails do
    admin_emails = Application.get_env(:rsolv, :admin_emails, ["admin@rsolv.dev"])

    # For now, during Postmark trial, only send to @rsolv.dev emails
    admin_emails
    |> Enum.filter(fn email -> String.ends_with?(email, "@rsolv.dev") end)
    |> case do
      # Fallback
      [] -> ["admin@rsolv.dev"]
      emails -> emails
    end
  end

  # Generate a unique message ID for tracking
  defp generate_message_id do
    timestamp = System.system_time(:second)
    random = :rand.uniform(999_999)
    "<#{timestamp}.#{random}@rsolv.dev>"
  end

  # Admin notification HTML template
  defp admin_signup_notification_html(signup_data) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #10b981; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-radius: 0 0 8px 8px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
        .metric-value { font-size: 18px; font-weight: bold; color: #111827; }
        .details { background: white; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f3f4f6; }
        .detail-row:last-child { border-bottom: none; }
        .detail-label { font-weight: 500; color: #6b7280; }
        .detail-value { color: #111827; }
        .utm-badge { display: inline-block; background: #dbeafe; color: #1e40af; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 4px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1 style="margin: 0; font-size: 24px;">🎉 New RSOLV Signup!</h1>
          <p style="margin: 5px 0 0 0; opacity: 0.9;">#{format_timestamp(signup_data.timestamp)}</p>
        </div>

        <div class="content">
          <div class="metric">
            <div class="metric-label">Email</div>
            <div class="metric-value">#{signup_data.email}</div>
          </div>

          #{if Map.get(signup_data, :company) do
      ~s(<div class="metric">
              <div class="metric-label">Company</div>
              <div class="metric-value">#{signup_data.company}</div>
            </div>)
    else
      ""
    end}

          <div class="details">
            <h3 style="margin-top: 0;">Signup Details</h3>

            <div class="detail-row">
              <span class="detail-label">Source</span>
              <span class="detail-value">
                #{Map.get(signup_data, :source, "landing_page")}
                #{if Map.get(signup_data, :utm_source), do: ~s(<span class="utm-badge">#{signup_data.utm_source}</span>), else: ""}
              </span>
            </div>

            #{if Map.get(signup_data, :utm_medium) do
      ~s(<div class="detail-row">
                <span class="detail-label">Medium</span>
                <span class="detail-value">#{signup_data.utm_medium}</span>
              </div>)
    else
      ""
    end}

            #{if Map.get(signup_data, :utm_campaign) do
      ~s(<div class="detail-row">
                <span class="detail-label">Campaign</span>
                <span class="detail-value">#{signup_data.utm_campaign}</span>
              </div>)
    else
      ""
    end}

            #{if Map.get(signup_data, :referrer) do
      ~s(<div class="detail-row">
                <span class="detail-label">Referrer</span>
                <span class="detail-value">#{truncate_url(signup_data.referrer)}</span>
              </div>)
    else
      ""
    end}
          </div>

          <div style="margin-top: 20px; text-align: center;">
            <a href="https://rsolv.dev/live/dashboard" style="display: inline-block; background: #10b981; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
              View Dashboard
            </a>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
  end

  # Admin notification text template
  defp admin_signup_notification_text(signup_data) do
    """
    🎉 New RSOLV Signup!

    Email: #{signup_data.email}
    #{if Map.get(signup_data, :company), do: "Company: #{signup_data.company}\n", else: ""}
    Time: #{format_timestamp(signup_data.timestamp)}

    Source Details:
    - Source: #{Map.get(signup_data, :source, "landing_page")}
    #{if Map.get(signup_data, :utm_source), do: "- UTM Source: #{signup_data.utm_source}\n", else: ""}
    #{if Map.get(signup_data, :utm_medium), do: "- UTM Medium: #{signup_data.utm_medium}\n", else: ""}
    #{if Map.get(signup_data, :utm_campaign), do: "- UTM Campaign: #{signup_data.utm_campaign}\n", else: ""}
    #{if Map.get(signup_data, :referrer), do: "- Referrer: #{signup_data.referrer}\n", else: ""}

    View full dashboard: https://rsolv.dev/live/dashboard
    """
  end

  # Format timestamp helper
  defp format_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, datetime, _} ->
        Calendar.strftime(datetime, "%B %d, %Y at %I:%M %p UTC")

      _ ->
        timestamp
    end
  end

  defp format_timestamp(_),
    do: DateTime.utc_now() |> Calendar.strftime("%B %d, %Y at %I:%M %p UTC")

  # Truncate URL helper
  defp truncate_url(url) when is_binary(url) do
    if String.length(url) > 50 do
      String.slice(url, 0..47) <> "..."
    else
      url
    end
  end

  defp truncate_url(_), do: ""

  # Contact form notification HTML template
  defp contact_form_notification_html(contact_data) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-radius: 0 0 8px 8px; }
        .field { margin-bottom: 15px; }
        .field-label { font-weight: 600; color: #374151; margin-bottom: 5px; }
        .field-value { color: #111827; background: white; padding: 10px; border-radius: 4px; border: 1px solid #e5e7eb; }
        .message { background: white; padding: 15px; border-radius: 4px; border: 1px solid #e5e7eb; margin: 20px 0; }
        .actions { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
        .btn { display: inline-block; padding: 10px 20px; background: #2563eb; color: white; text-decoration: none; border-radius: 4px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1 style="margin: 0; font-size: 24px;">🏢 New Contact Form Submission</h1>
          <p style="margin: 5px 0 0 0; opacity: 0.9;">#{format_timestamp(contact_data.timestamp)}</p>
        </div>

        <div class="content">
          <div class="field">
            <div class="field-label">Name</div>
            <div class="field-value">#{contact_data.name}</div>
          </div>

          <div class="field">
            <div class="field-label">Email</div>
            <div class="field-value">
              <a href="mailto:#{contact_data.email}" style="color: #2563eb;">#{contact_data.email}</a>
            </div>
          </div>

          <div class="field">
            <div class="field-label">Company</div>
            <div class="field-value">#{contact_data.company}</div>
          </div>

          <div class="field">
            <div class="field-label">Team Size</div>
            <div class="field-value">#{contact_data.team_size}</div>
          </div>

          <div class="message">
            <div class="field-label" style="margin-bottom: 10px;">Message</div>
            <div style="white-space: pre-wrap;">#{contact_data.message}</div>
          </div>

          <div class="actions">
            <a href="mailto:#{contact_data.email}" class="btn">Reply to #{contact_data.name}</a>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
  end

  # Contact form notification text template
  defp contact_form_notification_text(contact_data) do
    """
    🏢 New Contact Form Submission

    Name: #{contact_data.name}
    Email: #{contact_data.email}
    Company: #{contact_data.company}
    Team Size: #{contact_data.team_size}
    Time: #{format_timestamp(contact_data.timestamp)}

    Message:
    #{contact_data.message}

    ---
    Reply directly to this email or contact them at: #{contact_data.email}
    """
  end
end
