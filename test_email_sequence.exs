# Test Email Sequence Script
# Run with: mix run test_email_sequence.exs

alias Rsolv.CustomerOnboarding
alias Rsolv.Repo
require Ecto.Query

IO.puts("\n🧪 Testing Early Access Email Sequence\n")

# Create a test customer
test_email = "test-email-sequence-#{:rand.uniform(99999)}@example.com"
IO.puts("1. Creating test customer: #{test_email}")

case CustomerOnboarding.provision_customer(%{
  email: test_email,
  name: "Test User for Email Sequence"
}) do
  {:ok, result} ->
    IO.puts("✅ Customer provisioned successfully!")
    IO.puts("   Email: #{result.customer.email}")
    IO.puts("   Customer ID: #{result.customer.id}")
    IO.puts("   Name: #{result.customer.name}")
    IO.puts("   API Key: #{String.slice(result.api_key, 0..20)}...")
    IO.puts("   Trial fixes limit: #{result.customer.trial_fixes_limit}")
    IO.puts("   Auto provisioned: #{result.customer.auto_provisioned}")

    # Check Oban jobs for this customer
    IO.puts("\n2. Checking scheduled email jobs:")

    jobs = Repo.all(
      Ecto.Query.from j in Oban.Job,
        where: j.state in ["scheduled", "available"],
        where: fragment("?->>'email' = ?", j.args, ^test_email),
        order_by: [asc: j.scheduled_at],
        limit: 10
    )

    if Enum.empty?(jobs) do
      IO.puts("⚠️  No jobs found for #{test_email}")
      IO.puts("\nLet's check all recent jobs:")

      all_jobs = Repo.all(
        Ecto.Query.from j in Oban.Job,
          where: j.state in ["scheduled", "available", "completed"],
          order_by: [desc: j.inserted_at],
          limit: 10
      )

      Enum.each(all_jobs, fn job ->
        email = get_in(job.args, ["email"])
        IO.puts("   - #{job.worker} | #{job.state} | #{email} | scheduled: #{job.scheduled_at}")
      end)
    else
      IO.puts("📧 Found #{length(jobs)} scheduled email jobs:")
      Enum.each(jobs, fn job ->
        days_delay = if job.scheduled_at do
          DateTime.diff(job.scheduled_at, job.inserted_at, :day)
        else
          0
        end
        IO.puts("   - Day #{days_delay}: #{job.worker} scheduled for #{job.scheduled_at}")
      end)
    end

    # Check for welcome email delivery
    IO.puts("\n3. Checking welcome email delivery logs:")
    IO.puts("   (Look for '[EMAIL] send_early_access_welcome_email called' in logs)")

    IO.puts("\n✅ Test complete! Customer ID: #{result.customer.id}")

  {:error, {:validation_failed, changeset}} ->
    IO.puts("❌ Validation failed:")
    IO.inspect(changeset.errors)

  {:error, reason} ->
    IO.puts("❌ Provisioning failed: #{inspect(reason)}")
end
