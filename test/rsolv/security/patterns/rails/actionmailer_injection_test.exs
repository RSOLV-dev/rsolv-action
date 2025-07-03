defmodule Rsolv.Security.Patterns.Rails.ActionmailerInjectionTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Rails.ActionmailerInjection
  alias Rsolv.Security.Pattern

  describe "actionmailer_injection pattern" do
    test "returns correct pattern structure" do
      pattern = ActionmailerInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-actionmailer-injection"
      assert pattern.name == "ActionMailer Injection"
      assert pattern.type == :template_injection
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-117"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects mail() with direct params[:email] in to field" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(to: params[:email])",
        "mail(to: params[:email], subject: 'Hello')",
        "mail to: params[:email]",
        "mail to: params[:user_email]",
        "mail(to: params[:recipient])",
        "mail(:to => params[:email])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects mail() with string interpolation in subject field" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(subject: \"Welcome \#{params[:name]}\")",
        "mail(subject: 'Subject: \#{params[:subject]}')",
        "mail(to: 'user@example.com', subject: \"Hello \#{params[:username]}\")",
        "mail subject: \"Welcome \#{params[:name]}\", to: 'user@example.com'",
        "mail(:subject => \"Alert: \#{params[:message]}\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects mail() with string interpolation in from field" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(from: \"\#{params[:email]} <noreply@example.com>\")",
        "mail(from: 'From: \#{params[:from_name]} <system@example.com>')",
        "mail from: \"\#{params[:sender]} <admin@example.com>\"",
        "mail(:from => \"\#{params[:from]} <noreply@example.com>\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects mail() with params in cc and bcc fields" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(cc: params[:cc_email])",
        "mail(bcc: params[:bcc_recipients])",
        "mail(to: 'user@example.com', cc: params[:manager_email])",
        "mail cc: params[:cc], bcc: params[:bcc]",
        "mail(:cc => params[:carbon_copy])",
        "mail(:bcc => params[:blind_copy])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects mail() with ERB.new using params in body" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(body: ERB.new(params[:template]))",
        "mail(body: ERB.new params[:email_body])",
        "mail body: ERB.new(params[:content])",
        "mail(:body => ERB.new(params[:message]))"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects mail() with template_name from params" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        "mail(template_name: params[:template])",
        "mail(template_name: params[:email_template])",
        "mail template_name: params[:tmpl]",
        "mail(:template_name => params[:template_file])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects complex multiline mail configurations" do
      pattern = ActionmailerInjection.pattern()
      
      vulnerable_code = [
        """
        mail(
          to: params[:email],
          subject: "Welcome \#{params[:name]}",
          from: "\#{params[:sender]} <noreply@example.com>"
        )
        """,
        """
        mail to: params[:recipient],
             subject: "Hello \#{params[:username]}",
             cc: params[:manager]
        """,
        """
        mail(
          to: 'user@example.com',
          subject: "Alert: \#{params[:message]}",
          body: ERB.new(params[:body_template])
        )
        """
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe mail configurations" do
      pattern = ActionmailerInjection.pattern()
      
      safe_code = [
        "mail(to: validate_email(params[:email]))",
        "mail(to: User.find(params[:id]).email)",
        "mail(subject: 'Static subject line')",
        "mail(subject: \"Welcome \#{sanitize(params[:name])}\")",
        "mail(from: 'noreply@example.com')",
        "mail(to: 'admin@example.com', subject: 'Static message')",
        "mail(body: render_template('welcome'))",
        "mail(template_name: 'welcome_email')",
        "# mail(to: params[:email])  # commented out",
        "mail(to: ADMIN_EMAIL, subject: 'System notification')",
        "mail(to: current_user.email, subject: \"Hello \#{current_user.name}\")"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = ActionmailerInjection.vulnerability_metadata()
      
      assert metadata.description
      assert metadata.attack_vectors
      assert metadata.business_impact  
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains email injection specific information" do
      metadata = ActionmailerInjection.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "email")
      assert String.contains?(String.downcase(metadata.attack_vectors), "header")
      assert String.contains?(String.downcase(metadata.business_impact), "unauthorized")
      assert String.contains?(metadata.safe_alternatives, "validate")
      assert String.contains?(String.downcase(metadata.prevention_tips), "sanitize")
      
      # Check for ActionMailer-specific content
      assert String.contains?(String.downcase(metadata.description), "actionmailer")
      assert String.contains?(String.downcase(metadata.remediation_steps), "mail(")
    end

    test "includes AST enhancement rules" do
      enhancement = ActionmailerInjection.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has email specific rules" do
      enhancement = ActionmailerInjection.ast_enhancement()
      
      assert enhancement.context_rules.email_fields
      assert enhancement.context_rules.dangerous_sources
      assert enhancement.ast_rules.email_analysis
      assert enhancement.confidence_rules.adjustments.direct_params_usage
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = ActionmailerInjection.enhanced_pattern()
      
      assert enhanced.id == "rails-actionmailer-injection"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = ActionmailerInjection.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert ActionmailerInjection.applies_to_file?("app/mailers/user_mailer.rb", nil)
      assert ActionmailerInjection.applies_to_file?("app/mailers/notification_mailer.rb", ["rails"])
      assert ActionmailerInjection.applies_to_file?("app/controllers/emails_controller.rb", ["rails"])
      refute ActionmailerInjection.applies_to_file?("test.js", nil)
      refute ActionmailerInjection.applies_to_file?("script.py", nil)
    end

    test "applies to ruby files with Rails framework" do
      assert ActionmailerInjection.applies_to_file?("app/mailers/user_mailer.rb", ["rails"])
      refute ActionmailerInjection.applies_to_file?("app/mailers/user_mailer.rb", ["sinatra"])
      refute ActionmailerInjection.applies_to_file?("app/mailers/user_mailer.py", ["rails"])
    end
  end
end