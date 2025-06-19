defmodule RsolvApi.Security.Patterns.Rails.InsecureSessionDataTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.InsecureSessionData
  alias RsolvApi.Security.Pattern

  describe "insecure_session_data pattern" do
    test "returns correct pattern structure" do
      pattern = InsecureSessionData.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-insecure-session-data"
      assert pattern.name == "Sensitive Data in Session"
      assert pattern.type == :sensitive_data_exposure
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-200"
      assert pattern.owasp_category == "A02:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects password storage in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:password] = params[:password]",
        "session['password'] = user.password",
        "session[\"password\"] = raw_password",
        "session[:user_password] = input_password",
        "session[:admin_password] = admin_pwd",
        "session[:current_password] = current_pwd"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects credit card information storage in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:credit_card] = params[:credit_card]",
        "session['credit_card'] = cc_number",
        "session[\"credit_card\"] = card_info",
        "session[:cc_number] = card_number",
        "session[:card_number] = params[:card]",
        "session[:payment_card] = payment_info"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects SSN and personal identifiers in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:ssn] = params[:ssn]",
        "session['ssn'] = social_security_number",
        "session[\"ssn\"] = user_ssn",
        "session[:social_security] = ssn",
        "session[:tax_id] = params[:tax_id]",
        "session[:national_id] = params[:national_id]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects API keys and secret tokens in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:api_key] = params[:api_key]",
        "session['api_key'] = user_api_key",
        "session[\"api_key\"] = api_token",
        "session[:secret_token] = secret",
        "session[:auth_token] = token",
        "session[:access_token] = oauth_token"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects private keys and certificates in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:private_key] = params[:private_key]",
        "session['private_key'] = user_private_key",
        "session[\"private_key\"] = rsa_key",
        "session[:ssl_key] = ssl_private_key",
        "session[:encryption_key] = enc_key",
        "session[:cert_key] = certificate_key"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects medical and health information in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:medical_record] = params[:medical_record]",
        "session[:health_info] = health_data",
        "session[:diagnosis] = patient_diagnosis",
        "session[:medication] = medication_list",
        "session[:treatment] = treatment_plan",
        "session[:patient_data] = patient_info"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects financial and banking information in session" do
      pattern = InsecureSessionData.pattern()
      
      vulnerable_code = [
        "session[:bank_account] = params[:bank_account]",
        "session[:account_number] = account_num",
        "session[:routing_number] = routing_num",
        "session[:iban] = iban_number",
        "session[:financial_data] = financial_info",
        "session[:balance] = account_balance"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe session data" do
      pattern = InsecureSessionData.pattern()
      
      safe_code = [
        "session[:user_id] = user.id",
        "session[:username] = user.username",
        "session[:role] = user.role",
        "session[:last_login] = Time.current",
        "session[:preferences] = user_preferences",
        "session[:theme] = 'dark'",
        "session[:locale] = 'en'",
        "session[:timezone] = 'UTC'",
        "session[:cart_items] = []",
        "session[:shopping_cart] = cart_id",
        "session[:current_page] = request.path",
        "session[:visited_pages] = page_history",
        "# session[:password] = password  # commented out",
        "flash[:notice] = 'Password updated'",
        "cookies[:remember_token] = token"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = InsecureSessionData.vulnerability_metadata()
      
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

    test "vulnerability metadata contains sensitive data exposure specific information" do
      metadata = InsecureSessionData.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "sensitive")
      assert String.contains?(String.downcase(metadata.attack_vectors), "session")
      assert String.contains?(String.downcase(metadata.business_impact), "compliance")
      assert String.contains?(metadata.safe_alternatives, "server-side")
      assert String.contains?(String.downcase(metadata.prevention_tips), "encrypt")
      
      # Check for Rails-specific content
      assert String.contains?(String.downcase(metadata.description), "rails")
      assert String.contains?(String.downcase(metadata.remediation_steps), "database")
    end

    test "includes AST enhancement rules" do
      enhancement = InsecureSessionData.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has sensitive data specific rules" do
      enhancement = InsecureSessionData.ast_enhancement()
      
      assert enhancement.context_rules.sensitive_data_patterns
      assert enhancement.context_rules.safe_session_fields
      assert enhancement.ast_rules.session_analysis
      assert enhancement.confidence_rules.adjustments.contains_sensitive_keywords
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = InsecureSessionData.enhanced_pattern()
      
      assert enhanced.id == "rails-insecure-session-data"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = InsecureSessionData.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert InsecureSessionData.applies_to_file?("app/controllers/sessions_controller.rb")
      assert InsecureSessionData.applies_to_file?("app/controllers/users_controller.rb", ["rails"])
      assert InsecureSessionData.applies_to_file?("lib/authentication.rb", ["rails"])
      refute InsecureSessionData.applies_to_file?("test.js")
      refute InsecureSessionData.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert InsecureSessionData.applies_to_file?("app/controllers/admin_controller.rb", ["rails"])
      refute InsecureSessionData.applies_to_file?("app/controllers/admin_controller.rb", ["sinatra"])
      refute InsecureSessionData.applies_to_file?("app/controllers/admin_controller.py", ["rails"])
    end
  end
end