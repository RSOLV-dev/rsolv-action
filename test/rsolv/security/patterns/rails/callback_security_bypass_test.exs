defmodule Rsolv.Security.Patterns.Rails.CallbackSecurityBypassTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Rails.CallbackSecurityBypass

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = CallbackSecurityBypass.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "rails-callback-security-bypass"
      assert pattern.name == "Rails Callback Security Bypass"

      assert pattern.description ==
               "Bypass of security constraints through skip callback conditions"

      assert pattern.type == :broken_access_control
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-285"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = CallbackSecurityBypass.vulnerability_metadata()

      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :technical_impact)
      assert Map.has_key?(metadata, :business_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      assert Map.has_key?(metadata, :remediation_steps)
      assert Map.has_key?(metadata, :detection_methods)
      assert Map.has_key?(metadata, :prevention_tips)

      assert String.contains?(metadata.description, "security callbacks")
      assert String.contains?(metadata.attack_vectors, "authentication bypass")
      assert String.contains?(metadata.safe_alternatives, "predefined conditions")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = CallbackSecurityBypass.ast_enhancement()

      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)

      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.callback_methods)
      assert "skip_before_action" in ast.context_rules.callback_methods

      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.params_in_condition == +0.5

      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.callback_analysis.detect_user_input_conditions == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = CallbackSecurityBypass.enhanced_pattern()

      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == CallbackSecurityBypass.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects skip_before_action with params in lambda condition" do
      vulnerable_code = """
      class UsersController < ApplicationController
        skip_before_action :authenticate, if: -> { params[:skip] }
        
        def show
          @user = User.find(params[:id])
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects skip_around_action with direct params condition" do
      vulnerable_code = """
      class AdminController < ApplicationController
        skip_around_action :admin_check, if: params[:bypass_admin]
        
        def settings
          # Admin settings here
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects skip_after_action with eval in lambda" do
      vulnerable_code = """
      class PaymentController < ApplicationController
        skip_after_action :log_payment, if: -> { eval(params[:condition]) }
        
        def process_payment
          # Payment processing
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects complex bypass with user input" do
      vulnerable_code = """
      skip_before_action :require_admin, if: -> { 
        params[:user_type] == 'admin' || params[:override] 
      }
      """

      pattern = CallbackSecurityBypass.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects skip_before_filter (legacy Rails)" do
      vulnerable_code = """
      class LegacyController < ApplicationController
        skip_before_filter :authenticate_user, if: -> { params[:public] == 'true' }
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end
  end

  describe "safe code validation" do
    test "does not flag safe skip with predefined method" do
      safe_code = """
      class PublicController < ApplicationController
        skip_before_action :authenticate, if: :public_action?
        
        private
        
        def public_action?
          action_name.in?(['about', 'contact', 'home'])
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag skip with constant conditions" do
      safe_code = """
      class ApiController < ApplicationController
        skip_before_action :verify_authenticity_token, if: :api_request?
        skip_around_action :set_locale, only: [:health_check]
        skip_after_action :track_activity, except: [:index, :show]
        
        private
        
        def api_request?
          request.format.json?
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag skip without conditions" do
      safe_code = """
      class HealthController < ApplicationController
        skip_before_action :authenticate_user
        
        def status
          render json: { status: 'ok' }
        end
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag skip with Rails env conditions" do
      safe_code = """
      class DevController < ApplicationController
        skip_before_action :require_auth, if: -> { Rails.env.development? }
        skip_after_action :send_notifications, unless: -> { Rails.env.production? }
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag commented out vulnerable code" do
      safe_code = """
      class SecureController < ApplicationController
        # DEPRECATED: This was vulnerable
        # skip_before_action :authenticate, if: -> { params[:skip] }
        
        # Now using proper authentication
        before_action :authenticate_user!
      end
      """

      pattern = CallbackSecurityBypass.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Rails controller files" do
      assert CallbackSecurityBypass.applies_to_file?("app/controllers/users_controller.rb", [
               "rails"
             ])

      assert CallbackSecurityBypass.applies_to_file?(
               "app/controllers/admin/settings_controller.rb",
               ["rails"]
             )

      assert CallbackSecurityBypass.applies_to_file?(
               "app/controllers/application_controller.rb",
               ["rails"]
             )

      assert CallbackSecurityBypass.applies_to_file?(
               "app/controllers/api/v1/base_controller.rb",
               ["rails"]
             )
    end

    test "applies to concerns" do
      assert CallbackSecurityBypass.applies_to_file?(
               "app/controllers/concerns/authenticatable.rb",
               ["rails"]
             )

      assert CallbackSecurityBypass.applies_to_file?(
               "app/controllers/concerns/authorization.rb",
               ["rails"]
             )
    end

    test "infers Rails from controller file paths" do
      assert CallbackSecurityBypass.applies_to_file?("app/controllers/users_controller.rb", [])
      assert CallbackSecurityBypass.applies_to_file?("app/controllers/concerns/auth.rb", [])
    end

    test "does not apply to non-controller files" do
      refute CallbackSecurityBypass.applies_to_file?("app/models/user.rb", ["rails"])
      refute CallbackSecurityBypass.applies_to_file?("app/views/users/show.html.erb", ["rails"])
      refute CallbackSecurityBypass.applies_to_file?("config/routes.rb", ["rails"])

      refute CallbackSecurityBypass.applies_to_file?(
               "test/controllers/users_controller_test.rb",
               ["rails"]
             )
    end

    test "does not apply to non-Ruby files" do
      refute CallbackSecurityBypass.applies_to_file?("app/controllers/users.js", ["rails"])
      refute CallbackSecurityBypass.applies_to_file?("app/controllers/styles.css", ["rails"])
    end
  end
end
