defmodule Rsolv.Security.Patterns.Rails.SessionFixationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Rails.SessionFixation
  alias Rsolv.Security.Pattern

  describe "session_fixation pattern" do
    test "returns correct pattern structure" do
      pattern = SessionFixation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-session-fixation"
      assert pattern.name == "Session Fixation Vulnerability"
      assert pattern.type == :broken_authentication
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-384"
      assert pattern.owasp_category == "A07:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects login method without session regeneration" do
      pattern = SessionFixation.pattern()
      
      vulnerable_code = [
        "def login\n  if user.authenticate(params[:password])\n    session[:user_id] = user.id\n  end\nend",
        "def sign_in\n  user = User.find(params[:id])\n  session[:user_id] = user.id\nend",
        "def authenticate\n  if valid_credentials?\n    session[:current_user_id] = user.id\n  end\nend",
        "def create\n  user = User.authenticate(params[:email], params[:password])\n  if user\n    session[:user_id] = user.id\n    redirect_to dashboard_path\n  end\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects session assignment with admin flags" do
      pattern = SessionFixation.pattern()
      
      vulnerable_code = [
        "def admin_login\n  if admin.valid_password?(params[:password])\n    session[:admin] = true\n  end\nend",
        "def create\n  if params[:admin_key] == ADMIN_KEY\n    session[:admin] = true\n  end\nend",
        "session[:is_admin] = true",
        "session[:admin_user] = true",
        "session[:super_user] = true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects direct session user_id assignment without reset" do
      pattern = SessionFixation.pattern()
      
      vulnerable_code = [
        "session[:user_id] = user.id",
        "session[:user_id] = params[:user_id]",
        "session[:current_user_id] = user.id",
        "session[:authenticated_user] = user.id",
        "session['user_id'] = user.id",
        "session[\"user_id\"] = user.id"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects multiline login methods without session reset" do
      pattern = SessionFixation.pattern()
      
      vulnerable_code = [
        """
        def login
          user = User.find_by(email: params[:email])
          if user&.authenticate(params[:password])
            session[:user_id] = user.id
            flash[:notice] = "Welcome back!"
            redirect_to root_path
          else
            flash[:error] = "Invalid credentials"
            render :new
          end
        end
        """,
        """
        def create
          @user = User.find_by(email: params[:session][:email].downcase)
          
          if @user && @user.authenticate(params[:session][:password])
            log_in @user
            session[:user_id] = @user.id
            redirect_back_or @user
          else
            flash.now[:danger] = 'Invalid email/password combination'
            render 'new'
          end
        end
        """
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects authentication without session regeneration in controllers" do
      pattern = SessionFixation.pattern()
      
      vulnerable_code = [
        """
        class SessionsController < ApplicationController
          def create
            user = User.authenticate(params[:email], params[:password])
            if user
              session[:user_id] = user.id
              redirect_to dashboard_path
            end
          end
        end
        """,
        """
        def authenticate_user!
          if User.valid_login?(params[:username], params[:password])
            session[:authenticated] = true
            session[:user_id] = params[:user_id]
          end
        end
        """
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe authentication with session reset" do
      pattern = SessionFixation.pattern()
      
      safe_code = [
        "def login\n  if user.authenticate(params[:password])\n    reset_session\n    session[:user_id] = user.id\n  end\nend",
        "def sign_in\n  user = User.find(params[:id])\n  session.regenerate\n  session[:user_id] = user.id\nend",
        "def create\n  user = User.authenticate(params[:email], params[:password])\n  if user\n    reset_session\n    session[:user_id] = user.id\n    redirect_to dashboard_path\n  end\nend",
        "# session[:user_id] = user.id  # commented out",
        "session[:cart_items] = []  # not user authentication",
        "session[:last_visited] = request.path",
        "session[:theme] = 'dark'",
        """
        def login
          user = User.find_by(email: params[:email])
          if user&.authenticate(params[:password])
            reset_session  # Prevents session fixation
            session[:user_id] = user.id
            log_activity("User logged in")
          end
        end
        """
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = SessionFixation.vulnerability_metadata()
      
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

    test "vulnerability metadata contains session fixation specific information" do
      metadata = SessionFixation.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "session")
      assert String.contains?(String.downcase(metadata.attack_vectors), "fixation")
      assert String.contains?(String.downcase(metadata.business_impact), "hijack")
      assert String.contains?(metadata.safe_alternatives, "reset_session")
      assert String.contains?(String.downcase(metadata.prevention_tips), "regenerat")
      
      # Check for Rails-specific content
      assert String.contains?(String.downcase(metadata.description), "rails")
      assert String.contains?(String.downcase(metadata.remediation_steps), "reset_session")
    end

    test "includes AST enhancement rules" do
      enhancement = SessionFixation.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has authentication specific rules" do
      enhancement = SessionFixation.ast_enhancement()
      
      assert enhancement.context_rules.authentication_methods
      assert enhancement.context_rules.session_fields
      assert enhancement.ast_rules.authentication_analysis
      assert enhancement.confidence_rules.adjustments.missing_session_reset
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = SessionFixation.enhanced_pattern()
      
      assert enhanced.id == "rails-session-fixation"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = SessionFixation.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert SessionFixation.applies_to_file?("app/controllers/sessions_controller.rb", nil)
      assert SessionFixation.applies_to_file?("app/controllers/authentication_controller.rb", ["rails"])
      assert SessionFixation.applies_to_file?("lib/auth/login.rb", ["rails"])
      refute SessionFixation.applies_to_file?("test.js", nil)
      refute SessionFixation.applies_to_file?("script.py", nil)
    end

    test "applies to ruby files with Rails framework" do
      assert SessionFixation.applies_to_file?("app/controllers/sessions_controller.rb", ["rails"])
      refute SessionFixation.applies_to_file?("app/controllers/sessions_controller.rb", ["sinatra"])
      refute SessionFixation.applies_to_file?("app/controllers/sessions_controller.py", ["rails"])
    end
  end
end