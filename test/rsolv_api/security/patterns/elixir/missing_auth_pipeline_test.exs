defmodule RsolvApi.Security.Patterns.Elixir.MissingAuthPipelineTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.MissingAuthPipeline
  alias RsolvApi.Security.Pattern

  describe "missing_auth_pipeline pattern" do
    test "returns correct pattern structure" do
      pattern = MissingAuthPipeline.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-missing-auth-pipeline"
      assert pattern.name == "Missing Authentication Pipeline"
      assert pattern.type == :authentication
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["phoenix"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-306"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects controllers with missing authentication" do
      pattern = MissingAuthPipeline.pattern()
      
      test_cases = [
        "defmodule MyAppWeb.AdminController do\n  use MyAppWeb, :controller\n  def index(conn, _params) do",
        "defmodule AppWeb.UserController do\n  use AppWeb, :controller\n\n  def show(conn, %{\"id\" => id}) do",
        "defmodule WebApp.AccountController do\n  use WebApp, :controller\n  def edit(conn, _params) do"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects sensitive controllers without authentication" do
      pattern = MissingAuthPipeline.pattern()
      
      test_cases = [
        "defmodule MyAppWeb.AdminController do\n  use MyAppWeb, :controller\n  \n  def dashboard(conn, _params) do",
        "defmodule AppWeb.UserManagementController do\n  use AppWeb, :controller\n  def delete_user(conn, _params) do",
        "defmodule WebApp.AccountSettingsController do\n  use WebApp, :controller\n\n  def update_password(conn, _params) do"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects controllers with pipe_through but no auth" do
      pattern = MissingAuthPipeline.pattern()
      
      test_cases = [
        "defmodule MyAppWeb.AdminController do\n  use MyAppWeb, :controller\n  \n  pipe_through [:browser]\n  \n  def index(conn, _params) do",
        "defmodule AppWeb.UserController do\n  use AppWeb, :controller\n  pipe_through :api\n  def show(conn, _params) do"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multiline controller definitions" do
      pattern = MissingAuthPipeline.pattern()
      
      vulnerable_code = """
      defmodule MyAppWeb.AdminController do
        use MyAppWeb, :controller
        
        # Some comments
        alias MyApp.Users
        
        def index(conn, _params) do
          users = Users.list_all()
          render(conn, :index, users: users)
        end
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
             "Failed to detect multiline controller"
    end

    test "does not detect controllers with authentication" do
      pattern = MissingAuthPipeline.pattern()
      
      safe_code = [
        "defmodule MyAppWeb.AdminController do\n  use MyAppWeb, :controller\n  \n  plug :authenticate_admin\n  \n  def index(conn, _params) do",
        "defmodule AppWeb.UserController do\n  use AppWeb, :controller\n  plug :require_authenticated_user\n  def show(conn, _params) do",
        "defmodule WebApp.AccountController do\n  use WebApp, :controller\n  \n  plug MyApp.AuthPlug\n  \n  def edit(conn, _params) do"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect controllers with pipeline authentication" do
      pattern = MissingAuthPipeline.pattern()
      
      safe_code = [
        "defmodule MyAppWeb.AdminController do\n  use MyAppWeb, :controller\n  \n  pipe_through [:browser, :require_authenticated_user]\n  \n  def index(conn, _params) do",
        "defmodule AppWeb.UserController do\n  use AppWeb, :controller\n  pipe_through [:api, :auth]\n  def show(conn, _params) do"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect non-sensitive controllers" do
      pattern = MissingAuthPipeline.pattern()
      
      safe_code = [
        "defmodule MyAppWeb.HomeController do\n  use MyAppWeb, :controller\n  def index(conn, _params) do",
        "defmodule AppWeb.PageController do\n  use AppWeb, :controller\n  def show(conn, _params) do",
        "defmodule WebApp.PublicController do\n  use WebApp, :controller\n  def about(conn, _params) do"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = MissingAuthPipeline.vulnerability_metadata()
      
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

    test "vulnerability metadata contains authentication-specific information" do
      metadata = MissingAuthPipeline.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "Unauthorized")
      assert String.contains?(metadata.business_impact, "data")
      assert String.contains?(metadata.technical_impact, "access")
      assert String.contains?(metadata.safe_alternatives, "plug")
      assert String.contains?(metadata.prevention_tips, "authentication")
    end

    test "includes AST enhancement rules" do
      enhancement = MissingAuthPipeline.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has authentication-specific rules" do
      enhancement = MissingAuthPipeline.ast_enhancement()
      
      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.sensitive_controller_patterns
      assert enhancement.ast_rules.controller_analysis
      assert enhancement.ast_rules.authentication_analysis
      assert enhancement.confidence_rules.adjustments.sensitive_controller_bonus
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = MissingAuthPipeline.enhanced_pattern()
      
      assert enhanced.id == "elixir-missing-auth-pipeline"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = MissingAuthPipeline.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end