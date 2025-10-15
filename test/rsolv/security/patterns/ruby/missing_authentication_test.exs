defmodule Rsolv.Security.Patterns.Ruby.MissingAuthenticationTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.MissingAuthentication
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = MissingAuthentication.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-broken-access-control-missing-auth"
      assert pattern.name == "Missing Authentication in Rails Controller"
      assert pattern.severity == :high
      assert pattern.type == :authentication
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = MissingAuthentication.pattern()

      assert pattern.cwe_id == "CWE-862"
      assert pattern.owasp_category == "A01:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = MissingAuthentication.pattern()
      {:ok, pattern: pattern}
    end

    test "matches controllers without authentication", %{pattern: pattern} do
      vulnerable_code = [
        # Basic controller without auth
        ~S|class AdminController < ApplicationController
  def users
    @users = User.all
  end
end|,
        # Multiple actions without auth
        ~S|class UsersController < ApplicationController
  def index
    @users = User.all
  end
  
  def show
    @user = User.find(params[:id])
  end
end|,
        # Controller with other methods but no auth
        ~S|class AccountController < ApplicationController
  helper_method :current_user
  
  def profile
    @account = Account.find(params[:id])
  end
end|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match controllers with before_action authentication", %{pattern: pattern} do
      safe_code = [
        # With before_action
        ~S|class AdminController < ApplicationController
  before_action :authenticate_user!
  
  def users
    @users = User.all
  end
end|,
        # With before_filter (older Rails)
        ~S|class AdminController < ApplicationController
  before_filter :authenticate_admin
  
  def users
    @users = User.all
  end
end|,
        # Multiple authentication methods
        ~S|class SecureController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin
  
  def sensitive_data
    @data = SecretData.all
  end
end|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "handles various controller syntax", %{pattern: pattern} do
      # Should match - no auth
      vulnerable = ~S|class DashboardController < ApplicationController
  layout 'admin'
  
  def stats
    @stats = calculate_stats
  end
  
  private
  
  def calculate_stats
    # some logic
  end
end|

      assert Regex.match?(pattern.regex, vulnerable)

      # Should not match - has auth
      safe = ~S|class DashboardController < ApplicationController
  before_action :authenticate_user!
  layout 'admin'
  
  def stats
    @stats = calculate_stats
  end
end|

      refute Regex.match?(pattern.regex, safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = MissingAuthentication.vulnerability_metadata()

      assert metadata.description =~ "authentication"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end

    test "includes relevant CVE examples" do
      metadata = MissingAuthentication.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert "CVE-2019-16109" in cve_ids
      assert "CVE-2024-45409" in cve_ids
    end

    test "includes proper references" do
      metadata = MissingAuthentication.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = MissingAuthentication.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes Rails-specific AST rules" do
      enhancement = MissingAuthentication.ast_enhancement()

      assert enhancement.ast_rules.node_type == "ClassDefinition"
      assert "ApplicationController" in enhancement.ast_rules.inheritance_patterns
    end

    test "has proper context exclusions" do
      enhancement = MissingAuthentication.ast_enhancement()

      assert enhancement.context_rules.exclude_if_contains
      assert "PublicController" in enhancement.context_rules.safe_controller_patterns
    end
  end
end
