defmodule RsolvApi.Security.Patterns.Ruby.InsufficientLoggingTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Ruby.InsufficientLogging
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = InsufficientLogging.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-insufficient-logging"
      assert pattern.name == "Insufficient Security Logging"
      assert pattern.severity == :medium
      assert pattern.type == :information_disclosure
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = InsufficientLogging.pattern()
      
      assert pattern.cwe_id == "CWE-778"
      assert pattern.owasp_category == "A09:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = InsufficientLogging.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 8
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = InsufficientLogging.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches empty rescue blocks without logging", %{pattern: pattern} do
      vulnerable_code = [
        ~S|rescue StandardError|,
        ~S|rescue => e\n  # No logging|,
        ~S|rescue Exception\n  nil|,
        ~S|rescue\n  false|,
        ~S|rescue ActiveRecord::RecordNotFound|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches authentication actions without logging", %{pattern: pattern} do
      vulnerable_code = [
        ~S|def login\n  user = User.find_by(email: params[:email])\n  redirect_to root_path|,
        ~S|def authenticate\n  if user&.authenticate(params[:password])\n    session[:user_id] = user.id\n  end|,
        ~S|before_action :require_login\ndef destroy\n  session.clear\nend|,
        ~S|def reset_password\n  user.update(password: params[:password])\nend|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches authorization failures without logging", %{pattern: pattern} do
      vulnerable_code = [
        ~S|def admin_only\n  redirect_to root_path unless current_user.admin?\nend|,
        ~S|unless can?(:edit, @post)\n  render :unauthorized\nend|,
        ~S|raise PermissionDenied unless authorized?|,
        ~S|return false unless current_user.can_access?(resource)|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches sensitive operations without logging", %{pattern: pattern} do
      vulnerable_code = [
        ~S|def update_user_role\n  user.update(role: params[:role])\nend|,
        ~S|def delete_account\n  current_user.destroy\n  redirect_to root_path\nend|,
        ~S|def transfer_funds\n  account.withdraw(amount)\n  target.deposit(amount)\nend|,
        ~S|def change_permissions\n  user.permissions = new_permissions\n  user.save\nend|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches failed operations without proper logging", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if user.save\n  redirect_to user_path(user)\nelse\n  render :new\nend|,
        ~S|unless payment.process!\n  flash[:error] = "Payment failed"\nend|,
        ~S|return unless file.upload\nflash[:error] = "Upload failed"|,
        ~S|raise "Invalid input" if params[:data].blank?|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches missing audit trail for data changes", %{pattern: pattern} do
      vulnerable_code = [
        ~S|def bulk_update\n  User.where(id: ids).update_all(status: 'inactive')\nend|,
        "params[:users].each { |u| u.destroy }",
        ~S|@record.update_columns(sensitive_data: new_data)|,
        ~S|execute("DELETE FROM users WHERE created_at < ?", 1.year.ago)|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match code with proper security logging", %{pattern: pattern} do
      safe_code = [
        ~S|rescue StandardError => e\n  logger.error "Authentication failed: #{e.message}"|,
        ~S|def login\n  Rails.logger.warn "Failed login attempt for #{params[:email]}"\nend|,
        ~S|unless authorized?\n  security_log.info "Unauthorized access attempt by user #{current_user.id}"\nend|,
        ~S|def destroy\n  audit_log.info "User #{current_user.id} logged out"\n  session.clear\nend|,
        ~S|if user.save\n  redirect_to user_path(user)\nelse\n  logger.warn "User creation failed: #{user.errors.full_messages}"\nend|,
        ~S|# This is a comment about logging\nlogger.info "Action completed"|,
        ~S|puts "Debug output"|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = ~S|# rescue StandardError # No logging|
      
      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = InsufficientLogging.vulnerability_metadata()
      
      assert metadata.description =~ "security"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes CWE and OWASP examples from research" do
      metadata = InsufficientLogging.vulnerability_metadata()
      
      cwe_found = Enum.any?(metadata.references, &(&1.type == :cwe))
      assert cwe_found
      
      owasp_found = Enum.any?(metadata.references, &(&1.type == :owasp))
      assert owasp_found
    end
    
    test "includes proper security references" do
      metadata = InsufficientLogging.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = InsufficientLogging.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes logging-specific AST rules" do
      enhancement = InsufficientLogging.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodDefinition"
      assert enhancement.ast_rules.security_method_analysis.authentication_methods
      assert enhancement.ast_rules.security_method_analysis.authorization_methods
    end
    
    test "has exception handling analysis" do
      enhancement = InsufficientLogging.ast_enhancement()
      
      assert enhancement.ast_rules.exception_analysis.rescue_blocks
      assert enhancement.ast_rules.exception_analysis.check_logging_presence
    end
    
    test "includes logging pattern detection" do
      enhancement = InsufficientLogging.ast_enhancement()
      
      assert "logger" in enhancement.ast_rules.logging_analysis.logging_methods
      assert "Rails.logger" in enhancement.ast_rules.logging_analysis.logging_methods
      assert "audit_log" in enhancement.ast_rules.logging_analysis.logging_methods
    end
  end
end