defmodule RsolvApi.Security.Patterns.Elixir.UnsafeRedirectTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.UnsafeRedirect
  alias RsolvApi.Security.Pattern

  describe "unsafe_redirect pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeRedirect.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-redirect"
      assert pattern.name == "Open Redirect Vulnerability"
      assert pattern.type == :open_redirect
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["phoenix"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects redirect with external parameter" do
      pattern = UnsafeRedirect.pattern()
      
      test_cases = [
        "redirect(conn, external: params[\"return_to\"])",
        "redirect(conn, external: params[:redirect_url])",
        "redirect(conn, external: params.url)",
        "redirect(conn, external: conn.params[\"next\"])"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects redirect with user input variables" do
      pattern = UnsafeRedirect.pattern()
      
      test_cases = [
        "redirect(conn, external: user_url)",
        "redirect(conn, external: redirect_path)",
        "redirect(conn, external: next_page)",
        "redirect(conn, external: return_url)"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects redirect with interpolated user input" do
      pattern = UnsafeRedirect.pattern()
      
      test_cases = [
        ~S|redirect(conn, external: "https://example.com/#{params[:path]}")|,
        ~S|redirect(conn, external: "#{base_url}#{user_path}")|,
        ~S|redirect(conn, external: "#{params.host}/callback")|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects redirect with request data" do
      pattern = UnsafeRedirect.pattern()
      
      test_cases = [
        "redirect(conn, external: get_req_header(conn, \"referer\"))",
        "redirect(conn, external: conn.query_params[\"url\"])",
        "redirect(conn, external: conn.body_params[\"redirect_to\"])"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multiline redirect patterns" do
      pattern = UnsafeRedirect.pattern()
      
      vulnerable_code = """
      redirect(conn,
        external: params["callback_url"]
      )
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
             "Failed to detect multiline redirect"
    end

    test "does not detect safe redirect patterns" do
      pattern = UnsafeRedirect.pattern()
      
      safe_code = [
        "redirect(conn, to: Routes.home_path(conn, :index))",
        "redirect(conn, to: \"/dashboard\")",
        "redirect(conn, to: user_path(conn, :show, user))",
        "redirect(conn, external: \"https://trusted-site.com\")"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "regex properly excludes comments with negative lookahead" do
      pattern = UnsafeRedirect.pattern()
      
      # Comments ARE properly excluded by regex (using negative lookahead)
      safe_code = [
        "# redirect(conn, external: params[:url])",
        "  # This is a comment: redirect(conn, external: user_input)",
        "    # Never use redirect(conn, external: params[\"url\"])"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for comment: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeRedirect.vulnerability_metadata()
      
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

    test "vulnerability metadata contains redirect-specific information" do
      metadata = UnsafeRedirect.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "phishing")
      assert String.contains?(metadata.business_impact, "reputation")
      assert String.contains?(metadata.technical_impact, "redirect")
      assert String.contains?(metadata.safe_alternatives, "allowlist")
      assert String.contains?(metadata.prevention_tips, "validate")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeRedirect.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has redirect-specific rules" do
      enhancement = UnsafeRedirect.ast_enhancement()
      
      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.user_input_patterns
      assert enhancement.ast_rules.redirect_analysis
      assert enhancement.ast_rules.url_analysis
      assert enhancement.confidence_rules.adjustments.user_input_bonus
    end

    test "AST enhancement handles regex limitations" do
      enhancement = UnsafeRedirect.ast_enhancement()
      
      # These rules handle cases that regex cannot distinguish
      assert enhancement.context_rules.exclude_comments == true,
             "AST should exclude comments that regex matches"
      
      assert enhancement.context_rules.exclude_string_literals == true,
             "AST should exclude string literals that regex matches"
      
      assert enhancement.context_rules.exclude_if_within_conditional == true,
             "AST should exclude code within validation conditionals that regex matches"
      
      # These patterns indicate validation is present
      assert "validate_" in enhancement.context_rules.safe_validation_patterns
      assert "allowed_hosts" in enhancement.context_rules.safe_validation_patterns
      assert "allowlist" in enhancement.context_rules.safe_validation_patterns
      
      # Validation presence should reduce confidence significantly
      assert enhancement.confidence_rules.adjustments.validation_penalty == -0.4
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeRedirect.enhanced_pattern()
      
      assert enhanced.id == "elixir-unsafe-redirect"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeRedirect.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end