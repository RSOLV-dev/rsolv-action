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
      assert pattern.default_tier == :public
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

    test "does not detect redirect with validation" do
      pattern = UnsafeRedirect.pattern()
      
      safe_code = [
        "if URI.parse(url).host in @allowed_hosts do\n  redirect(conn, external: url)\nelse\n  redirect(conn, to: Routes.home_path(conn, :index))\nend",
        "case validate_redirect_url(params[:url]) do\n  {:ok, safe_url} -> redirect(conn, external: safe_url)\n  :error -> redirect(conn, to: \"/\")\nend"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or strings" do
      pattern = UnsafeRedirect.pattern()
      
      safe_code = [
        "# redirect(conn, external: params[:url])",
        "\"Example: redirect(conn, external: user_input)\"",
        ~S|"Documentation: redirect(conn, external: #{variable})"|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
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