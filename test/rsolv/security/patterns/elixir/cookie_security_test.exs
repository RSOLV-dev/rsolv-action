defmodule Rsolv.Security.Patterns.Elixir.CookieSecurityTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.CookieSecurity
  alias Rsolv.Security.Pattern

  describe "cookie_security pattern" do
    test "returns correct pattern structure" do
      pattern = CookieSecurity.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-cookie-security"
      assert pattern.name == "Insecure Cookie Configuration"
      assert pattern.type == :session_management
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-614"
      assert pattern.owasp_category == "A05:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects put_resp_cookie without security flags" do
      pattern = CookieSecurity.pattern()

      test_cases = [
        ~S|put_resp_cookie(conn, "session", value)|,
        ~S|put_resp_cookie(conn, "auth_token", token)|,
        ~S|put_resp_cookie(conn, "user_id", id)|,
        "conn |> put_resp_cookie(\"csrf_token\", csrf)",
        ~S|Plug.Conn.put_resp_cookie(conn, "session_id", session_id)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects put_resp_cookie with only partial security flags" do
      pattern = CookieSecurity.pattern()

      test_cases = [
        ~S|put_resp_cookie(conn, "session", value, secure: true)|,
        ~S|put_resp_cookie(conn, "auth", token, http_only: true)|,
        ~S|put_resp_cookie(conn, "csrf", csrf, same_site: "Strict")|,
        ~S|put_resp_cookie(conn, "user", id, max_age: 3600)|,
        ~S|put_resp_cookie(conn, "data", data, path: "/")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects sensitive cookie names without security flags" do
      pattern = CookieSecurity.pattern()

      test_cases = [
        ~S|put_resp_cookie(conn, "session_token", value)|,
        ~S|put_resp_cookie(conn, "auth_cookie", token)|,
        ~S|put_resp_cookie(conn, "user_session", data)|,
        ~S|put_resp_cookie(conn, "csrf_protection", csrf)|,
        ~S|put_resp_cookie(conn, "authentication", auth)|,
        ~S|put_resp_cookie(conn, "login_token", login)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects cookies with incomplete security configuration" do
      pattern = CookieSecurity.pattern()

      test_cases = [
        ~S|put_resp_cookie(conn, "session", value, secure: true, max_age: 3600)|,
        ~S|put_resp_cookie(conn, "auth", token, http_only: true, path: "/")|,
        ~S|put_resp_cookie(conn, "csrf", csrf, same_site: "Lax", domain: "example.com")|,
        ~S|put_resp_cookie(conn, "user", data, secure: false, http_only: true)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line cookie configurations without all security flags" do
      pattern = CookieSecurity.pattern()

      test_cases = [
        ~S"""
        put_resp_cookie(conn, "session", session_id,
          secure: true,
          max_age: 86400)
        """,
        ~S"""
        put_resp_cookie(conn, "auth_token", token,
          http_only: true,
          path: "/api")
        """,
        """
        conn
        |> put_resp_cookie("csrf", csrf_token,
             same_site: "Strict",
             domain: "localhost")
        """
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect cookies with all required security flags" do
      pattern = CookieSecurity.pattern()

      safe_code = [
        ~S|put_resp_cookie(conn, "session", value, secure: true, http_only: true, same_site: "Strict")|,
        ~S|put_resp_cookie(conn, "auth", token, secure: true, http_only: true, same_site: "Lax")|,
        ~S|Plug.Conn.put_resp_cookie(conn, "csrf", csrf, secure: true, http_only: true, same_site: "None")|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect non-sensitive cookies without flags" do
      pattern = CookieSecurity.pattern()

      safe_code = [
        ~S|put_resp_cookie(conn, "theme", "dark")|,
        ~S|put_resp_cookie(conn, "language", "en")|,
        ~S|put_resp_cookie(conn, "timezone", "UTC")|,
        ~S|put_resp_cookie(conn, "preferences", prefs)|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = CookieSecurity.pattern()

      safe_code = [
        ~S|# put_resp_cookie(conn, "session", value)|,
        ~S|@doc "Use put_resp_cookie with secure flags"|,
        ~S|# TODO: Add secure: true to put_resp_cookie|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = CookieSecurity.vulnerability_metadata()

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

    test "vulnerability metadata contains cookie-specific information" do
      metadata = CookieSecurity.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "session")
      assert String.contains?(metadata.business_impact, "hijacking")
      assert String.contains?(metadata.technical_impact, "cookie")
      assert String.contains?(metadata.safe_alternatives, "secure:")
      assert String.contains?(metadata.prevention_tips, "http_only")
    end

    test "includes AST enhancement rules" do
      enhancement = CookieSecurity.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has cookie-specific rules" do
      enhancement = CookieSecurity.ast_enhancement()

      assert enhancement.context_rules.sensitive_cookie_names
      assert enhancement.context_rules.required_security_flags
      assert enhancement.ast_rules.cookie_analysis
      assert enhancement.ast_rules.security_flags_analysis
      assert enhancement.confidence_rules.adjustments.all_flags_present_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = CookieSecurity.enhanced_pattern()

      assert enhanced.id == "elixir-cookie-security"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = CookieSecurity.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
