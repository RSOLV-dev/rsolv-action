defmodule Rsolv.Security.Patterns.Elixir.ExposedErrorDetailsTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.ExposedErrorDetails
  alias Rsolv.Security.Pattern

  describe "exposed_error_details pattern" do
    test "returns correct pattern structure" do
      pattern = ExposedErrorDetails.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-exposed-error-details"
      assert pattern.name == "Exposed Error Details"
      assert pattern.type == :information_disclosure
      assert pattern.severity == :low
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-209"
      assert pattern.owasp_category == "A05:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects send_resp with error interpolation" do
      pattern = ExposedErrorDetails.pattern()

      test_cases = [
        ~S|send_resp(conn, 500, "Database error: #{error.message}")|,
        ~S|send_resp(conn, 400, "Validation failed: #{inspect(error)}")|,
        ~S|send_resp(conn, 500, "Internal error: #{error}")|,
        ~S|send_resp(conn, 404, "Resource not found: #{exception.message}")|,
        ~S|send_resp(conn, 422, "Processing error: #{error_details}")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects put_resp with error interpolation" do
      pattern = ExposedErrorDetails.pattern()

      test_cases = [
        ~S|put_resp(conn, 500, "Error occurred: #{error.message}")|,
        ~S|put_resp(conn, 400, "Bad request: #{inspect(exception)}")|,
        ~S|put_resp(conn, 503, "Service unavailable: #{error}")|,
        "conn |> put_resp(500, \"Database error: \#{db_error}\")"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Phoenix.Controller error functions with interpolation" do
      pattern = ExposedErrorDetails.pattern()

      test_cases = [
        ~S|Phoenix.Controller.json(conn, %{error: "Failed: #{error.message}"})|,
        ~S|Phoenix.Controller.text(conn, "Error: #{inspect(exception)}")|,
        ~S|json(conn, %{message: "Database error: #{error}"})|,
        ~S|text(conn, "Validation error: #{changeset.errors}")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Logger functions with interpolated errors in response context" do
      pattern = ExposedErrorDetails.pattern()

      test_cases = [
        ~S"""
        Logger.error("Database error: #{error.message}")
        send_resp(conn, 500, "Error: #{error.message}")
        """,
        ~S"""
        Logger.warn("Processing failed: #{inspect(error)}")
        json(conn, %{error: "Failed: #{inspect(error)}"})
        """,
        ~S|render(conn, "error.html", message: "Error: #{error.message}")|,
        ~S|render(conn, "error.json", error: "Failed: #{inspect(exception)}")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line error response patterns" do
      pattern = ExposedErrorDetails.pattern()

      test_cases = [
        ~S"""
        send_resp(
          conn, 
          500, 
          "Database error: #{error.message}"
        )
        """,
        ~S"""
        conn
        |> put_status(500)
        |> json(%{error: "Processing failed: #{inspect(error)}"})
        """,
        ~S"""
        Phoenix.Controller.json(
          conn,
          %{message: "Error occurred: #{error}"}
        )
        """
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe error handling patterns" do
      pattern = ExposedErrorDetails.pattern()

      safe_code = [
        # Generic error messages
        ~S|send_resp(conn, 500, "Internal server error")|,
        ~S|json(conn, %{error: "Something went wrong"})|,
        ~S|render(conn, "error.html", message: "An error occurred")|,
        # Logging without exposure
        ~S"""
        Logger.error("Database error: #{inspect(error)}")
        send_resp(conn, 500, "Internal server error")
        """,
        # User-friendly messages
        ~S|text(conn, "Please try again later")|,
        ~S|put_resp(conn, 400, "Invalid request")|,
        # Comments
        ~S|# send_resp(conn, 500, "Error: #{error.message}")|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = ExposedErrorDetails.pattern()

      safe_code = [
        ~S|# send_resp(conn, 500, "Error: #{error.message}")|,
        ~S|@doc "Never expose error details: send_resp(conn, 500, error)"|,
        ~S|# TODO: Fix error exposure in send_resp(conn, 500, "#{error}")"|,
        ~S"""
        # Bad example:
        # send_resp(conn, 500, "Database error: #{error}")
        """
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = ExposedErrorDetails.vulnerability_metadata()

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

    test "vulnerability metadata contains error disclosure specific information" do
      metadata = ExposedErrorDetails.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "error")
      assert String.contains?(metadata.business_impact, "disclosure")
      assert String.contains?(metadata.technical_impact, "information")
      assert String.contains?(metadata.safe_alternatives, "generic")
      assert String.contains?(metadata.prevention_tips, "messages")
    end

    test "includes AST enhancement rules" do
      enhancement = ExposedErrorDetails.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has error disclosure specific rules" do
      enhancement = ExposedErrorDetails.ast_enhancement()

      assert enhancement.context_rules.response_functions
      assert enhancement.context_rules.error_interpolation_patterns
      assert enhancement.ast_rules.error_context_analysis
      assert enhancement.confidence_rules.adjustments.generic_message_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = ExposedErrorDetails.enhanced_pattern()

      assert enhanced.id == "elixir-exposed-error-details"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = ExposedErrorDetails.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
