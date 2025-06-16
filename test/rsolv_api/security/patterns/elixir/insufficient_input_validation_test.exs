defmodule RsolvApi.Security.Patterns.Elixir.InsufficientInputValidationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.InsufficientInputValidation
  alias RsolvApi.Security.Pattern

  describe "insufficient_input_validation pattern" do
    test "returns correct pattern structure" do
      pattern = InsufficientInputValidation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-insufficient-input-validation"
      assert pattern.name == "Insufficient Input Validation"
      assert pattern.type == :input_validation
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-20"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects cast with sensitive fields without validation" do
      pattern = InsufficientInputValidation.pattern()
      
      test_cases = [
        ~S|cast(user, params, [:email, :password, :role])|,
        ~S|cast(changeset, user_params, [:name, :role, :admin])|,
        ~S|Ecto.Changeset.cast(user, attrs, [:role, :permissions])|,
        ~S|cast(struct, params, [:admin, :is_superuser])|,
        ~S|cast(user_struct, form_data, [:role])|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects cast with permission-related sensitive fields" do
      pattern = InsufficientInputValidation.pattern()
      
      test_cases = [
        ~S|cast(user, params, [:email, :permissions, :name])|,
        ~S|cast(account, attrs, [:title, :admin, :status])|,
        ~S|cast(changeset, data, [:superuser, :email])|,
        ~S|cast(user, input, [:is_admin, :username])|,
        ~S|cast(profile, params, [:verified, :moderator])|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects cast with financial and security sensitive fields" do
      pattern = InsufficientInputValidation.pattern()
      
      test_cases = [
        ~S|cast(payment, params, [:amount, :approved, :name])|,
        ~S|cast(transaction, attrs, [:user_id, :status])|,
        ~S|cast(order, data, [:confirmed, :items])|,
        ~S|cast(account, params, [:balance, :type])|,
        ~S|cast(user, input, [:active, :suspended])|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line cast patterns with sensitive fields" do
      pattern = InsufficientInputValidation.pattern()
      
      test_cases = [
        ~S"""
        cast(user, params, [
          :email,
          :name,
          :role,
          :password
        ])
        """,
        ~S"""
        user
        |> cast(user_params, [:email, :admin])
        """,
        ~S"""
        Ecto.Changeset.cast(
          changeset,
          attrs,
          [:role, :permissions, :name]
        )
        """
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects pipeline syntax with cast and sensitive fields" do
      pattern = InsufficientInputValidation.pattern()
      
      test_cases = [
        "user |> cast(params, [:email, :role])",
        "changeset |> cast(attrs, [:admin, :name])",
        "struct |> Ecto.Changeset.cast(data, [:permissions])",
        "user |> cast(form_params, [:role, :active])",
        "account |> cast(input, [:superuser])"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe validation patterns" do
      pattern = InsufficientInputValidation.pattern()
      
      safe_code = [
        # Proper validation chain
        ~S"""
        user
        |> cast(params, [:email, :name])
        |> validate_required([:email, :name])
        |> validate_format(:email, ~r/@/)
        |> validate_inclusion(:role, ["user", "admin"])
        """,
        # Non-sensitive fields only
        ~S|cast(user, params, [:email, :name, :bio])|,
        ~S|cast(profile, attrs, [:description, :avatar_url])|,
        # Hardcoded safe role assignment
        ~S|put_change(changeset, :role, "user")|,
        # Manual role validation
        ~S"""
        case params["role"] do
          "admin" -> validate_admin_permissions(changeset)
          _ -> put_change(changeset, :role, "user")
        end
        """,
        # Comments and documentation
        ~S|# cast(user, params, [:role]) - dangerous without validation|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = InsufficientInputValidation.pattern()
      
      safe_code = [
        ~S|# cast(user, params, [:role])|,
        ~S|@doc "Use cast/3 carefully with role fields"|,
        ~S|# TODO: Add validation for cast(user, params, [:admin])"|,
        ~S"""
        # Example of unsafe cast:
        # cast(user, params, [:role, :admin])
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = InsufficientInputValidation.vulnerability_metadata()
      
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

    test "vulnerability metadata contains input validation specific information" do
      metadata = InsufficientInputValidation.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "validation")
      assert String.contains?(metadata.business_impact, "authorization")
      assert String.contains?(metadata.technical_impact, "privilege")
      assert String.contains?(metadata.safe_alternatives, "validate")
      assert String.contains?(metadata.prevention_tips, "whitelist")
    end

    test "includes AST enhancement rules" do
      enhancement = InsufficientInputValidation.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has input validation specific rules" do
      enhancement = InsufficientInputValidation.ast_enhancement()
      
      assert enhancement.context_rules.sensitive_fields
      assert enhancement.context_rules.validation_functions
      assert enhancement.ast_rules.changeset_analysis
      assert enhancement.confidence_rules.adjustments.validation_present_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = InsufficientInputValidation.enhanced_pattern()
      
      assert enhanced.id == "elixir-insufficient-input-validation"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = InsufficientInputValidation.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end