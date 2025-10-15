defmodule RsolvWeb.Validators.EmailValidatorTest do
  use ExUnit.Case, async: true
  alias RsolvWeb.Validators.EmailValidator

  describe "is_valid?/1" do
    test "returns true for valid emails" do
      assert EmailValidator.is_valid?("user@example.com")
      assert EmailValidator.is_valid?("test.user@example.com")
      assert EmailValidator.is_valid?("user+tag@example.co.uk")
      assert EmailValidator.is_valid?("123@example.com")
    end

    test "returns false for invalid emails" do
      refute EmailValidator.is_valid?("")
      refute EmailValidator.is_valid?(nil)
      refute EmailValidator.is_valid?("notanemail")
      refute EmailValidator.is_valid?("user@")
      refute EmailValidator.is_valid?("@example.com")
      refute EmailValidator.is_valid?("user@example")
      refute EmailValidator.is_valid?("user@@example.com")
      refute EmailValidator.is_valid?("user@example..com")
    end
  end

  describe "validate_with_feedback/1" do
    test "returns ok for valid emails" do
      assert {:ok, "Valid email"} = EmailValidator.validate_with_feedback("user@example.com")
    end

    test "returns error with nil for empty input" do
      assert {:error, nil} = EmailValidator.validate_with_feedback("")
      assert {:error, nil} = EmailValidator.validate_with_feedback(nil)
    end

    test "returns specific error for short emails" do
      assert {:error, "Email is too short"} = EmailValidator.validate_with_feedback("a@b")
    end

    test "returns error for missing @" do
      assert {:error, "Email must contain @"} =
               EmailValidator.validate_with_feedback("userexample.com")
    end

    test "returns error for invalid format" do
      assert {:error, "Invalid email format"} = EmailValidator.validate_with_feedback("user@")
    end

    test "catches common TLD typos" do
      assert {:error, "Did you mean .com?"} =
               EmailValidator.validate_with_feedback("user@example.con")

      assert {:error, "Did you mean .com?"} =
               EmailValidator.validate_with_feedback("user@example.cmo")

      assert {:error, "Did you mean .com?"} =
               EmailValidator.validate_with_feedback("user@example.xom")

      assert {:error, "Did you mean .net?"} =
               EmailValidator.validate_with_feedback("user@example.ney")

      assert {:error, "Did you mean .org?"} =
               EmailValidator.validate_with_feedback("user@example.ogr")
    end

    test "catches consecutive dots" do
      assert {:error, "Email contains consecutive dots"} =
               EmailValidator.validate_with_feedback("user@example..com")
    end

    test "catches leading dot" do
      assert {:error, "Email can't start with a dot"} =
               EmailValidator.validate_with_feedback(".user@example.com")
    end

    test "validates domain format" do
      assert {:error, "Domain contains consecutive hyphens"} =
               EmailValidator.validate_with_feedback("user@ex--ample.com")

      assert {:error, "Domain can't start with a hyphen"} =
               EmailValidator.validate_with_feedback("user@-example.com")

      assert {:error, "Domain can't end with a hyphen"} =
               EmailValidator.validate_with_feedback("user@example-.com")

      assert {:error, "Domain can't start with a dot"} =
               EmailValidator.validate_with_feedback("user@.example.com")

      assert {:error, "Domain can't end with a dot"} =
               EmailValidator.validate_with_feedback("user@example.com.")
    end

    test "validates TLD" do
      assert {:error, "Domain must include a TLD (e.g., .com, .org)"} =
               EmailValidator.validate_with_feedback("user@example")

      assert {:error, "TLD is too short"} =
               EmailValidator.validate_with_feedback("user@example.c")

      assert {:error, "TLD should only contain letters"} =
               EmailValidator.validate_with_feedback("user@example.123")
    end
  end

  describe "suggest_correction/1" do
    test "suggests correction for common TLD typos" do
      assert "user@example.com" = EmailValidator.suggest_correction("user@example.con")
      assert "user@example.com" = EmailValidator.suggest_correction("user@example.cmo")
      assert "user@example.com" = EmailValidator.suggest_correction("user@example.xom")
      assert "user@example.net" = EmailValidator.suggest_correction("user@example.ney")
      assert "user@example.org" = EmailValidator.suggest_correction("user@example.ogr")
    end

    test "fixes double @ symbol" do
      assert "user@example.com" = EmailValidator.suggest_correction("user@@example.com")
      assert "user@example.com" = EmailValidator.suggest_correction("user@test@example.com")
    end

    test "fixes consecutive dots" do
      assert "user@example.com" = EmailValidator.suggest_correction("user@example..com")
    end

    test "fixes trailing dot" do
      assert "user@example.com" = EmailValidator.suggest_correction("user@example.com.")
    end

    test "returns original if no correction possible" do
      assert "notanemail" = EmailValidator.suggest_correction("notanemail")
    end

    test "returns original if email is already valid" do
      assert "user@example.com" = EmailValidator.suggest_correction("user@example.com")
    end
  end
end
