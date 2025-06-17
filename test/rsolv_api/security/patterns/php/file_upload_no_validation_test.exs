defmodule RsolvApi.Security.Patterns.Php.FileUploadNoValidationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.FileUploadNoValidation
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = FileUploadNoValidation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-file-upload-no-validation"
      assert pattern.name == "File Upload without Validation"
      assert pattern.severity == :high
      assert pattern.type == :file_upload
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = FileUploadNoValidation.pattern()
      
      assert pattern.cwe_id == "CWE-434"
      assert pattern.owasp_category == "A01:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = FileUploadNoValidation.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches move_uploaded_file with direct name usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);|,
        ~S|move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/' . $_FILES['upload']['name']);|,
        ~S|move_uploaded_file($_FILES["image"]["tmp_name"], "gallery/" . $_FILES["image"]["name"]);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches with variable assignment", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$name = $_FILES['doc']['name']; move_uploaded_file($_FILES['doc']['tmp_name'], "docs/$name");|,
        ~S|$filename = $_FILES['photo']['name']; move_uploaded_file($_FILES['photo']['tmp_name'], $filename);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches with path concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $_FILES['file']['name']);|,
        ~S|move_uploaded_file($_FILES['data']['tmp_name'], dirname(__FILE__) . '/uploads/' . $_FILES['data']['name']);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe code with validation", %{pattern: pattern} do
      safe_code = [
        ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . uniqid() . '.jpg');|,
        ~S|move_uploaded_file($tmpName, $safePath);|,
        ~S|move_uploaded_file($_FILES['file']['tmp_name'], generateSafeFilename());|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "matches array notation variations", %{pattern: pattern} do
      vulnerable_code = [
        ~S|move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);|,
        ~S|move_uploaded_file($_FILES["file"]["tmp_name"], $_FILES["file"]["name"]);|,
        ~S|move_uploaded_file($_FILES['file']["tmp_name"], $_FILES['file']["name"]);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = FileUploadNoValidation.pattern()
      test_cases = FileUploadNoValidation.test_cases()
      
      for test_case <- test_cases.positive do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, test_case.code)),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = FileUploadNoValidation.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = FileUploadNoValidation.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.75
      assert length(enhancement.rules) >= 3
      
      upload_context_rule = Enum.find(enhancement.rules, &(&1.type == "upload_context"))
      assert upload_context_rule
      assert "move_uploaded_file" in upload_context_rule.functions
      
      validation_rule = Enum.find(enhancement.rules, &(&1.type == "validation_checks"))
      assert validation_rule
      assert "pathinfo" in validation_rule.validation_functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = FileUploadNoValidation.pattern()
      assert pattern.owasp_category == "A01:2021"
    end
    
    test "has educational content" do
      desc = FileUploadNoValidation.vulnerability_description()
      assert desc =~ "file upload"
      assert desc =~ "web shell"
      assert desc =~ "validation"
    end
    
    test "provides safe alternatives" do
      examples = FileUploadNoValidation.examples()
      assert Map.has_key?(examples.fixed, "Complete validation")
      assert Map.has_key?(examples.fixed, "Rename uploaded files")
    end
  end
end