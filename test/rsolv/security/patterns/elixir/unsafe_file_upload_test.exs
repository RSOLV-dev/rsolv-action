defmodule Rsolv.Security.Patterns.Elixir.UnsafeFileUploadTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Elixir.UnsafeFileUpload
  alias Rsolv.Security.Pattern

  describe "unsafe_file_upload pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeFileUpload.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-file-upload"
      assert pattern.name == "Unsafe File Upload"
      assert pattern.type == :file_upload
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-434"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects File.write with user-controlled filenames" do
      pattern = UnsafeFileUpload.pattern()
      
      test_cases = [
        ~S|File.write!("/uploads/#{upload.filename}", upload.content)|,
        ~S|File.write("/uploads/#{params.filename}", data)|,
        ~S|File.write!("/uploads/" <> upload.filename, content)|,
        ~S|File.write(Path.join(dir, upload.filename), data)|,
        ~S|File.write!(upload_path <> upload.filename, content)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects File.write with interpolated paths" do
      pattern = UnsafeFileUpload.pattern()
      
      test_cases = [
        ~S|File.write!("#{base_path}/#{upload.filename}", content)|,
        ~S|File.write("#{upload_dir}/#{params[:filename]}", data)|,
        ~S|File.write!("uploads/#{upload.filename}", upload.content)|,
        ~S|File.write("/tmp/#{filename}", data)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects File.write with concatenated user input" do
      pattern = UnsafeFileUpload.pattern()
      
      test_cases = [
        ~S|File.write!("/uploads/" <> params["filename"], content)|,
        ~S|File.write(upload_dir <> "/" <> upload.filename, data)|,
        ~S|File.write!(base_dir <> params.filename, content)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Path.join with unsafe filename" do
      pattern = UnsafeFileUpload.pattern()
      
      test_cases = [
        ~S|File.write!(Path.join("/uploads", upload.filename), content)|,
        ~S|File.write(Path.join(upload_dir, params.filename), data)|,
        ~S|File.write!(Path.join(["uploads", upload.filename]), content)|,
        ~S|File.write(Path.join([base_dir, params[:filename]]), data)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line file upload patterns" do
      pattern = UnsafeFileUpload.pattern()
      
      test_cases = [
        ~S"""
        File.write!(
          "/uploads/#{upload.filename}",
          upload.content
        )
        """,
        ~S"""
        path = Path.join(upload_dir, upload.filename)
        File.write!(path, content)
        """,
        ~S"""
        File.write!(
          upload_path <> upload.filename,
          data
        )
        """
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe file upload patterns" do
      pattern = UnsafeFileUpload.pattern()
      
      safe_code = [
        # Sanitized filename
        ~S"""
        if Path.extname(upload.filename) in [".jpg", ".png"] do
          safe_name = "#{UUID.generate()}_#{Path.basename(upload.filename)}"
          File.write!(Path.join(upload_dir, safe_name), upload.content)
        end
        """,
        # Hardcoded safe paths
        ~S|File.write!("/uploads/safe_file.jpg", content)|,
        ~S|File.write("uploads/config.json", data)|,
        # UUID-based filenames
        ~S|File.write!(Path.join(upload_dir, UUID.generate()), content)|,
        # Whitelist validation
        ~S"""
        validated_filename = validate_filename(upload.filename)
        File.write!(Path.join(upload_dir, validated_filename), content)
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = UnsafeFileUpload.pattern()
      
      safe_code = [
        ~S|# File.write!("/uploads/#{upload.filename}", content)|,
        ~S|@doc "Use File.write! with safe filenames"|,
        ~S|# TODO: Validate upload.filename before File.write|,
        ~S"""
        # Example of unsafe file upload:
        # File.write!("/uploads/#{upload.filename}", content)
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeFileUpload.vulnerability_metadata()
      
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

    test "vulnerability metadata contains file upload specific information" do
      metadata = UnsafeFileUpload.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "upload")
      assert String.contains?(metadata.business_impact, "execution")
      assert String.contains?(metadata.technical_impact, "file")
      assert String.contains?(metadata.safe_alternatives, "validate")
      assert String.contains?(metadata.prevention_tips, "sanitize")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeFileUpload.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has file upload specific rules" do
      enhancement = UnsafeFileUpload.ast_enhancement()
      
      assert enhancement.context_rules.file_write_functions
      assert enhancement.context_rules.user_input_sources
      assert enhancement.ast_rules.file_path_analysis
      assert enhancement.ast_rules.user_input_validation
      assert enhancement.confidence_rules.adjustments.sanitized_input_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeFileUpload.enhanced_pattern()
      
      assert enhanced.id == "elixir-unsafe-file-upload"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeFileUpload.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end