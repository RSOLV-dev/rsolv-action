defmodule RsolvApi.Security.Patterns.Javascript.XssDocumentWriteTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.XssDocumentWrite
  alias RsolvApi.Security.Pattern
  
  doctest XssDocumentWrite
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssDocumentWrite.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-document-write"
      assert pattern.name == "Cross-Site Scripting (XSS) via document.write"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
    end
    
    test "pattern detects vulnerable document.write calls" do
      pattern = XssDocumentWrite.pattern()
      
      vulnerable_cases = [
        ~S|document.write(userInput)|,
        ~S|document.write(req.query.name)|,
        ~S|document.write('<div>' + data + '</div>')|,
        ~S|document.write(`<p>${message}</p>`)|,
        ~S|document.write("<script>var x = '" + input + "';</script>")|,
        ~S|document.writeln(untrustedData)|,
        ~S|window.document.write(userContent)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match non-document.write operations" do
      pattern = XssDocumentWrite.pattern()
      
      safe_cases = [
        ~S|console.write(data)|,
        ~S|element.write(content)|,
        ~S|fs.write(buffer)|,
        ~S|response.write(data)|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code), 
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "pattern matches document.write even with encoding (AST will filter)" do
      pattern = XssDocumentWrite.pattern()
      
      # These will match the regex but AST rules will filter them as potentially safe
      encoded_cases = [
        ~S|document.write(encodeHTML(userInput))|,
        ~S|document.write(escape(message))|,
        ~S|document.write(DOMPurify.sanitize(content))|
      ]
      
      for code <- encoded_cases do
        assert Regex.match?(pattern.regex, code), 
          "Should match document.write call (AST will determine safety): #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = XssDocumentWrite.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      
      # Check references include specific document.write resources
      ref_urls = Enum.map(metadata.references, & &1.url)
      assert Enum.any?(ref_urls, &(String.contains?(&1, "document.write") || String.contains?(&1, "document-write")))
    end
    
    test "metadata includes DOM sink information" do
      metadata = XssDocumentWrite.vulnerability_metadata()
      
      # Should mention DOM sink
      assert metadata.description =~ "sink"
      
      # Should have CVE examples
      assert length(metadata.cve_examples) > 0
      assert Enum.any?(metadata.cve_examples, & &1.id =~ "CVE")
    end
    
    test "metadata includes parser blocking warnings" do
      metadata = XssDocumentWrite.vulnerability_metadata()
      
      assert Map.has_key?(metadata, :additional_context)
      context_text = inspect(metadata.additional_context)
      assert context_text =~ "parser" || context_text =~ "blocking"
    end
  end
  
  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert XssDocumentWrite.applies_to_file?("script.js")
      assert XssDocumentWrite.applies_to_file?("app.ts")
      assert XssDocumentWrite.applies_to_file?("src/utils/helper.jsx")
      assert XssDocumentWrite.applies_to_file?("components/widget.tsx")
    end
    
    test "applies to HTML files with embedded JavaScript" do
      html_content = """
      <script>
        document.write('<h1>' + title + '</h1>');
      </script>
      """
      assert XssDocumentWrite.applies_to_file?("index.html", html_content)
    end
    
    test "does not apply to non-JavaScript files" do
      refute XssDocumentWrite.applies_to_file?("style.css")
      refute XssDocumentWrite.applies_to_file?("data.json")
      refute XssDocumentWrite.applies_to_file?("README.md")
      refute XssDocumentWrite.applies_to_file?("image.png")
    end
  end

  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = XssDocumentWrite.ast_enhancement()
      
      assert is_map(enhancement)
      assert Enum.sort(Map.keys(enhancement)) == Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end
    
    test "AST rules target document.write call expressions" do
      enhancement = XssDocumentWrite.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.object == "document"
      assert enhancement.ast_rules.callee.property == "write"
      assert enhancement.ast_rules.callee.alternate_properties == ["writeln"]
      assert enhancement.ast_rules.argument_analysis.has_user_input == true
      assert enhancement.ast_rules.argument_analysis.not_escaped == true
    end
    
    test "context rules exclude test files and legacy code" do
      enhancement = XssDocumentWrite.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/legacy/))
      assert enhancement.context_rules.exclude_if_sanitized == true
      assert enhancement.context_rules.exclude_if_static_only == true
      assert enhancement.context_rules.exclude_if_dev_environment == true
      assert enhancement.context_rules.deprecated_warning == true
    end
    
    test "confidence rules heavily penalize static content and build scripts" do
      enhancement = XssDocumentWrite.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["static_content_only"] == -1.0
      assert enhancement.confidence_rules.adjustments["in_build_script"] == -0.9
      assert enhancement.confidence_rules.adjustments["in_polyfill"] == -0.8
      assert enhancement.confidence_rules.adjustments["user_input_in_write"] == 0.4
      assert enhancement.min_confidence == 0.8
    end
  end

  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = XssDocumentWrite.enhanced_pattern()
      enhancement = XssDocumentWrite.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-xss-document-write"
      assert enhanced.severity == :high
    end
  end
end