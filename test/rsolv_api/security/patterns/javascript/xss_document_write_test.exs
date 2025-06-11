defmodule RsolvApi.Security.Patterns.Javascript.XssDocumentWriteTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.XssDocumentWrite
  alias RsolvApi.Security.Pattern
  
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
end