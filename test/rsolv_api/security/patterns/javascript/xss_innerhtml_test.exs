defmodule RsolvApi.Security.Patterns.Javascript.XssInnerhtmlTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.XssInnerhtml
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssInnerhtml.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-innerhtml"
      assert pattern.name == "Cross-Site Scripting (XSS) via innerHTML"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
    end
    
    test "pattern detects vulnerable innerHTML assignments" do
      pattern = XssInnerhtml.pattern()
      
      vulnerable_cases = [
        ~S|element.innerHTML = userInput|,
        ~S|document.getElementById('content').innerHTML = data|,
        ~S|div.innerHTML = req.query.search|,
        ~S|container.innerHTML = '<div>' + untrustedData + '</div>'|,
        ~S|el.innerHTML = `<p>${userMessage}</p>`|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match non-innerHTML assignments" do
      pattern = XssInnerhtml.pattern()
      
      safe_cases = [
        ~S|element.innerText = userInput|,
        ~S|element.textContent = data|,
        ~S|container.setHTML(untrustedData)|,  # New Sanitizer API
        ~S|element.insertAdjacentHTML('beforeend', sanitized)|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code), 
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "pattern matches innerHTML even with safe wrappers (AST will filter)" do
      pattern = XssInnerhtml.pattern()
      
      # These will match the regex but AST rules will filter them as safe
      wrapped_safe_cases = [
        ~S|div.innerHTML = DOMPurify.sanitize(userInput)|,
        ~S|el.innerHTML = escapeHtml(userMessage)|
      ]
      
      for code <- wrapped_safe_cases do
        assert Regex.match?(pattern.regex, code), 
          "Should match innerHTML assignment (AST will determine safety): #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = XssInnerhtml.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      
      # Check references include OWASP DOM XSS
      ref_urls = Enum.map(metadata.references, & &1.url)
      assert Enum.any?(ref_urls, &String.contains?(&1, "DOM_based_XSS"))
    end
    
    test "metadata includes DOM-specific information" do
      metadata = XssInnerhtml.vulnerability_metadata()
      
      # Should mention DOM-based XSS
      assert metadata.description =~ "DOM"
      
      # Should have attack vectors with event handlers
      attack_vector_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_vector_text =~ "onerror" || attack_vector_text =~ "onload"
    end
    
    test "metadata includes safe alternatives" do
      metadata = XssInnerhtml.vulnerability_metadata()
      
      assert Map.has_key?(metadata, :safe_alternatives)
      alternatives_text = Enum.join(metadata.safe_alternatives, " ")
      assert alternatives_text =~ "innerText"
      assert alternatives_text =~ "textContent"
    end
  end
  
  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert XssInnerhtml.applies_to_file?("app.js")
      assert XssInnerhtml.applies_to_file?("index.ts")
      assert XssInnerhtml.applies_to_file?("src/components/widget.jsx")
      assert XssInnerhtml.applies_to_file?("pages/home.tsx")
    end
    
    test "applies to HTML files with embedded JavaScript" do
      html_content = """
      <script>
        document.getElementById('output').innerHTML = userInput;
      </script>
      """
      assert XssInnerhtml.applies_to_file?("index.html", html_content)
    end
    
    test "does not apply to non-JavaScript files" do
      refute XssInnerhtml.applies_to_file?("style.css")
      refute XssInnerhtml.applies_to_file?("data.json")
      refute XssInnerhtml.applies_to_file?("README.md")
    end
  end
end