defmodule Rsolv.Security.Patterns.Ruby.XssErbRawTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.XssErbRaw
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssErbRaw.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-xss-erb-raw"
      assert pattern.name == "XSS in ERB Templates"
      assert pattern.severity == :high
      assert pattern.type == :xss
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XssErbRaw.pattern()
      
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = XssErbRaw.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 6
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XssErbRaw.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches raw with user input", %{pattern: pattern} do
      vulnerable_code = [
        "<%= raw params[:content] %>",
        "<%= raw user_input %>",
        "<%= raw params['message'] %>",
        "<%= raw request.params[:description] %>",
        "<%= raw @user %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches html_safe with user input", %{pattern: pattern} do
      vulnerable_code = [
        "<%= params[:content].html_safe %>",
        "<%= user_data.html_safe %>",
        "<%= params['text'].html_safe %>",
        "<%= @comment.body.html_safe %>",
        "<%= request.params[:html].html_safe %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches double equals ERB syntax", %{pattern: pattern} do
      vulnerable_code = [
        "<%== params[:content] %>",
        "<%== user_input %>",
        "<%== @post.description %>",
        "<%== params['html_content'] %>",
        "<%== request.params[:message] %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches concatenation with html_safe", %{pattern: pattern} do
      vulnerable_code = [
        "<%= (\"<div>\" + params[:content] + \"</div>\").html_safe %>",
        "<%= (prefix + user_input + suffix).html_safe %>",
        "<%= (\"<span>\" + params['name'] + \"</span>\").html_safe %>",
        "<%= (header + params[:bio] + footer).html_safe %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches string interpolation with html_safe", %{pattern: pattern} do
      vulnerable_code = [
        "<%= \"<div>\#{params[:content]}</div>\".html_safe %>",
        "<%= \"Hello \#{user_input}!\".html_safe %>",
        "<%= \"<p>\#{params[:title]}</p>\".html_safe %>",
        "<%= \"Message: \#{params['text']}\".html_safe %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches method chaining with html_safe", %{pattern: pattern} do
      vulnerable_code = [
        "<%= params[:content].strip.html_safe %>",
        "<%= user_input.downcase.html_safe %>",
        "<%= @comment.body.truncate(100).html_safe %>",
        "<%= params['description'].gsub(/\\n/, '<br>').html_safe %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe ERB usage", %{pattern: pattern} do
      safe_code = [
        "<%= params[:content] %>",
        "<%= sanitize(params[:content]) %>",
        "<%= h(user_input) %>",
        "<%= html_escape(params[:message]) %>",
        "<%= strip_tags(params[:description]) %>",
        "<%= raw \"<div>Static HTML</div>\" %>",
        "<%= escape_html(user_input) %>"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = "# <%= raw params[:content] %> # Commented out XSS vulnerability"
      
      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XssErbRaw.vulnerability_metadata()
      
      assert metadata.description =~ "XSS"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes CVE examples from research" do
      metadata = XssErbRaw.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2024-26143"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2024-39308"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2015-3226"))
    end
    
    test "includes proper security references" do
      metadata = XssErbRaw.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XssErbRaw.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes ERB template analysis" do
      enhancement = XssErbRaw.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "ERBNode"
      assert enhancement.ast_rules.erb_analysis.unsafe_methods
      assert enhancement.ast_rules.erb_analysis.double_equals_syntax
    end
    
    test "has user input source detection" do
      enhancement = XssErbRaw.ast_enhancement()
      
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "user_input" in enhancement.ast_rules.user_input_analysis.input_sources
    end
    
    test "includes sanitization detection" do
      enhancement = XssErbRaw.ast_enhancement()
      
      assert enhancement.ast_rules.sanitization_analysis.check_sanitization_methods
      assert enhancement.ast_rules.sanitization_analysis.safe_methods
      assert enhancement.ast_rules.sanitization_analysis.escape_methods
    end
  end
end