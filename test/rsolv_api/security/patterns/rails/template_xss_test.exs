defmodule RsolvApi.Security.Patterns.Rails.TemplateXssTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.TemplateXss
  alias RsolvApi.Security.Pattern

  describe "template_xss pattern" do
    test "returns correct pattern structure" do
      pattern = TemplateXss.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-template-xss"
      assert pattern.name == "Rails Template XSS"
      assert pattern.type == :xss
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects raw helper with user input" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "<%= raw params[:content] %>",
        "<%= raw user_input %>",
        "<%= raw @user.bio %>",
        "<%= raw request.params[:description] %>",
        "<%= raw params[:html_content] %>",
        "<%= raw @post.content %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects html_safe method with user input" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "<%= params[:content].html_safe %>",
        "<%= user_input.html_safe %>",
        "<%= @user.description.html_safe %>",
        "<%= request.params[:bio].html_safe %>",
        "<%= params[:html].html_safe %>",
        "content = params[:text].html_safe"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects unescaped ERB output" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "<%== params[:content] %>",
        "<%== user_input %>",
        "<%== @user.bio %>",
        "<%== request.params[:description] %>"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects content_tag with raw" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "content_tag :div, raw(params[:content])",
        "content_tag(:p, raw(user_input))",
        "content_tag 'span', raw(@user.bio)",
        "content_tag :h1, raw(params[:title]), class: 'header'"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects link_to with raw" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "link_to raw(params[:link_text]), '/path'",
        "link_to raw(user_input), user_path",
        "link_to raw(@user.name), profile_path",
        "link_to raw(params[:title]), post_path(@post)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects link_to with html_safe" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "link_to params[:text].html_safe, '/path'",
        "link_to user_input.html_safe, user_path",
        "link_to @user.name.html_safe, profile_path",
        "link_to params[:link_content].html_safe, external_url"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects Haml unescaped output" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "!= params[:content]",
        "!= user_input",
        "!= @user.bio",
        "!= request.params[:description]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects unsafe link_to href vectors" do
      pattern = TemplateXss.pattern()
      
      # Based on OWASP Rails cheat sheet findings
      vulnerable_code = [
        "link_to 'Website', @user.website",
        "link_to 'Link', params[:url]",
        "link_to 'External', user_input",
        "link_to 'Click here', request.params[:href]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects complex XSS patterns" do
      pattern = TemplateXss.pattern()
      
      vulnerable_code = [
        "render html: params[:content].html_safe",
        "button_to raw(params[:button_text]), '/submit'",
        "form_tag url_for(params[:action].html_safe)",
        "concat raw(user_content)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe template usage" do
      pattern = TemplateXss.pattern()
      
      safe_code = [
        "<%= sanitize(params[:content]) %>",
        "<%= strip_tags(user_input) %>",
        "<%= h(params[:text]) %>",
        "<%= escape_once(@user.bio) %>",
        "<%= params[:content] %>",  # Default Rails escaping
        "link_to 'Safe Link', '/static/path'",
        "link_to sanitize(params[:text]), user_path",
        "content_tag :div, sanitize(params[:content])",
        "# <%= raw params[:content] %> - commented out",
        "raw('static content')",  # Static content
        "'raw text content'.html_safe"  # Static string
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = TemplateXss.vulnerability_metadata()
      
      assert metadata.description
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

    test "vulnerability metadata contains XSS specific information" do
      metadata = TemplateXss.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "cross-site scripting")
      assert String.contains?(String.downcase(metadata.attack_vectors), "script")
      assert String.contains?(metadata.business_impact, "data theft")
      assert String.contains?(metadata.safe_alternatives, "sanitize")
      assert String.contains?(String.downcase(metadata.prevention_tips), "escape")
      
      # Check for CVE references found in research
      cve_examples_text = Enum.join(metadata.cve_examples, " ")
      assert String.contains?(cve_examples_text, "CVE-2015-3226")
    end

    test "includes AST enhancement rules" do
      enhancement = TemplateXss.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has XSS specific rules" do
      enhancement = TemplateXss.ast_enhancement()
      
      assert enhancement.context_rules.dangerous_methods
      assert enhancement.context_rules.user_input_sources
      assert enhancement.ast_rules.output_analysis
      assert enhancement.confidence_rules.adjustments.raw_or_html_safe_usage
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = TemplateXss.enhanced_pattern()
      
      assert enhanced.id == "rails-template-xss"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = TemplateXss.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert TemplateXss.applies_to_file?("app/views/users/show.html.erb", nil)
      assert TemplateXss.applies_to_file?("app/controllers/users_controller.rb", nil)
      assert TemplateXss.applies_to_file?("app/helpers/application_helper.rb", ["rails"])
      refute TemplateXss.applies_to_file?("test.js", nil)
      refute TemplateXss.applies_to_file?("script.py", nil)
    end

    test "applies to ruby files with Rails framework" do
      assert TemplateXss.applies_to_file?("helper.rb", ["rails"])
      refute TemplateXss.applies_to_file?("helper.rb", ["sinatra"])
      refute TemplateXss.applies_to_file?("helper.py", ["rails"])
    end
  end
end