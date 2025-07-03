defmodule Rsolv.Security.Patterns.Rails.ErbInjectionTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Rails.ErbInjection
  alias Rsolv.Security.Pattern

  describe "erb_injection pattern" do
    test "returns correct pattern structure" do
      pattern = ErbInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-erb-injection"
      assert pattern.name == "ERB Template Injection"
      assert pattern.type == :template_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects ERB.new with user input" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "ERB.new(params[:template]).result",
        "ERB.new(params[:user_template]).result(binding)",
        "ERB.new(request.params[:template]).result",
        "template = ERB.new(params[:code])",
        "ERB.new(user_input).result",
        "erb = ERB.new(params[:erb_template])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects ActionView::Template.new with user input" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "ActionView::Template.new(params[:template], \"template\")",
        "ActionView::Template.new(params[:source], \"inline\")",
        "template = ActionView::Template.new(params[:erb_code], \"view\")",
        "ActionView::Template.new(request.params[:template_source])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects render inline with user input" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "render inline: params[:template]",
        "render inline: params[:erb_template], type: :erb",
        "render inline: request.params[:template]",
        "render inline: user_template, locals: { data: @data }",
        "render :inline => params[:template_code]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects render template with interpolated user input" do
      pattern = ErbInjection.pattern()
      
      # Based on CVE-2016-2098 and research findings
      vulnerable_code = [
        "render template: \"\#{params[:template]}\"",
        "render template: \"users/\#{params[:view]}\"",
        "render template: \"\#{request.params[:template_name]}\"",
        "render :template => \"\#{params[:view_name]}\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects render partial with user input" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "render partial: params[:partial_name]",
        "render partial: params[:view], locals: { data: @data }",
        "render :partial => params[:template]",
        "render partial: request.params[:partial]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects Haml template injection" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "Haml::Engine.new(params[:haml_template]).render",
        "Haml::Engine.new(user_input).render(self)",
        "Haml.render(params[:template])",
        "engine = Haml::Engine.new(params[:haml_code])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects CVE-2016-2098 vulnerability patterns" do
      pattern = ErbInjection.pattern()
      
      # Based on CVE-2016-2098: RCE via render inline
      vulnerable_code = [
        "render inline: params[:template]",
        "render :inline => user_template",
        "render inline: \"<%= \#{params[:code]} %>\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect CVE-2016-2098 pattern: #{code}"
      end
    end

    test "detects complex template injection patterns" do
      pattern = ErbInjection.pattern()
      
      vulnerable_code = [
        "erb_template = ERB.new(\"<%= \#{params[:code]} %>\")",
        "render plain: erb_template.result",
        "template_content = params[:template_source]\\nERB.new(template_content).result"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe template usage" do
      pattern = ErbInjection.pattern()
      
      safe_code = [
        "render template: \"users/show\"",
        "render partial: \"shared/header\"",
        "ERB.new(File.read(\"template.erb\")).result",
        "render inline: \"<%= @user.name %>\", locals: { user: @user }",
        "render template: \"users/show\", locals: { data: params[:data] }",
        "Haml::Engine.new(File.read(\"view.haml\")).render",
        "render plain: \"Hello World\"",
        "# ERB.new(params[:template]) - commented out vulnerability",
        "ActionView::Template.new(File.read(template_path), \"view\")"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = ErbInjection.vulnerability_metadata()
      
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

    test "vulnerability metadata contains template injection specific information" do
      metadata = ErbInjection.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "template injection")
      assert String.contains?(String.downcase(metadata.attack_vectors), "erb")
      assert String.contains?(metadata.business_impact, "remote code execution")
      assert String.contains?(metadata.safe_alternatives, "static template")
      assert String.contains?(String.downcase(metadata.prevention_tips), "sanitize")
      
      # Check for CVE references found in research
      cve_examples_text = Enum.join(metadata.cve_examples, " ")
      assert String.contains?(cve_examples_text, "CVE-2016-2098")
      assert String.contains?(cve_examples_text, "CVE-2020-8163")
    end

    test "includes AST enhancement rules" do
      enhancement = ErbInjection.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has template injection specific rules" do
      enhancement = ErbInjection.ast_enhancement()
      
      assert enhancement.context_rules.template_engines
      assert enhancement.context_rules.dangerous_patterns
      assert enhancement.ast_rules.template_analysis
      assert enhancement.confidence_rules.adjustments.user_input_in_template
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = ErbInjection.enhanced_pattern()
      
      assert enhanced.id == "rails-erb-injection"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = ErbInjection.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert ErbInjection.applies_to_file?("app/controllers/users_controller.rb", nil)
      assert ErbInjection.applies_to_file?("app/views/users/show.html.erb", nil)
      assert ErbInjection.applies_to_file?("lib/template_service.rb", ["rails"])
      refute ErbInjection.applies_to_file?("test.js", nil)
      refute ErbInjection.applies_to_file?("script.py", nil)
    end

    test "applies to ruby files with Rails framework" do
      assert ErbInjection.applies_to_file?("service.rb", ["rails"])
      refute ErbInjection.applies_to_file?("service.rb", ["sinatra"])
      refute ErbInjection.applies_to_file?("service.py", ["rails"])
    end
  end
end