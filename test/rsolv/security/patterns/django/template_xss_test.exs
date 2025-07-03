defmodule Rsolv.Security.Patterns.Django.TemplateXssTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Django.TemplateXss

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = TemplateXss.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "django-template-xss"
      assert pattern.name == "Django Template XSS"
      assert pattern.description == "XSS vulnerabilities through unsafe Django template filters"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["python", "html"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = TemplateXss.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :technical_impact)
      assert Map.has_key?(metadata, :business_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      assert Map.has_key?(metadata, :remediation_steps)
      assert Map.has_key?(metadata, :detection_methods)
      assert Map.has_key?(metadata, :prevention_tips)
      
      assert String.contains?(metadata.description, "XSS")
      assert String.contains?(metadata.description, "Django template")
      assert String.contains?(metadata.cve_examples, "CVE-2022-22818")
      assert String.contains?(metadata.safe_alternatives, "escape")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = TemplateXss.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
      
      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.unsafe_filters)
      assert "safe" in ast.context_rules.unsafe_filters
      
      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.safe_filter_with_user_input == +0.9
      
      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.template_analysis.detect_unsafe_filters == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = TemplateXss.enhanced_pattern()
      
      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == TemplateXss.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects safe filter with user input" do
      vulnerable_code = """
      <div class="comment">
          {{ user_comment|safe }}
      </div>
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects autoescape off block" do
      vulnerable_code = """
      {% autoescape off %}
          <h1>{{ user_title }}</h1>
          <p>{{ user_content }}</p>
      {% endautoescape %}
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects mark_safe with request data" do
      vulnerable_code = """
      from django.utils.safestring import mark_safe
      
      def display_message(request):
          message = request.GET.get('message')
          return mark_safe(message)
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects mark_safe with user data" do
      vulnerable_code = """
      def render_bio(user):
          bio_html = user_profile.bio
          return mark_safe(bio_html)
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects safeseq filter" do
      vulnerable_code = """
      <ul>
          {% for item in user_items|safeseq %}
              <li>{{ item }}</li>
          {% endfor %}
      </ul>
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects format_html with user input" do
      vulnerable_code = """
      from django.utils.html import format_html
      
      def show_profile(request):
          name = request.GET.get('name')
          return format_html('<h1>{}</h1>', user_input)
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects safe filter in complex template" do
      vulnerable_code = """
      {% extends "base.html" %}
      {% block content %}
          <div class="post">
              <h2>{{ post.title|safe }}</h2>
              <div class="body">
                  {{ post.content|safe }}
              </div>
          </div>
      {% endblock %}
      """
      
      pattern = TemplateXss.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end
  end

  describe "safe code validation" do
    test "does not flag normal template variables" do
      safe_code = """
      <div class="comment">
          {{ user_comment }}
      </div>
      """
      
      pattern = TemplateXss.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag escaped template variables" do
      safe_code = """
      <div class="comment">
          {{ user_comment|escape }}
      </div>
      """
      
      pattern = TemplateXss.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag safe filter with sanitized content" do
      safe_code = """
      <div class="content">
          {{ bleach.clean(user_content)|safe }}
      </div>
      """
      
      pattern = TemplateXss.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag autoescape on block" do
      safe_code = """
      {% autoescape on %}
          <h1>{{ user_title }}</h1>
          <p>{{ user_content }}</p>
      {% endautoescape %}
      """
      
      pattern = TemplateXss.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag mark_safe with static content" do
      safe_code = """
      from django.utils.safestring import mark_safe
      
      def copyright_notice():
          return mark_safe('<p>&copy; 2025 My Company</p>')
      """
      
      pattern = TemplateXss.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Django template files" do
      assert TemplateXss.applies_to_file?("template.html", ["django"])
      assert TemplateXss.applies_to_file?("index.html", ["django"]) 
      assert TemplateXss.applies_to_file?("views.py", ["django"])
      assert TemplateXss.applies_to_file?("templatetags/custom_filters.py", ["django"])
    end

    test "infers Django from file paths" do
      assert TemplateXss.applies_to_file?("templates/base.html", [])
      assert TemplateXss.applies_to_file?("app/templates/index.html", [])
      assert TemplateXss.applies_to_file?("myapp/views.py", [])
    end

    test "does not apply to non-Python/HTML files" do
      refute TemplateXss.applies_to_file?("style.css", ["django"])
      refute TemplateXss.applies_to_file?("script.js", ["django"])
      refute TemplateXss.applies_to_file?("data.json", ["django"])
    end

    test "does not apply to test files" do
      refute TemplateXss.applies_to_file?("test_views.py", ["django"])
      refute TemplateXss.applies_to_file?("tests.py", ["django"])
      refute TemplateXss.applies_to_file?("test_templates/test.html", ["django"])
    end
  end
end