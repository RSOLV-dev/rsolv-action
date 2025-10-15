defmodule Rsolv.Security.Patterns.Django.TemplateInjectionTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Django.TemplateInjection

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = TemplateInjection.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "django-template-injection"
      assert pattern.name == "Django Template Injection"
      assert pattern.description == "Server-side template injection allowing code execution"
      assert pattern.type == :template_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = TemplateInjection.vulnerability_metadata()

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

      assert String.contains?(metadata.description, "template injection")
      assert String.contains?(metadata.description, "code execution")
      assert String.contains?(metadata.cve_examples, "CVE-")
      assert String.contains?(metadata.safe_alternatives, "static template names")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = TemplateInjection.ast_enhancement()

      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)

      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.template_functions)
      assert "render_to_string" in ast.context_rules.template_functions

      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.user_controlled_template_name == +0.9

      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.template_analysis.detect_dynamic_templates == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = TemplateInjection.enhanced_pattern()

      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == TemplateInjection.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects render_to_string with request data" do
      vulnerable_code = """
      from django.template.loader import render_to_string

      def generate_report(request):
          template_name = request.GET.get('template')
          context = {'data': user_data}
          return render_to_string(template_name, context)
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects Template constructor with user input" do
      vulnerable_code = """
      from django.template import Template, Context

      def custom_template(request):
          template_string = request.POST.get('template_code')
          template = Template(template_string)
          return template.render(Context({'user': request.user}))
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects render with user-controlled template path" do
      vulnerable_code = """
      def display_report(request):
          report_type = request.GET['report_type']
          template_path = f"reports/{report_type}.html"
          return render(request, template_path, context)
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects get_template with user input" do
      vulnerable_code = """
      from django.template.loader import get_template

      def load_user_template(request):
          template_name = request.POST.get('template_name')
          template = get_template(template_name)
          return HttpResponse(template.render(context))
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects template.render with request data in first argument" do
      vulnerable_code = """
      def process_template(request):
          user_template = request.GET['tpl']
          t = loader.get_template(user_template)
          html = t.render(request.GET)
          return HttpResponse(html)
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects from_string with user input" do
      vulnerable_code = """
      from django.template import engines

      def custom_render(request):
          template_code = request.body.decode('utf-8')
          django_engine = engines['django']
          template = django_engine.from_string(template_code)
          return template.render()
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects complex template injection pattern" do
      vulnerable_code = """
      def generate_invoice(request):
          invoice_template = request.session.get('custom_template', 'default.html')
          data = prepare_invoice_data(request.user)
          
          # This is vulnerable - user controls template
          return render_to_string(invoice_template, {'invoice': data})
      """

      pattern = TemplateInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end
  end

  describe "safe code validation" do
    test "does not flag static template names" do
      safe_code = """
      def show_report(request):
          report_data = process_report(request.user)
          return render_to_string('reports/summary.html', {'data': report_data})
      """

      pattern = TemplateInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag whitelisted template selection" do
      safe_code = """
      ALLOWED_TEMPLATES = ['report1.html', 'report2.html', 'report3.html']

      def show_report(request):
          template_name = request.GET.get('template', 'report1.html')
          if template_name not in ALLOWED_TEMPLATES:
              template_name = 'report1.html'
          return render(request, template_name, context)
      """

      pattern = TemplateInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag Template with static content" do
      safe_code = """
      from django.template import Template, Context

      def generate_email():
          template = Template('Hello {{ name }}, welcome to our service!')
          context = Context({'name': user.name})
          return template.render(context)
      """

      pattern = TemplateInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag fixed template paths" do
      safe_code = """
      def get_dashboard(request):
          user_role = request.user.role
          if user_role == 'admin':
              return render(request, 'admin/dashboard.html', context)
          else:
              return render(request, 'user/dashboard.html', context)
      """

      pattern = TemplateInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag template rendering with safe context" do
      safe_code = """
      def render_profile(request):
          template = get_template('profile/view.html')
          context = {
              'user': request.user,
              'posts': request.user.posts.all()
          }
          return HttpResponse(template.render(context))
      """

      pattern = TemplateInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Django Python files" do
      assert TemplateInjection.applies_to_file?("views.py", ["django"])
      assert TemplateInjection.applies_to_file?("template_utils.py", ["django"])
      assert TemplateInjection.applies_to_file?("render_helpers.py", ["django"])
      assert TemplateInjection.applies_to_file?("api_views.py", ["django"])
    end

    test "infers Django from file paths" do
      assert TemplateInjection.applies_to_file?("myapp/views.py", [])
      assert TemplateInjection.applies_to_file?("apps/reports/views.py", [])
      assert TemplateInjection.applies_to_file?("django_app/template_loader.py", [])
    end

    test "does not apply to non-Python files" do
      refute TemplateInjection.applies_to_file?("template.html", ["django"])
      refute TemplateInjection.applies_to_file?("style.css", ["django"])
      refute TemplateInjection.applies_to_file?("script.js", ["django"])
    end

    test "does not apply to test files" do
      refute TemplateInjection.applies_to_file?("test_views.py", ["django"])
      refute TemplateInjection.applies_to_file?("tests.py", ["django"])
      refute TemplateInjection.applies_to_file?("test_templates.py", ["django"])
    end
  end
end
