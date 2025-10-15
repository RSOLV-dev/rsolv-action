defmodule Rsolv.Security.Patterns.Django.OrmInjectionTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Django.OrmInjection

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = OrmInjection.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "django-orm-injection"
      assert pattern.name == "Django ORM SQL Injection"
      assert pattern.description == "SQL injection through Django ORM using string formatting"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = OrmInjection.vulnerability_metadata()

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

      assert String.contains?(metadata.description, "Django ORM")
      assert String.contains?(metadata.description, "SQL injection")
      assert String.contains?(metadata.cve_examples, "CVE-2022-28346")
      assert String.contains?(metadata.safe_alternatives, "parameterized")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = OrmInjection.ast_enhancement()

      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)

      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.orm_methods)
      assert "filter" in ast.context_rules.orm_methods

      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.string_formatting_in_orm == +0.8

      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.orm_analysis.detect_unsafe_methods == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = OrmInjection.enhanced_pattern()

      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == OrmInjection.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects filter with % string formatting" do
      vulnerable_code = """
      def search_users(username):
          return User.objects.filter("name = '%s'" % username)
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects extra() with string formatting" do
      vulnerable_code = """
      def get_filtered_data(user_id):
          return Model.objects.extra(where=["id = %s" % user_id])
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects raw() with string formatting" do
      vulnerable_code = """
      def get_user_data(name):
          return User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects filter with f-string formatting" do
      vulnerable_code = """
      def search_by_id(user_id):
          return User.objects.filter(f"id = {user_id}")
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects raw() with format method" do
      vulnerable_code = """
      def find_user(email):
          query = "SELECT * FROM users WHERE email = '{}'".format(email)
          return User.objects.raw(query)
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects cursor.execute with string formatting" do
      vulnerable_code = """
      from django.db import connection

      def delete_old_records(user_id):
          with connection.cursor() as cursor:
              cursor.execute("DELETE FROM table WHERE id = %s" % user_id)
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end

    test "detects CVE-2022-28346 pattern with extra and dictionary expansion" do
      vulnerable_code = """
      def vulnerable_query(**kwargs):
          return Model.objects.extra(**kwargs)  # CVE-2022-28346
      """

      pattern = OrmInjection.pattern()

      assert Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, vulnerable_code)
             end)
    end
  end

  describe "safe code validation" do
    test "does not flag safe filter with ORM fields" do
      safe_code = """
      def search_users(username):
          return User.objects.filter(name=username)
      """

      pattern = OrmInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag safe raw() with parameterized query" do
      safe_code = """
      def get_user_data(username):
          return User.objects.raw("SELECT * FROM users WHERE name = %s", [username])
      """

      pattern = OrmInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag safe cursor.execute with parameters" do
      safe_code = """
      from django.db import connection

      def delete_old_records(user_id):
          with connection.cursor() as cursor:
              cursor.execute("DELETE FROM table WHERE id = %s", [user_id])
      """

      pattern = OrmInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag Q objects usage" do
      safe_code = """
      from django.db.models import Q

      def complex_search(name, email):
          return User.objects.filter(
              Q(name__icontains=name) | Q(email__icontains=email)
          )
      """

      pattern = OrmInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end

    test "does not flag safe extra with static SQL" do
      safe_code = """
      def get_recent_users():
          return User.objects.extra(
              select={'is_recent': "created_at > NOW() - INTERVAL '30 days'"}
          )
      """

      pattern = OrmInjection.pattern()

      refute Enum.any?(pattern.regex, fn regex ->
               Regex.match?(regex, safe_code)
             end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Django Python files" do
      assert OrmInjection.applies_to_file?("views.py", ["django"])
      assert OrmInjection.applies_to_file?("models.py", ["django"])
      assert OrmInjection.applies_to_file?("serializers.py", ["django"])
      assert OrmInjection.applies_to_file?("admin.py", ["django"])
    end

    test "infers Django from file paths" do
      assert OrmInjection.applies_to_file?("app/views.py", [])
      assert OrmInjection.applies_to_file?("myapp/models.py", [])
      assert OrmInjection.applies_to_file?("project/settings.py", [])
    end

    test "does not apply to non-Python files" do
      refute OrmInjection.applies_to_file?("template.html", ["django"])
      refute OrmInjection.applies_to_file?("style.css", ["django"])
      refute OrmInjection.applies_to_file?("script.js", ["django"])
    end

    test "does not apply to test files" do
      refute OrmInjection.applies_to_file?("test_views.py", ["django"])
      refute OrmInjection.applies_to_file?("tests.py", ["django"])
      refute OrmInjection.applies_to_file?("test/test_models.py", ["django"])
    end
  end
end
