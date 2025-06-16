defmodule RsolvApi.Security.Patterns.Django.NosqlInjectionTest do
  use RsolvApi.DataCase, async: true

  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Django.NosqlInjection

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = NosqlInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "django-nosql-injection"
      assert pattern.name == "Django NoSQL Injection"
      assert pattern.description == "NoSQL injection through MongoDB, Elasticsearch, or Redis with user input"
      assert pattern.type == :nosql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-943"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = NosqlInjection.vulnerability_metadata()
      
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
      
      assert String.contains?(metadata.description, "NoSQL")
      assert String.contains?(metadata.description, "injection")
      assert String.contains?(metadata.cve_examples, "CVE")
      assert String.contains?(metadata.safe_alternatives, "validate")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = NosqlInjection.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
      
      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.nosql_methods)
      assert "find" in ast.context_rules.nosql_methods
      
      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.json_loads_with_user_input == +0.8
      
      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.nosql_analysis.detect_json_parsing == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = NosqlInjection.enhanced_pattern()
      
      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == NosqlInjection.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects $where injection with user input" do
      vulnerable_code = """
      def search_products(request):
          query = {'$where': request.GET.get('query')}
          results = db.products.find(query)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects filter with json.loads from request" do
      vulnerable_code = """
      def filter_users(request):
          filter_data = json.loads(request.body)
          users = User.objects.filter(**filter_data)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects aggregate with json.loads" do
      vulnerable_code = """
      def get_stats(request):
          pipeline = json.loads(request.GET.get('pipeline', '[]'))
          results = collection.aggregate(pipeline)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects find with json.loads" do
      vulnerable_code = """
      def search_docs(request):
          query = json.loads(request.POST.get('query'))
          documents = collection.find(query)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects elasticsearch search with user input" do
      vulnerable_code = """
      def elastic_search(request):
          body = json.loads(request.body)
          results = es.search(body=body)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects redis eval with request data" do
      vulnerable_code = """
      def run_script(request):
          script = request.POST.get('script')
          result = redis_client.eval(script, 0)
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects MongoDB raw query with user input" do
      vulnerable_code = """
      def custom_query(request):
          collection.raw({'$where': f"this.price > {request.GET['min_price']}"})
      """
      
      pattern = NosqlInjection.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end
  end

  describe "safe code validation" do
    test "does not flag safe filter with specific fields" do
      safe_code = """
      def search_users(request):
          name = request.GET.get('name')
          age = request.GET.get('age')
          users = User.objects.filter(name=name, age=age)
      """
      
      pattern = NosqlInjection.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag safe MongoDB query with validation" do
      safe_code = """
      def find_products(request):
          category = request.GET.get('category')
          if category in ALLOWED_CATEGORIES:
              products = collection.find({'category': category})
      """
      
      pattern = NosqlInjection.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag safe elasticsearch with structured query" do
      safe_code = """
      def search_items(request):
          term = request.GET.get('q', '')
          query = {
              'query': {
                  'match': {
                      'title': term
                  }
              }
          }
          results = es.search(body=query)
      """
      
      pattern = NosqlInjection.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag redis commands without eval" do
      safe_code = """
      def cache_data(request):
          key = f"user:{request.user.id}"
          value = request.POST.get('data')
          redis_client.set(key, value)
      """
      
      pattern = NosqlInjection.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag json.loads without database operations" do
      safe_code = """
      def process_data(request):
          data = json.loads(request.body)
          result = calculate_something(data)
          return JsonResponse({'result': result})
      """
      
      pattern = NosqlInjection.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Django Python files" do
      assert NosqlInjection.applies_to_file?("views.py", ["django"])
      assert NosqlInjection.applies_to_file?("models.py", ["django"]) 
      assert NosqlInjection.applies_to_file?("api_views.py", ["django"])
      assert NosqlInjection.applies_to_file?("serializers.py", ["django"])
    end

    test "infers Django from file paths" do
      assert NosqlInjection.applies_to_file?("app/views.py", [])
      assert NosqlInjection.applies_to_file?("myapp/models.py", [])
      assert NosqlInjection.applies_to_file?("api/views.py", [])
    end

    test "does not apply to non-Python files" do
      refute NosqlInjection.applies_to_file?("template.html", ["django"])
      refute NosqlInjection.applies_to_file?("style.css", ["django"])
      refute NosqlInjection.applies_to_file?("script.js", ["django"])
    end

    test "does not apply to test files" do
      refute NosqlInjection.applies_to_file?("test_views.py", ["django"])
      refute NosqlInjection.applies_to_file?("tests.py", ["django"])
      refute NosqlInjection.applies_to_file?("test/test_models.py", ["django"])
    end
  end
end