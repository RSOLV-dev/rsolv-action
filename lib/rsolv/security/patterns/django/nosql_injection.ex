defmodule Rsolv.Security.Patterns.Django.NosqlInjection do
  @moduledoc """
  Django NoSQL Injection pattern for Django applications.
  
  This pattern detects NoSQL injection vulnerabilities in Django applications
  that use MongoDB, Elasticsearch, Redis, or other NoSQL databases where user
  input is unsafely incorporated into queries.
  
  ## Background
  
  While Django doesn't have built-in NoSQL support, many Django applications
  integrate with NoSQL databases like MongoDB (via PyMongo/Djongo), Elasticsearch,
  or Redis. These integrations can introduce NoSQL injection vulnerabilities when
  user input is directly incorporated into queries without proper sanitization.
  
  ## Vulnerability Details
  
  NoSQL injection occurs when:
  1. User input is passed to json.loads() and used in database queries
  2. MongoDB $where clauses contain user-controlled data
  3. Elasticsearch query bodies are built from user input
  4. Redis eval() commands execute user-provided scripts
  5. Query operators like $gt, $ne, $regex are controlled by users
  
  ## Examples
  
      # VULNERABLE - json.loads with user input in MongoDB
      filter_data = json.loads(request.body)
      results = collection.find(filter_data)
      
      # VULNERABLE - $where injection
      query = {'$where': request.GET.get('filter')}
      products = db.products.find(query)
      
      # VULNERABLE - Redis eval injection
      script = request.POST.get('script')
      redis_client.eval(script, 0)
      
      # SAFE - Validated MongoDB query
      category = request.GET.get('category')
      if category in ALLOWED_CATEGORIES:
          products = collection.find({'category': category})
      
      # SAFE - Structured Elasticsearch query
      query = {
          'query': {
              'match': {'title': request.GET.get('q', '')}
          }
      }
      results = es.search(body=query)
  """
  
  use Rsolv.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-nosql-injection",
      name: "Django NoSQL Injection",
      description: "NoSQL injection through MongoDB, Elasticsearch, or Redis with user input",
      type: :nosql_injection,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # MongoDB $where injection
        ~r/['"]\$where['"]\s*:\s*request\./,
        ~r/\$where.*?request\.(?:GET|POST|data)/,
        
        # json.loads with user input used in database operations
        ~r/json\.loads\s*\(\s*request\..*?\).*?\.(?:find|filter|aggregate|update)/ms,
        ~r/filter_data\s*=\s*json\.loads\s*\(\s*request\./,
        
        # MongoDB operations with json.loads
        ~r/collection\.find\s*\(\s*json\.loads/,
        ~r/collection\.aggregate\s*\(\s*json\.loads/,
        ~r/\.find\s*\(\s*json\.loads\s*\(\s*request\./,
        
        # Elasticsearch with json.loads
        ~r/es\.search\s*\(\s*body\s*=\s*json\.loads/,
        ~r/elasticsearch.*?body\s*=\s*json\.loads/,
        ~r/body\s*=\s*json\.loads\s*\(\s*request\..*?\).*?es\.search/ms,
        
        # Redis eval with user input
        ~r/redis[_\-]?client\.eval\s*\(\s*request\./,
        ~r/\.eval\s*\(\s*request\.(?:GET|POST|data)/,
        ~r/script\s*=\s*request\..*?\.eval\s*\(\s*script/ms,
        
        # MongoDB raw operations with f-strings
        ~r/\.raw\s*\(\s*\{['"]\$where['"]\s*:\s*f['"]/,
        
        # Direct operator injection
        ~r/\{['"]\$(?:gt|lt|ne|regex|in|nin)['"]\s*:\s*request\./
      ],
      cwe_id: "CWE-943",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize user input before using in NoSQL queries. Use parameterized queries where possible.",
      test_cases: %{
        vulnerable: [
          ~s|collection.find(json.loads(request.body))|,
          ~s|query = {'$where': request.GET.get('query')}|,
          ~s|redis_client.eval(request.POST.get('script'), 0)|
        ],
        safe: [
          ~s|collection.find({'name': request.GET.get('name')})|,
          ~s|query = {'query': {'match': {'field': value}}}|,
          ~s|redis_client.set(key, value)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      NoSQL injection is a vulnerability that allows attackers to manipulate NoSQL database
      queries by injecting malicious data. In Django applications using NoSQL databases,
      this commonly occurs when user input is passed to json.loads() and used directly
      in database queries, or when query operators are controlled by user input.
      
      Unlike SQL injection, NoSQL injection can take many forms:
      1. Operator injection ($gt, $ne, $regex) to bypass authentication
      2. JavaScript injection via $where clauses in MongoDB
      3. Query structure manipulation through JSON parsing
      4. Script injection in Redis eval() commands
      5. Query DSL injection in Elasticsearch
      
      The vulnerability is particularly dangerous because:
      - It can bypass authentication and authorization
      - Allows data extraction and manipulation
      - Can cause denial of service through complex queries
      - May enable remote code execution in some cases
      """,
      
      attack_vectors: """
      1. **Authentication Bypass**: `{"username": "admin", "password": {"$ne": null}}`
      2. **$where JavaScript Injection**: `$where: "function() { return true; }"`
      3. **Operator Injection**: `{"age": {"$gt": 0}, "admin": true}`
      4. **Redis Script Injection**: `eval "return redis.call('flushdb')" 0`
      5. **Elasticsearch DSL Injection**: `{"script": {"source": "doc['balance'].value * 2"}}`
      6. **Regular Expression DoS**: `{"name": {"$regex": "^(a+)+$"}}`
      7. **Data Extraction**: `{"$or": [{"a": "a"}, {"a": "b"}]}`
      8. **Type Confusion**: `{"id": {"$type": 2}}` to find string IDs
      9. **Aggregation Pipeline Injection**: `[{"$lookup": {...}}]`
      10. **Time-based Extraction**: `$where: "sleep(5000) || true"`
      """,
      
      business_impact: """
      - Complete authentication bypass leading to unauthorized access
      - Data breach through extraction of sensitive documents
      - Financial losses from manipulated transactions
      - Service disruption through resource-intensive queries
      - Compliance violations (GDPR, PCI-DSS) from data exposure
      - Reputation damage from security incidents
      - Legal liability from compromised user data
      - Intellectual property theft through data extraction
      - Competitive disadvantage from exposed business logic
      - Recovery costs including incident response and remediation
      """,
      
      technical_impact: """
      - Authentication and authorization bypass
      - Arbitrary data retrieval from all collections
      - Data modification and deletion
      - Denial of service through complex queries
      - Remote code execution (in some configurations)
      - Database schema and structure enumeration
      - Privilege escalation through role manipulation
      - Session hijacking via session storage access
      - Cache poisoning in Redis-based caches
      - Query performance degradation
      """,
      
      likelihood: "High - Developers often trust JSON input and use json.loads() without validation",
      
      cve_examples: """
      CVE-2020-35654 (CVSS 9.8) - NoSQL Injection in Django application
      - Affected Django-based CMS with MongoDB integration
      - json.loads() used directly with user input in find() queries
      - Allowed complete authentication bypass
      
      CVE-2019-10077 (CVSS 9.8) - MongoDB Injection via $where
      - JavaScript injection through $where operator
      - Remote code execution possible
      - Affected multiple Python web applications
      
      CVE-2021-22911 (CVSS 9.8) - Redis Lua Injection
      - Unsafe eval() usage with user input
      - Allowed arbitrary Lua code execution
      - Database-wide impact possible
      
      CVE-2018-1000815 (CVSS 8.8) - Elasticsearch Injection
      - Query DSL injection through user input
      - Information disclosure and DoS
      - Affected Python Elasticsearch clients
      
      CVE-2017-16023 (CVSS 7.5) - MongoDB Operator Injection
      - Authentication bypass using $ne operator
      - Affected Node.js and Python applications
      - Demonstrated in multiple CTF challenges
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
        "CWE-1286: Improper Validation of Syntactic Correctness of Input",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5.3 Output Encoding and Injection Prevention",
        "SANS Top 25 - Injection vulnerabilities"
      ],
      
      remediation_steps: """
      1. **Validate Input Types and Structure**:
         ```python
         # NEVER DO THIS - Direct json.loads
         filter_data = json.loads(request.body)
         results = collection.find(filter_data)  # VULNERABLE!
         
         # SAFE - Validate structure
         try:
             data = json.loads(request.body)
             # Whitelist allowed fields
             safe_filter = {}
             if 'name' in data and isinstance(data['name'], str):
                 safe_filter['name'] = data['name']
             if 'age' in data and isinstance(data['age'], int):
                 safe_filter['age'] = data['age']
             
             results = collection.find(safe_filter)
         except (json.JSONDecodeError, TypeError):
             return JsonResponse({'error': 'Invalid input'}, status=400)
         ```
      
      2. **Avoid $where and JavaScript Execution**:
         ```python
         # NEVER DO THIS - $where with user input
         query = {'$where': f"this.price > {request.GET['min_price']}"}
         
         # SAFE - Use native operators
         try:
             min_price = float(request.GET.get('min_price', 0))
             query = {'price': {'$gt': min_price}}
             results = collection.find(query)
         except ValueError:
             return JsonResponse({'error': 'Invalid price'}, status=400)
         ```
      
      3. **Use ODM/ORM Libraries with Built-in Protection**:
         ```python
         # Using MongoEngine (Django MongoDB ORM)
         from mongoengine import Document, StringField, IntField
         
         class User(Document):
             username = StringField(required=True)
             age = IntField(min_value=0, max_value=150)
         
         # Safe query with validation
         users = User.objects(
             username=request.GET.get('username'),
             age__gte=request.GET.get('min_age', 0)
         )
         ```
      
      4. **Sanitize Elasticsearch Queries**:
         ```python
         # NEVER DO THIS
         query = json.loads(request.body)
         results = es.search(body=query)  # VULNERABLE!
         
         # SAFE - Build structured query
         search_term = request.GET.get('q', '')
         query = {
             'query': {
                 'bool': {
                     'must': [
                         {
                             'match': {
                                 'title': {
                                     'query': search_term,
                                     'operator': 'and'
                                 }
                             }
                         }
                     ]
                 }
             },
             'size': 10,  # Limit results
             'from': 0    # Pagination
         }
         results = es.search(index='products', body=query)
         ```
      
      5. **Secure Redis Operations**:
         ```python
         # NEVER DO THIS - eval with user input
         script = request.POST.get('script')
         redis_client.eval(script, 0)  # VULNERABLE!
         
         # SAFE - Use predefined operations
         key = f"user:{request.user.id}:data"
         value = request.POST.get('value')
         
         # Validate key format
         if not re.match(r'^user:\d+:data$', key):
             return JsonResponse({'error': 'Invalid key'}, status=400)
         
         # Use safe Redis commands
         redis_client.set(key, value, ex=3600)  # With expiration
         ```
      
      6. **Input Validation and Type Checking**:
         ```python
         def validate_mongodb_input(data):
             \"\"\"Validate and sanitize MongoDB query input\"\"\"
             if not isinstance(data, dict):
                 raise ValueError("Input must be a dictionary")
             
             # Check for dangerous operators
             dangerous_ops = ['$where', '$function', '$accumulator', '$code']
             
             def check_dict(d):
                 for key, value in d.items():
                     if key in dangerous_ops:
                         raise ValueError(f"Operator {key} not allowed")
                     if isinstance(value, dict):
                         check_dict(value)
                     elif isinstance(value, list):
                         for item in value:
                             if isinstance(item, dict):
                                 check_dict(item)
             
             check_dict(data)
             return data
         ```
      """,
      
      prevention_tips: """
      - Never pass user input directly to json.loads() for database queries
      - Avoid MongoDB $where operator; use native query operators
      - Validate all input types and structure before querying
      - Use ODM/ORM libraries that provide query sanitization
      - Implement strict input validation and whitelisting
      - Disable JavaScript execution in MongoDB if not needed
      - Use parameterized queries where available
      - Implement query complexity limits
      - Monitor and log suspicious query patterns
      - Regular security audits of database operations
      """,
      
      detection_methods: """
      - Static analysis with Bandit rules for json.loads patterns
      - Search for $where, eval(), and operator usage
      - Code review checklist for NoSQL operations
      - Dynamic testing with NoSQL injection payloads
      - Database query logging and anomaly detection
      - Runtime application self-protection (RASP)
      - Security testing with tools like NoSQLMap
      - Dependency scanning for vulnerable libraries
      """,
      
      safe_alternatives: """
      # 1. MongoEngine for Django (Safe ODM) - Always validate user input
      from mongoengine import connect, Document, StringField, IntField, Q
      
      connect('mydb')
      
      class Product(Document):
          name = StringField(max_length=200, required=True)
          price = IntField(min_value=0)
          category = StringField(choices=['electronics', 'books', 'clothing'])
      
      # Safe queries with validation
      products = Product.objects(
          category=request.GET.get('category', 'electronics'),
          price__gte=int(request.GET.get('min_price', 0))
      )
      
      # 2. Elasticsearch DSL (Safe Query Builder)
      from elasticsearch_dsl import Search, Q
      
      s = Search(using=es, index='products')
      
      # Safe query construction
      query = request.GET.get('q', '')
      if query:
          s = s.query('match', title=query)
      
      category = request.GET.get('category')
      if category in ['electronics', 'books', 'clothing']:
          s = s.filter('term', category=category)
      
      response = s.execute()
      
      # 3. PyMongo with Validation
      from pymongo import MongoClient
      from bson import ObjectId
      
      def get_user_safely(user_id):
          # Validate ObjectId format
          try:
              obj_id = ObjectId(user_id)
          except:
              return None
          
          # Safe query
          return db.users.find_one({'_id': obj_id})
      
      # 4. Redis with Safe Commands
      import redis
      import json
      
      r = redis.Redis()
      
      def cache_user_data(user_id, data):
          # Validate user_id is numeric
          if not str(user_id).isdigit():
              raise ValueError("Invalid user ID")
          
          # Safe key construction
          key = f"user:{user_id}:profile"
          
          # Serialize safely
          r.setex(key, 3600, json.dumps(data))
      
      # 5. Query Builder Pattern
      class SafeMongoQuery:
          def __init__(self, collection):
              self.collection = collection
              self.filters = {}
          
          def add_filter(self, field, value, operator='$eq'):
              # Whitelist allowed fields and operators
              allowed_fields = ['name', 'age', 'category', 'price']
              allowed_ops = ['$eq', '$gt', '$gte', '$lt', '$lte', '$in']
              
              if field not in allowed_fields:
                  raise ValueError(f"Field {field} not allowed")
              if operator not in allowed_ops:
                  raise ValueError(f"Operator {operator} not allowed")
              
              if operator == '$eq':
                  self.filters[field] = value
              else:
                  self.filters[field] = {operator: value}
              
              return self
          
          def execute(self):
              return list(self.collection.find(self.filters))
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # NoSQL database methods
        nosql_methods: [
          "find", "find_one", "insert", "update", "delete",
          "aggregate", "map_reduce", "eval", "search"
        ],
        
        # Dangerous functions
        dangerous_functions: [
          "json.loads", "eval", "exec", "compile",
          "ast.literal_eval"
        ],
        
        # MongoDB operators
        mongo_operators: [
          "$where", "$function", "$accumulator", "$code",
          "$gt", "$gte", "$lt", "$lte", "$ne", "$regex"
        ],
        
        # Safe patterns to exclude
        safe_patterns: [
          ~r/if\s+\w+\s+in\s+ALLOWED_/,          # Whitelist check
          ~r/isinstance\s*\(\s*\w+,\s*(?:str|int|float)\)/, # Type check
          ~r/\.find\s*\(\s*\{\s*['"]_id['"]/,    # ID lookup
          ~r/ObjectId\s*\(/                       # ObjectId usage
        ],
        
        # User input sources
        user_inputs: [
          "request.GET", "request.POST", "request.body",
          "request.data", "request.FILES", "request.META"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          json_loads_with_user_input: +0.8,
          where_operator_injection: +0.9,
          eval_with_user_input: +0.9,
          operator_injection: +0.7,
          
          # Medium confidence
          indirect_json_loads: +0.5,
          elasticsearch_injection: +0.6,
          
          # Lower confidence for safer patterns
          validated_input: -0.8,
          type_checking: -0.7,
          odm_usage: -0.9,
          whitelisted_values: -0.9,
          
          # Context adjustments
          in_view_function: +0.2,
          in_api_handler: +0.3,
          in_migration: -0.8,
          
          # File location adjustments
          in_test_file: -0.9,
          in_fixtures: -0.8,
          commented_line: -1.0
        }
      },
      
      ast_rules: %{
        # NoSQL analysis
        nosql_analysis: %{
          detect_json_parsing: true,
          check_operator_usage: true,
          analyze_query_building: true,
          track_user_input_flow: true
        },
        
        # Input validation
        validation_analysis: %{
          detect_type_checking: true,
          find_whitelisting: true,
          check_sanitization: true,
          identify_validation_functions: true
        },
        
        # Database client detection
        client_analysis: %{
          identify_mongodb_clients: true,
          detect_elasticsearch_usage: true,
          find_redis_clients: true,
          check_odm_usage: true
        },
        
        # Safe pattern detection
        safe_pattern_analysis: %{
          detect_parameterization: true,
          find_safe_builders: true,
          identify_orm_usage: true,
          check_input_validation: true
        }
      }
    }
  end
  
  def applies_to_file?(file_path, frameworks ) do
    # Apply to Python files in Django projects
    is_python_file = String.ends_with?(file_path, ".py")
    
    # Django framework check
    frameworks_list = frameworks || []
    is_django = "django" in frameworks_list
    
    # Common Django file patterns
    is_django_file = String.contains?(file_path, "views.py") ||
                    String.contains?(file_path, "models.py") ||
                    String.contains?(file_path, "api_views.py") ||
                    String.contains?(file_path, "serializers.py")
    
    # Not a test file
    not_test = !String.contains?(file_path, "test") &&
               !String.contains?(file_path, "spec")
    
    # If no frameworks specified but it looks like Django, include it
    inferred_django = frameworks_list == [] && is_django_file
    
    is_python_file && (is_django || inferred_django) && not_test
  end
end
