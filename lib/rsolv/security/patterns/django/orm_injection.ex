defmodule Rsolv.Security.Patterns.Django.OrmInjection do
  @moduledoc """
  Django ORM SQL Injection pattern for Django applications.

  This pattern detects SQL injection vulnerabilities through Django ORM operations
  where user input is unsafely incorporated into queries using string formatting
  instead of proper parameterization.

  ## Background

  Django's ORM normally protects against SQL injection by using parameterized queries.
  However, developers can bypass this protection by using string formatting to build
  SQL queries, particularly with methods like filter(), extra(), raw(), and direct
  cursor operations.

  ## Vulnerability Details

  The vulnerability occurs when:
  1. User input is incorporated into ORM queries using string formatting (%, f-strings, .format())
  2. raw() queries are built with string concatenation
  3. extra() method receives user-controlled input
  4. Direct database cursor operations use string formatting
  5. Dictionary expansion (**kwargs) is used with user input (CVE-2022-28346)

  ## Examples

      # VULNERABLE - String formatting in filter
      User.objects.filter("name = '%s'" % username)
      
      # VULNERABLE - F-string in raw query
      User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")
      
      # VULNERABLE - Format method
      query = "DELETE FROM table WHERE id = {}".format(id)
      cursor.execute(query)
      
      # SAFE - Parameterized ORM query
      User.objects.filter(name=username)
      
      # SAFE - Parameterized raw query
      User.objects.raw("SELECT * FROM users WHERE name = %s", [username])
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-orm-injection",
      name: "Django ORM SQL Injection",
      description: "SQL injection through Django ORM using string formatting",
      type: :sql_injection,
      severity: :critical,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # filter() with % formatting
        ~r/\.filter\s*\(\s*["'].*?%s["'].*?%/,

        # extra() with % formatting in where clause
        ~r/\.extra\s*\(\s*where\s*=\s*\[["'].*?%s["'].*?%/,

        # raw() with % formatting
        ~r/\.raw\s*\(\s*["'].*?%s["'].*?%/,

        # filter() with f-string
        ~r/\.filter\s*\(\s*f["'].*?\{.*?\}["']/,

        # extra() with f-string
        ~r/\.extra\s*\(\s*where\s*=\s*\[f["'].*?\{.*?\}["']/,

        # raw() with f-string
        ~r/\.raw\s*\(\s*f["'].*?\{.*?\}["']/,

        # filter() with .format()
        ~r/\.filter\s*\(\s*["'].*?\.format\s*\(/,

        # extra() with .format()
        ~r/\.extra\s*\(\s*.*?\.format\s*\(/,

        # raw() with .format()
        ~r/\.raw\s*\(\s*["'].*?\.format\s*\(/,

        # Variable assignment with format() then used in raw()
        ~r/query\s*=\s*["'].*?\.format\s*\(.*?\).*?\.raw\s*\(\s*query/ms,

        # cursor.execute() with % formatting
        ~r/cursor\.execute\s*\(\s*["'].*?%s["'].*?%/,

        # cursor.execute() with f-string
        ~r/cursor\.execute\s*\(\s*f["'].*?\{.*?\}["']/,

        # CVE-2022-28346 - extra with **kwargs
        ~r/\.extra\s*\(\s*\*\*\w+\)/,

        # annotate() with **kwargs
        ~r/\.annotate\s*\(\s*\*\*\w+\)/,

        # aggregate() with **kwargs  
        ~r/\.aggregate\s*\(\s*\*\*\w+\)/
      ],
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation:
        "Use Django parameterized queries: Model.objects.raw(\"SELECT * FROM table WHERE id = %s\", [user_id]) or Django ORM methods: filter(name=username)",
      test_cases: %{
        vulnerable: [
          ~s|User.objects.filter("name = '%s'" % username)|,
          ~s|User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)|,
          ~s|cursor.execute("DELETE FROM table WHERE id = %s" % user_id)|
        ],
        safe: [
          ~s|User.objects.filter(name=username)|,
          ~s|User.objects.raw("SELECT * FROM users WHERE name = %s", [username])|,
          ~s|cursor.execute("DELETE FROM table WHERE id = %s", [user_id])|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Django ORM SQL Injection is a critical vulnerability that occurs when user-controlled
      input is incorporated into database queries through unsafe string formatting methods
      instead of using Django's built-in parameterization. While Django's ORM typically
      protects against SQL injection by using parameterized queries, developers can bypass
      this protection by building SQL strings manually using %, f-strings, or .format().

      This vulnerability is particularly dangerous because:
      1. It can lead to complete database compromise
      2. Attackers can read, modify, or delete any data
      3. Database administrative commands can be executed
      4. It can be used to escalate privileges
      5. The vulnerability often goes undetected in code reviews
      """,
      attack_vectors: """
      1. **String Format Injection**: Injecting SQL via % formatting: `'; DROP TABLE users; --`
      2. **F-String Exploitation**: Using f-strings with malicious input: `{user_id} OR 1=1`
      3. **Format Method Attack**: Exploiting .format() calls: `1 UNION SELECT * FROM passwords`
      4. **Extra Method Injection**: Abusing extra() with raw SQL: `1=1; DELETE FROM sessions`
      5. **Raw Query Manipulation**: Injecting into raw() queries: `admin' --`
      6. **Cursor Direct Injection**: Direct cursor.execute() exploitation
      7. **Dictionary Expansion (CVE-2022-28346)**: Malicious **kwargs in extra/annotate/aggregate
      8. **Union-Based Data Extraction**: Using UNION SELECT to extract data
      9. **Boolean Blind Injection**: Using AND/OR conditions to infer data
      10. **Time-Based Blind Injection**: Using database sleep functions for data extraction
      """,
      business_impact: """
      - Complete data breach exposing customer records, passwords, and sensitive information
      - Financial losses from stolen credit card data or fraudulent transactions
      - Regulatory fines under GDPR, CCPA, PCI-DSS for data protection failures
      - Reputation damage leading to customer loss and decreased market value
      - Legal liability from compromised user data and privacy violations
      - Intellectual property theft through database extraction
      - Service disruption from deleted or corrupted data
      - Compliance audit failures and loss of certifications
      - Competitive disadvantage from exposed business data
      - Recovery costs including forensics, notification, and credit monitoring
      """,
      technical_impact: """
      - Arbitrary SQL command execution on the database
      - Complete database schema enumeration
      - Data extraction from all tables and columns
      - Privilege escalation to database admin
      - Data modification including updates and deletions
      - Database server file system access (depending on DB)
      - Potential remote code execution through DB features
      - Bypass of all application-level access controls
      - Session hijacking through session table access
      - Password hash extraction for offline cracking
      """,
      likelihood:
        "High - Developers often use string formatting for convenience without realizing the security implications",
      cve_examples: """
      CVE-2022-28346 (CVSS 9.8 CRITICAL) - Django SQL Injection via QuerySet methods
      - Affected Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4
      - QuerySet.annotate(), aggregate(), and extra() vulnerable to SQL injection
      - Column aliases could be injected via crafted dictionary with **kwargs expansion
      - Allowed attackers to execute arbitrary SQL commands

      CVE-2022-28347 (CVSS 9.8 CRITICAL) - Django SQL Injection in QuerySet.explain()
      - Affected same Django versions as CVE-2022-28346
      - PostgreSQL-specific vulnerability in explain() method
      - Options parameter vulnerable to SQL injection

      CVE-2021-35042 (CVSS 9.8 CRITICAL) - Django SQL Injection via QuerySet.order_by()
      - Unsanitized user input to order_by() allowed SQL injection
      - Affected Django 3.2 before 3.2.14 and 4.0 before 4.0.6

      CVE-2020-7471 (CVSS 9.8 CRITICAL) - Django SQL Injection in PostgreSQL
      - StringAgg delimiter parameter vulnerable to SQL injection
      - Affected Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3

      CVE-2019-14234 (CVSS 9.8 CRITICAL) - Django JSONField/HStoreField SQL Injection
      - Key transforms in JSONField and HStoreField vulnerable
      - Affected Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-89: SQL Injection",
        "CWE-564: SQL Injection: Hibernate",
        "CWE-20: Improper Input Validation",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5.3 Output Encoding and Injection Prevention",
        "SANS Top 25 - CWE-89 SQL Injection"
      ],
      remediation_steps: """
      1. **Use Django ORM Properly**:
         ```python
         # NEVER DO THIS - String formatting
         users = User.objects.filter("name = '%s'" % username)  # VULNERABLE!
         users = User.objects.filter(f"age > {min_age}")       # VULNERABLE!
         
         # SAFE - Use field lookups
         users = User.objects.filter(name=username)
         users = User.objects.filter(age__gt=min_age)
         
         # SAFE - Use Q objects for complex queries
         from django.db.models import Q
         users = User.objects.filter(
             Q(name=username) | Q(email=user_email)
         )
         ```

      2. **Parameterize Raw Queries**:
         ```python
         # NEVER DO THIS - String concatenation
         query = "SELECT * FROM users WHERE name = '%s'" % name
         users = User.objects.raw(query)  # VULNERABLE!
         
         # SAFE - Use parameterized queries
         users = User.objects.raw(
             "SELECT * FROM users WHERE name = %s",
             [name]  # Parameters passed separately
         )
         
         # SAFE - Multiple parameters
         users = User.objects.raw(
             "SELECT * FROM users WHERE name = %s AND age > %s",
             [name, min_age]
         )
         ```

      3. **Secure Cursor Operations**:
         ```python
         from django.db import connection
         
         # NEVER DO THIS
         with connection.cursor() as cursor:
             query = f"DELETE FROM logs WHERE user_id = {user_id}"
             cursor.execute(query)  # VULNERABLE!
         
         # SAFE - Parameterized cursor execution
         with connection.cursor() as cursor:
             cursor.execute(
                 "DELETE FROM logs WHERE user_id = %s",
                 [user_id]
             )
         ```

      4. **Avoid Dynamic extra() Usage**:
         ```python
         # NEVER DO THIS - User input in extra()
         Model.objects.extra(
             where=[f"status = '{status}'"]  # VULNERABLE!
         )
         
         # NEVER DO THIS - CVE-2022-28346 pattern
         def build_query(**kwargs):
             return Model.objects.extra(**kwargs)  # VULNERABLE!
         
         # SAFE - Use ORM methods instead
         Model.objects.filter(status=status)
         
         # If extra() is necessary, use parameters
         Model.objects.extra(
             where=["status = %s"],
             params=[status]
         )
         ```

      5. **Input Validation and Sanitization**:
         ```python
         # Whitelist allowed values
         ALLOWED_SORT_FIELDS = ['name', 'created_at', 'updated_at']
         
         def get_sorted_users(sort_field):
             if sort_field not in ALLOWED_SORT_FIELDS:
                 sort_field = 'name'  # Default safe value
             
             return User.objects.order_by(sort_field)
         ```
      """,
      prevention_tips: """
      - Always use Django ORM field lookups instead of string formatting
      - Parameterize all raw SQL queries without exception
      - Never use %, f-strings, or .format() with SQL queries
      - Avoid extra() method; use ORM methods instead
      - Validate and whitelist all user input
      - Use Django's built-in SQL escaping functions
      - Enable SQL query logging in development
      - Regular security code reviews focusing on database queries
      - Use static analysis tools like Bandit with Django plugins
      - Implement database query monitoring and anomaly detection
      """,
      detection_methods: """
      - Static analysis with Bandit, PyLint, or Semgrep
      - Search codebase for patterns: %.filter, f-string queries, .format in queries
      - SQL query logging and analysis for injection attempts
      - Code review checklist for database operations
      - Automated security testing with SQLMap
      - Dynamic application security testing (DAST)
      - Database activity monitoring for suspicious queries
      - Regular penetration testing of Django applications
      """,
      safe_alternatives: """
      # 1. Django ORM Field Lookups with Parameterized Queries
      # Instead of string formatting, use field lookups and parameterized queries
      users = User.objects.filter(
          username__icontains=search_term,
          age__gte=min_age,
          is_active=True
      )

      # 2. Q Objects for Complex Queries
      from django.db.models import Q

      results = Product.objects.filter(
          Q(name__icontains=search) | Q(description__icontains=search),
          price__lte=max_price
      )

      # 3. Prefetch and Select Related
      # Avoid N+1 queries safely
      orders = Order.objects.select_related('customer').prefetch_related('items')

      # 4. Aggregation with ORM
      from django.db.models import Count, Sum, Avg

      stats = Order.objects.aggregate(
          total_orders=Count('id'),
          total_revenue=Sum('total'),
          avg_order_value=Avg('total')
      )

      # 5. Safe Dynamic Queries
      def build_filters(request):
          filters = {}
          if request.GET.get('status'):
              filters['status'] = request.GET['status']
          if request.GET.get('category'):
              filters['category__name'] = request.GET['category']
          
          return Product.objects.filter(**filters)

      # 6. Raw Queries When Necessary
      # Use parameters for any user input
      def get_user_stats(user_id):
          with connection.cursor() as cursor:
              cursor.execute('''
                  SELECT COUNT(*) as order_count,
                         SUM(total) as total_spent
                  FROM orders
                  WHERE user_id = %s
                  AND status = %s
              ''', [user_id, 'completed'])
              
              return cursor.fetchone()
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        # Django ORM methods vulnerable to injection
        orm_methods: [
          "filter",
          "exclude",
          "annotate",
          "aggregate",
          "extra",
          "raw",
          "order_by",
          "values",
          "values_list"
        ],

        # String formatting patterns
        string_formats: [
          "%",
          "format",
          "f-string",
          "str.format",
          "%-formatting"
        ],

        # Database cursor methods
        cursor_methods: [
          "execute",
          "executemany",
          "executescript"
        ],

        # Safe patterns to exclude
        safe_patterns: [
          # field=value
          ~r/\.filter\s*\(\s*\w+\s*=/,
          # Q objects
          ~r/\.filter\s*\(\s*Q\s*\(/,
          # parameterized
          ~r/\.raw\s*\([^,]+,\s*\[/,
          # parameterized
          ~r/cursor\.execute\s*\([^,]+,\s*\[/
        ],

        # User input indicators
        user_inputs: [
          "request.GET",
          "request.POST",
          "request.data",
          "request.query_params",
          "request.FILES",
          "request.META"
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous patterns
          string_formatting_in_orm: +0.8,
          fstring_in_query: +0.9,
          format_method_in_query: +0.7,
          kwargs_expansion: +0.8,

          # Medium confidence
          indirect_formatting: +0.5,
          cursor_operations: +0.6,

          # Lower confidence for safer patterns
          parameterized_query: -0.9,
          orm_field_lookup: -0.8,
          static_query: -0.7,

          # Context adjustments
          in_view: +0.2,
          in_model: +0.3,
          in_migration: -0.5,

          # File location adjustments
          in_test_file: -0.9,
          commented_line: -1.0
        }
      },
      ast_rules: %{
        # ORM analysis
        orm_analysis: %{
          detect_unsafe_methods: true,
          check_string_building: true,
          analyze_parameter_passing: true,
          identify_kwargs_usage: true
        },

        # String analysis
        string_analysis: %{
          detect_format_operations: true,
          check_concatenation: true,
          identify_interpolation: true,
          analyze_query_construction: true
        },

        # Input tracking
        input_analysis: %{
          track_user_input: true,
          follow_variable_flow: true,
          check_sanitization: true,
          detect_validation: true
        },

        # Safe pattern detection
        safe_analysis: %{
          identify_parameterization: true,
          detect_orm_usage: true,
          check_whitelisting: true,
          find_escape_functions: true
        }
      }
    }
  end

  def applies_to_file?(file_path, frameworks) do
    # Apply to Python files in Django projects
    is_python_file = String.ends_with?(file_path, ".py")

    # Django framework check
    frameworks_list = frameworks || []
    is_django = "django" in frameworks_list

    # Common Django file patterns
    is_django_file =
      String.contains?(file_path, "views.py") ||
        String.contains?(file_path, "models.py") ||
        String.contains?(file_path, "serializers.py") ||
        String.contains?(file_path, "admin.py") ||
        String.contains?(file_path, "forms.py") ||
        String.contains?(file_path, "managers.py") ||
        String.contains?(file_path, "urls.py") ||
        String.contains?(file_path, "settings.py")

    # Not a test file
    not_test =
      !String.contains?(file_path, "test") &&
        !String.contains?(file_path, "spec")

    # If no frameworks specified but it looks like Django, include it
    inferred_django = frameworks_list == [] && is_django_file

    is_python_file && (is_django || inferred_django) && not_test
  end
end
