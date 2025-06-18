defmodule RsolvApi.Security.Patterns.Django.Cve201914234 do
  @moduledoc """
  Django CVE-2019-14234 - SQL Injection in JSONField/HStoreField Key Transforms
  
  This pattern detects Django applications vulnerable to CVE-2019-14234, a critical 
  SQL injection vulnerability in JSONField and HStoreField key transforms due to 
  shallow key transformation error that allows direct injection into SQL queries.
  
  ## Vulnerability Details
  
  The vulnerability affects Django versions:
  - 2.1 before 2.1.11
  - 2.2 before 2.2.4
  - 1.11 before 1.11.23
  
  The issue occurs in Django's ORM when using JSONField or HStoreField key lookups,
  where user-provided keys are not properly escaped when building SQL queries for
  key transforms like `__key=value` or `__contains` operations.
  
  ### Attack Example
  ```python
  # Vulnerable: Direct user input in JSONField key lookup
  def search_data(request):
      key = request.GET.get('key')  # Could be "'; DROP TABLE users; --"
      results = Model.objects.filter(data__key=key)  # SQL injection
      return results
  
  # Generated SQL (vulnerable):
  # SELECT * FROM model WHERE (data -> 'key_from_user_input') = %s
  # If key_from_user_input = "'; DROP TABLE users; --"
  # Result: SELECT * FROM model WHERE (data -> ''; DROP TABLE users; --') = %s
  
  # Attack scenarios:
  # 1. Data extraction: data__key="' UNION SELECT password FROM auth_user--"
  # 2. Data manipulation: data__key="'; UPDATE auth_user SET is_superuser=true--"
  # 3. Table deletion: data__key="'; DROP TABLE sensitive_data--"
  ```
  
  ### Safe Example
  ```python
  # Safe: Validate and sanitize input before use
  def search_data(request):
      key = request.GET.get('key', '')
      # Validate key against whitelist
      allowed_keys = ['name', 'email', 'status']
      if key not in allowed_keys:
          raise ValueError("Invalid key")
      
      results = Model.objects.filter(data__key=key)
      return results
  
  # Or use Django 2.2.4+ which properly escapes keys
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "django-cve-2019-14234",
      name: "Django CVE-2019-14234 - SQL Injection in JSONField",
      description: "SQL injection via JSONField/HStoreField key transforms due to shallow key transformation error",
      type: :sql_injection,
      severity: :critical,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/__[a-zA-Z_]\w*\s*=\s*request\./,
        ~r/JSONField.*__\w+\s*=\s*request\./,
        ~r/HStoreField.*__\w+\s*=\s*request\./,
        ~r/\.filter\s*\([^)]*__\w+\s*=\s*request\./,
        ~r/\.filter\s*\([^)]*data__[^=]*=\s*request\./,
        ~r/\.objects\.filter\s*\([^)]*__\w+\s*=\s*request\./,
        ~r/__contains\s*=\s*request\./,
        ~r/__has_key\s*=\s*request\./,
        ~r/__has_keys\s*=\s*request\./,
        ~r/data__\d+\s*=\s*request\./,
        ~r/json_field__\w+__\w+\s*=\s*request\./,
        ~r/\.filter\s*\([^)]*__\w+.*=.*request\./,
        ~r/queryset\.filter\s*\([^)]*__\w+.*=.*request\./,
        ~r/Entry\.objects\.filter\s*\([^)]*__\w+.*=.*request\./,
        ~r/Model\.objects\.filter\s*\([^)]*__\w+.*=.*request\./,
        ~r/\.getlist\s*\(/,
        ~r/__isnull\s*=.*False.*__\w+\s*=.*request\./,
        ~r/data__\d+\s*=\s*request\./,
        ~r/json_array__\d+__\w+\s*=\s*request\./,
        ~r/metadata__\w+__\d+\s*=\s*user_input/,
        ~r/__has_key\s*=\s*request\./,
        ~r/__has_keys\s*=\s*request\.POST\.getlist/,
        ~r/metadata__\w+__isnull\s*=\s*False.*metadata__\w+\s*=\s*user_\w+/
      ],
      default_tier: :enterprise,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Update Django to 2.2.4+, 2.1.11+, or 1.11.23+. Validate input and sanitize key parameters before JSONField operations.",
      test_cases: %{
        vulnerable: [
          ~s|Model.objects.filter(data__key=request.GET['key'])|,
          ~s|queryset.filter(json_field__contains=request.POST['search'])|,
          ~s|Model.objects.filter(metadata__user__name=request.GET.get('username'))|,
          ~s|Entry.objects.filter(data__0=request.GET['item'])|,
          ~s|Model.objects.filter(data__has_key=request.GET['key'])|
        ],
        safe: [
          ~s|# Django 2.2.4+ handles key escaping properly
Model.objects.filter(data__key=validated_key)|,
          ~s|# Validate against whitelist
allowed_keys = ['name', 'email']
if key in allowed_keys:
    Model.objects.filter(data__key=key)|,
          ~s|# Use parameterized queries
Model.objects.extra(where=["data->%s = %s"], params=[safe_key, value])|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      CVE-2019-14234 is a critical SQL injection vulnerability affecting Django's JSONField 
      and HStoreField key transform operations. The vulnerability occurs due to a shallow key transformation error where user-provided keys in database lookups are not properly 
      escaped when building SQL queries.
      
      This affects PostgreSQL-specific field types (JSONField, HStoreField) where key lookups 
      like `data__user_key=value` translate to SQL operations that include the key name directly 
      in the query without proper escaping. Attackers can inject malicious SQL through the key 
      parameter, leading to full database compromise.
      
      The vulnerability was discovered during Django's security audit and affects millions of 
      Django applications using PostgreSQL with JSON or HStore data types. The impact is 
      particularly severe because these fields are commonly used for storing user preferences, 
      metadata, and dynamic content.
      """,
      references: [
        %{
          type: :cve,
          id: "CVE-2019-14234",
          title: "Django SQL injection in JSONField/HStoreField key transforms",
          url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14234"
        },
        %{
          type: :cwe,
          id: "CWE-89",
          title: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
          url: "https://cwe.mitre.org/data/definitions/89.html"
        },
        %{
          type: :advisory,
          id: "GHSA-5h98-wxpf-v4m8",
          title: "SQL injection in Django JSONField/HStoreField key transforms",
          url: "https://github.com/advisories/GHSA-5h98-wxpf-v4m8"
        },
        %{
          type: :security_release,
          id: "Django-2019-08-01",
          title: "Django security releases issued: 2.2.4, 2.1.11 and 1.11.23",
          url: "https://www.djangoproject.com/weblog/2019/aug/01/security-releases/"
        },
        %{
          type: :research,
          id: "Django-commit-fix",
          title: "Django commit fixing CVE-2019-14234",
          url: "https://github.com/django/django/commit/c238701859a52d584f349cce15d56c8e8137c828"
        }
      ],
      attack_vectors: [
        "SQL injection through JSONField key parameters in ORM queries",
        "HStoreField key manipulation leading to database command execution", 
        "Index-based JSONField lookups allowing nested SQL injection",
        "Chained key transforms enabling complex SQL payload injection",
        "PostgreSQL-specific function injection via malformed JSON keys"
      ],
      real_world_impact: [
        "Complete database compromise including unauthorized data access and modification",
        "Sensitive data extraction from PostgreSQL databases using JSON/HStore fields",
        "Privilege escalation through manipulation of user authentication data",
        "Database schema discovery and data exfiltration via error-based injection",
        "Application logic bypass through direct database manipulation"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-14234",
          description: "Django SQL injection vulnerability in JSONField/HStoreField key transforms allowing remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "NIST CVSS 3.1 score - critical severity with network exploitability"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. JSONField and HStoreField key lookups using user input (request.GET/POST/etc.)
      2. Double underscore key transform syntax with request data
      3. Index-based JSON array lookups with user-controlled indices
      4. Nested key transforms where user input flows into key parameters
      5. PostgreSQL-specific JSON operations containing user data
      
      The pattern specifically looks for Django ORM filter operations where user-controllable 
      data (typically from request objects) is used directly in field lookup key parameters 
      without proper validation or escaping.
      """,
      safe_alternatives: [
        "Update Django to version 2.2.4+, 2.1.11+, or 1.11.23+ which includes proper key escaping",
        "Validate JSONField/HStoreField keys against a predefined whitelist of allowed values",
        "Use parameterized queries with Django's extra() method for complex JSON operations",
        "Implement application-level input sanitization before ORM operations",
        "Use Django's Q objects with explicit field validation for complex queries"
      ],
      additional_context: %{
        common_mistakes: [
          "Using request parameters directly in JSONField key lookups without validation",
          "Assuming Django ORM automatically escapes all user input including field keys",
          "Not implementing input validation for PostgreSQL-specific field operations",
          "Trusting client-side validation without server-side key whitelisting"
        ],
        secure_patterns: [
          "Always validate JSONField/HStoreField keys against predefined whitelists",
          "Use Django's built-in field validation and form cleaning for JSON operations",
          "Implement defense-in-depth with both application and database-level validation",
          "Monitor database query logs for suspicious JSON/HStore operations"
        ],
        framework_specific_notes: [
          "This vulnerability specifically affects Django applications using PostgreSQL",
          "JSONField and HStoreField are PostgreSQL-specific database fields",
          "The issue occurs in Django's ORM query building, not PostgreSQL itself",
          "Upgrading Django versions includes automatic protection against this vulnerability"
        ]
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: :exclusion,
          patterns: [
            ~r/Django.*2\.2\.4|Django.*2\.1\.11|Django.*1\.11\.23/,
            ~r/allowed_keys\s*=.*\[.*\]/,
            ~r/if\s+\w+\s+in\s+allowed_keys/,
            ~r/whitelist\s*=|ALLOWED_KEYS\s*=/,
            ~r/\.extra\s*\(\s*where\s*=.*params\s*=/
          ],
          description: "Exclude if using patched Django versions, key whitelisting, or parameterized queries"
        },
        %{
          type: :validation,
          context: %{
            required_imports: ["django.db", "django.contrib.postgres"],
            file_patterns: ["*.py"],
            framework_indicators: ["JSONField", "HStoreField", "django.db.models", "objects.filter"]
          },
          description: "Validate Django ORM context with PostgreSQL field usage"
        },
        %{
          type: :confidence_adjustment,
          adjustments: %{
            direct_user_input_to_jsonfield: 0.95,
            request_parameter_in_key_lookup: 0.9,
            nested_json_key_transforms: 0.85,
            index_based_json_access: 0.8,
            hstore_field_operations: 0.8
          },
          description: "Adjust confidence based on JSONField/HStoreField usage patterns"
        }
      ],
      min_confidence: 0.7
    }
  end
end