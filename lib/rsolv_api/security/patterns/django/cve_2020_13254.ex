defmodule RsolvApi.Security.Patterns.Django.Cve202013254 do
  @moduledoc """
  Django CVE-2020-13254 - Cache Key Injection Leading to Data Leakage
  
  This pattern detects Django applications vulnerable to CVE-2020-13254, where 
  malformed cache keys can result in key collision and potential data leakage 
  when using memcached backends that do not perform key validation.
  
  ## Vulnerability Details
  
  The vulnerability affects Django versions:
  - 2.2 before 2.2.13
  - 3.0 before 3.0.7
  
  When using memcached backends that don't validate cache keys, passing malformed 
  keys (containing spaces, control characters, or other invalid characters) can 
  result in key collisions, leading to data leakage where one user's cached data 
  could be retrieved by another user.
  
  ### Attack Example
  ```python
  from django.core.cache import cache
  
  # Vulnerable: User-controlled cache key without validation
  def get_user_data(request):
      cache_key = request.GET.get('key')  # Could be "user:123\\nuser:456"
      cached_data = cache.get(cache_key)
      if not cached_data:
          cached_data = expensive_operation()
          cache.set(cache_key, cached_data)  # Key collision possible
      return cached_data
  
  # Attack scenario:
  # 1. Legitimate user: cache.set("user:123", sensitive_data)
  # 2. Attacker: cache.get("user:123\\x00user:456") 
  #    - In some memcached configs, this could collide with "user:123"
  #    - Attacker retrieves sensitive_data meant for user 123
  ```
  
  ### Safe Example
  ```python
  import hashlib
  from django.core.cache import cache
  
  # Safe: Hash user input to create valid cache keys
  def get_user_data(request):
      raw_key = request.GET.get('key', '')
      safe_key = hashlib.md5(raw_key.encode()).hexdigest()
      cached_data = cache.get(f"user_data:{safe_key}")
      if not cached_data:
          cached_data = expensive_operation()
          cache.set(f"user_data:{safe_key}", cached_data)
      return cached_data
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "django-cve-2020-13254",
      name: "Django CVE-2020-13254 - Cache Key Injection",
      description: "Malformed cache keys can lead to data leakage via key collision in memcached backend",
      type: :information_disclosure,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/cache\.set\s*\(\s*request\./,
        ~r/cache\.get\s*\(\s*request\./,
        ~r/cache\.delete\s*\(\s*request\./,
        ~r/make_key\s*\(\s*request\./,
        ~r/cache\.set\s*\(\s*[^,]*request\.[^,)]*\s*,/,
        ~r/cache\.get\s*\(\s*[^,)]*request\.[^,)]*\s*\)/,
        ~r/from\s+django\.core\.cache\s+import\s+cache.*cache\.[gs]et\s*\(\s*.*request\./s,
        ~r/=\s*request\.[^=]*cache\.set\s*\(\s*\w+/s,
        ~r/cache\.set\s*\(\s*\w+.*request\./s
      ],
      cwe_id: "CWE-74",
      owasp_category: "A03:2021",
      recommendation: "Update Django to 3.0.7+ or 2.2.13+. Validate and sanitize cache keys before use.",
      test_cases: %{
        vulnerable: [
          ~s|cache.set(request.GET['key'], value)|,
          ~s|data = cache.get(request.POST['cache_key'])|,
          ~s|cache.delete(request.session.get('key'))|,
          ~s|cache.set(request.user.username + '_' + request.GET['suffix'], data)|
        ],
        safe: [
          ~s|safe_key = hashlib.md5(user_input.encode()).hexdigest()
cache.set(safe_key, value)|,
          ~s|# Django 3.0.7+ handles key validation properly
cache.set(validated_key, data)|,
          ~s|# Sanitize cache key before use
import re
safe_key = re.sub(r'[^\w\-_\.]', '_', user_key)
cache.set(f"prefix_{safe_key}", value)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      CVE-2020-13254 affects Django applications using memcached backends that do not perform 
      proper memcached key validation. When malformed cache keys containing spaces, control characters, 
      or other invalid memcached key characters are passed to cache operations, it can result 
      in key collisions and potential data leakage.
      
      The vulnerability occurs because some memcached configurations interpret certain character 
      sequences as key separators or terminators, causing different user-provided keys to map 
      to the same internal cache key. This allows attackers to access cached data intended for 
      other users or sessions.
      
      Dan Palmer, who discovered this vulnerability, demonstrated that malformed keys could lead 
      to cache pollution and unauthorized data access in production Django applications.
      """,
      references: [
        %{
          type: :cve,
          id: "CVE-2020-13254",
          title: "Django Cache Key Injection vulnerability",
          url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13254"
        },
        %{
          type: :cwe,
          id: "CWE-74",
          title: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
          url: "https://cwe.mitre.org/data/definitions/74.html"
        },
        %{
          type: :advisory,
          id: "GHSA-wpjr-j57x-wxfw",
          title: "Data leakage via cache key collision in Django",
          url: "https://github.com/advisories/GHSA-wpjr-j57x-wxfw"
        },
        %{
          type: :security_release,
          id: "Django-2020-06-03",
          title: "Django security releases issued: 3.0.7 and 2.2.13",
          url: "https://www.djangoproject.com/weblog/2020/jun/03/security-releases/"
        },
        %{
          type: :research,
          id: "Dan Palmer Blog",
          title: "CVE-2020-13254 - Dan Palmer's vulnerability research",
          url: "https://danpalmer.me/2020-06-07-django-memcache-vulnerability/"
        }
      ],
      attack_vectors: [
        "Cache key collision via malformed keys containing spaces or control characters",
        "Data leakage through unauthorized access to other users' cached data",
        "Cache pollution attacks where attackers can influence cache contents",
        "Session hijacking through cache key manipulation",
        "Information disclosure via memcached key space exploration"
      ],
      real_world_impact: [
        "Unauthorized access to sensitive cached data including user sessions and private information",
        "Cache pollution leading to application logic bypass and data corruption",
        "Potential privilege escalation through cached authentication states",
        "Performance degradation through deliberate cache poisoning attacks",
        "Compliance violations due to unauthorized data access and privacy breaches"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-13254",
          description: "Django cache key injection vulnerability allowing data leakage via memcached key collision",
          severity: "medium",
          cvss: 5.9,
          note: "NIST CVSS 3.1 score - impacts confidentiality with medium severity"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. Direct usage of request parameters in cache.set() operations
      2. Request data being passed to cache.get() without validation
      3. User input incorporated into cache key construction
      4. Patterns where Django cache operations use unsanitized user input
      5. Cache operations in views that don't validate key formats
      
      The pattern focuses on identifying code where user-controllable data flows directly 
      into cache key parameters without proper sanitization or validation.
      """,
      safe_alternatives: [
        "Update Django to version 3.0.7+ or 2.2.13+ which includes proper key validation",
        "Hash user input before using as cache keys: hashlib.md5(user_input.encode()).hexdigest()",
        "Sanitize cache keys by removing or replacing invalid characters",
        "Use a whitelist approach for allowed cache key characters",
        "Implement application-level cache key validation before Django cache operations"
      ],
      additional_context: %{
        common_mistakes: [
          "Using request parameters directly as cache keys without validation",
          "Assuming memcached performs comprehensive key validation",
          "Concatenating user input into cache keys without sanitization",
          "Not implementing defense-in-depth for cache key construction"
        ],
        secure_patterns: [
          "Always hash or sanitize user input before using as cache keys",
          "Use predictable key prefixes to namespace cached data",
          "Implement cache key validation at the application layer",
          "Use Django's built-in cache key validation in updated versions"
        ],
        framework_specific_notes: [
          "This vulnerability specifically affects Django's memcached cache backends",
          "Django 3.0.7+ and 2.2.13+ include automatic key validation",
          "Other cache backends (Redis, database) may have different validation behavior",
          "The issue is related to memcached protocol limitations, not Django core logic"
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
            ~r/cache\.set\s*\(\s*['"][^'"]*['"],/,
            ~r/hashlib\.md5\s*\(/,
            ~r/re\.sub\s*\(\s*.*,\s*.*,\s*.*key/,
            ~r/Django.*3\.0\.7|Django.*2\.2\.13/
          ],
          description: "Exclude if using static keys, hashing, sanitization, or patched Django versions"
        },
        %{
          type: :validation,
          context: %{
            required_imports: ["django.core.cache"],
            file_patterns: ["*.py"],
            framework_indicators: ["django", "Django", "cache.set", "cache.get"]
          },
          description: "Validate Django cache usage context"
        },
        %{
          type: :confidence_adjustment,
          adjustments: %{
            direct_user_input_to_cache: 0.9,
            request_parameter_in_cache_key: 0.8,
            concatenated_user_input: 0.7,
            session_data_in_cache_key: 0.6
          },
          description: "Adjust confidence based on cache key construction patterns"
        }
      ],
      min_confidence: 0.6
    }
  end
end