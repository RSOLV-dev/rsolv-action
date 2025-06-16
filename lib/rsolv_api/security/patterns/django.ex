defmodule RsolvApi.Security.Patterns.Django do
  @moduledoc """
  Django framework security patterns for detecting vulnerabilities.
  
  This module contains 19 security patterns specifically designed for Django
  framework code. These patterns complement the base Python patterns with
  Django-specific vulnerability detection.
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Django.OrmInjection
  alias RsolvApi.Security.Patterns.Django.NosqlInjection
  alias RsolvApi.Security.Patterns.Django.TemplateXss
  alias RsolvApi.Security.Patterns.Django.TemplateInjection
  alias RsolvApi.Security.Patterns.Django.DebugSettings
  alias RsolvApi.Security.Patterns.Django.InsecureSession
  alias RsolvApi.Security.Patterns.Django.MissingSecurityMiddleware
  alias RsolvApi.Security.Patterns.Django.BrokenAuth
  alias RsolvApi.Security.Patterns.Django.AuthorizationBypass
  
  @doc """
  Returns all Django security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Django.all()
      iex> length(patterns)
      19
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      OrmInjection.pattern(),
      NosqlInjection.pattern(),
      TemplateXss.pattern(),
      TemplateInjection.pattern(),
      DebugSettings.pattern(),
      InsecureSession.pattern(),
      MissingSecurityMiddleware.pattern(),
      BrokenAuth.pattern(),
      AuthorizationBypass.pattern(),
      django_csrf_bypass(),
      django_clickjacking(),
      django_model_injection(),
      django_mass_assignment(),
      django_unsafe_url_patterns(),
      django_cve_2021_33203(),
      django_cve_2021_33571(),
      django_cve_2020_13254(),
      django_cve_2019_14234(),
      django_cve_2018_14574()
    ]
  end
  
  
  # Migrated to Django.TemplateInjection module
  
  # Migrated to Django.DebugSettings module
  
  # Migrated to Django.InsecureSession module
  
  # Migrated to Django.MissingSecurityMiddleware module
  
  # Migrated to Django.BrokenAuth module
  
  # Migrated to Django.AuthorizationBypass module
  
  @doc """
  Django CSRF Bypass pattern.
  
  Detects CSRF protection bypasses.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_csrf_bypass()
      iex> pattern.type
      :csrf
  """
  def django_csrf_bypass do
    %Pattern{
      id: "django-csrf-bypass", 
      name: "Django CSRF Bypass",
      description: "CSRF protection disabled or bypassed",
      type: :csrf,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/@csrf_exempt/,
        ~r/CSRF_COOKIE_SECURE\s*=\s*False/,
        ~r/{% csrf_token %}/  # Missing in forms
      ],
      default_tier: :public,
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Enable CSRF protection. Only use @csrf_exempt when absolutely necessary with additional security measures.",
      test_cases: %{
        vulnerable: [
          ~s|@csrf_exempt
def payment_view(request):|,
          ~s|<form method="post"><!-- Missing {% csrf_token %} -->|
        ],
        safe: [
          ~s|def payment_view(request):
    # CSRF protected by default|,
          ~s|<form method="post">{% csrf_token %}|
        ]
      }
    }
  end
  
  @doc """
  Django Clickjacking pattern.
  
  Detects missing clickjacking protection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_clickjacking()
      iex> pattern.type
      :clickjacking
  """
  def django_clickjacking do
    %Pattern{
      id: "django-clickjacking",
      name: "Django Clickjacking Vulnerability", 
      description: "Missing X-Frame-Options header protection",
      type: :clickjacking,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/X_FRAME_OPTIONS\s*=\s*['"]ALLOWALL['"]/,
        ~r/@xframe_options_exempt/,
        ~r/@xframe_options_sameorigin/
      ],
      default_tier: :public,
      cwe_id: "CWE-1021",
      owasp_category: "A05:2021",
      recommendation: "Set X_FRAME_OPTIONS = 'DENY' in settings",
      test_cases: %{
        vulnerable: [
          ~s|X_FRAME_OPTIONS = 'ALLOWALL'|,
          ~s|@xframe_options_exempt
def sensitive_view(request):|
        ],
        safe: [
          ~s|X_FRAME_OPTIONS = 'DENY'|,
          ~s|X_FRAME_OPTIONS = 'SAMEORIGIN'|
        ]
      }
    }
  end
  
  @doc """
  Django Model Injection pattern.
  
  Detects injection through model operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_model_injection()
      iex> pattern.type
      :injection
  """
  def django_model_injection do
    %Pattern{
      id: "django-model-injection",
      name: "Django Model Injection",
      description: "Injection vulnerabilities in model operations",
      type: :injection,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/\.objects\.create\s*\(\s*\*\*request\./,
        ~r/\.objects\.update\s*\(\s*\*\*request\./,
        ~r/\.save\s*\(\s*update_fields\s*=\s*request\./,
        ~r/getattr\s*\(\s*\w+,\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-74",
      owasp_category: "A03:2021",
      recommendation: "Validate and whitelist fields before model operations",
      test_cases: %{
        vulnerable: [
          ~s|User.objects.create(**request.POST)|,
          ~s|model.save(update_fields=request.POST.getlist('fields'))|,
          ~s|setattr(user, request.POST['field'], value)|
        ],
        safe: [
          ~s|User.objects.create(
    username=request.POST.get('username'),
    email=request.POST.get('email')
)|,
          ~s|allowed_fields = ['name', 'email']
model.save(update_fields=[f for f in fields if f in allowed_fields])|
        ]
      }
    }
  end
  
  @doc """
  Django Mass Assignment pattern.
  
  Detects mass assignment vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_mass_assignment()
      iex> pattern.type
      :mass_assignment
  """
  def django_mass_assignment do
    %Pattern{
      id: "django-mass-assignment",
      name: "Django Mass Assignment",
      description: "Mass assignment allowing unauthorized field updates",
      type: :mass_assignment,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/ModelForm.*fields\s*=\s*['"]__all__['"]/,
        ~r/form\.save\s*\(\s*commit\s*=\s*False\s*\)(?!.*\.save\s*\()/,
        ~r/serializer\s*\(\s*data\s*=\s*request\.data\s*\)(?!.*validated_data)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Explicitly define allowed fields in forms and serializers",
      test_cases: %{
        vulnerable: [
          ~s|class UserForm(ModelForm):
    class Meta:
        model = User
        fields = '__all__'|,
          ~s|serializer = UserSerializer(data=request.data)
serializer.save()|
        ],
        safe: [
          ~s|class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']|,
          ~s|serializer = UserSerializer(data=request.data)
if serializer.is_valid():
    serializer.save()|
        ]
      }
    }
  end
  
  @doc """
  Django Unsafe URL Patterns pattern.
  
  Detects unsafe URL pattern configurations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_unsafe_url_patterns()
      iex> pattern.type
      :misconfiguration
  """
  def django_unsafe_url_patterns do
    %Pattern{
      id: "django-unsafe-url-patterns",
      name: "Django Unsafe URL Patterns",
      description: "URL patterns that may expose sensitive endpoints",
      type: :misconfiguration,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/path\s*\(\s*['"]admin['"],\s*admin\.site\.urls\s*\)/,
        ~r/path\s*\(\s*['"].*\.\*['"],/,
        ~r/re_path\s*\(\s*r['"]\^\.?\*['"],/,
        ~r/include\s*\(\s*['"]debug_toolbar/
      ],
      default_tier: :public,
      cwe_id: "CWE-284",
      owasp_category: "A01:2021",
      recommendation: "Use specific URL patterns. Change default admin URL. Remove debug tools in production.",
      test_cases: %{
        vulnerable: [
          ~s|path('admin', admin.site.urls)|,
          ~s|path('.*', catch_all_view)|,
          ~s|path('', include('debug_toolbar.urls'))|
        ],
        safe: [
          ~s|path('secure-admin-url/', admin.site.urls)|,
          ~s|path('api/<str:endpoint>/', api_view)|,
          ~s|if settings.DEBUG:
    urlpatterns += [path('__debug__/', include('debug_toolbar.urls'))]|
        ]
      }
    }
  end
  
  # CVE patterns for Django
  
  @doc """
  Django CVE-2021-33203 pattern.
  
  Potential directory traversal via uploaded files.
  """
  def django_cve_2021_33203 do
    %Pattern{
      id: "django-cve-2021-33203",
      name: "Django CVE-2021-33203 - Directory Traversal",
      description: "Potential directory traversal via uploaded files with crafted names",
      type: :path_traversal,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/FileField\s*\(\s*upload_to\s*=\s*['"]\.\./,
        ~r/ImageField\s*\(\s*upload_to\s*=\s*['"]\.\./,
        ~r/default_storage\.save\s*\(\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Update Django to patched version. Validate file names before saving.",
      test_cases: %{
        vulnerable: [
          ~s|file_field = FileField(upload_to='../uploads/')|,
          ~s|default_storage.save(request.FILES['file'].name, file)|
        ],
        safe: [
          ~s|file_field = FileField(upload_to='uploads/')|,
          ~s|safe_name = default_storage.get_valid_name(filename)
default_storage.save(safe_name, file)|
        ]
      }
    }
  end
  
  @doc """
  Django CVE-2021-33571 pattern.
  
  Insufficient validation of IPv4 addresses with leading zeros.
  """
  def django_cve_2021_33571 do
    %Pattern{
      id: "django-cve-2021-33571",
      name: "Django CVE-2021-33571 - IPv4 Validation Bypass",
      description: "IPv4 addresses with leading zeros can bypass validation",
      type: :input_validation,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/URLValidator\s*\(\s*\)(?!.*schemes)/,
        ~r/validate_ipv4_address\s*\(\s*request\./
      ],
      default_tier: :public,
      cwe_id: "CWE-20",
      owasp_category: "A03:2021",
      recommendation: "Update Django to 3.2.4+ or 3.1.12+",
      test_cases: %{
        vulnerable: [
          ~s|URLValidator()(user_url)|,
          ~s|validate_ipv4_address(request.GET['ip'])|
        ],
        safe: [
          ~s|# Updated Django version handles this correctly
URLValidator()(user_url)|
        ]
      }
    }
  end
  
  @doc """
  Django CVE-2020-13254 pattern.
  
  Potential data leakage via malformed memcached keys.
  """
  def django_cve_2020_13254 do
    %Pattern{
      id: "django-cve-2020-13254",
      name: "Django CVE-2020-13254 - Cache Key Injection",
      description: "Malformed cache keys can lead to data leakage",
      type: :information_disclosure,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/cache\.set\s*\(\s*request\./,
        ~r/cache\.get\s*\(\s*request\./,
        ~r/make_key\s*\(\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-74",
      owasp_category: "A03:2021",
      recommendation: "Update Django to 3.0.7+ or 2.2.13+. Validate cache keys.",
      test_cases: %{
        vulnerable: [
          ~s|cache.set(request.GET['key'], value)|,
          ~s|data = cache.get(request.POST['cache_key'])|
        ],
        safe: [
          ~s|safe_key = hashlib.md5(user_input.encode()).hexdigest()
cache.set(safe_key, value)|
        ]
      }
    }
  end
  
  @doc """
  Django CVE-2019-14234 pattern.
  
  SQL injection possibility in key transforms.
  """
  def django_cve_2019_14234 do
    %Pattern{
      id: "django-cve-2019-14234",
      name: "Django CVE-2019-14234 - SQL Injection in JSONField",
      description: "SQL injection via JSONField/HStoreField key transforms",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/JSONField.*__\w+\s*=\s*request\./,
        ~r/HStoreField.*__\w+\s*=\s*request\./,
        ~r/\.filter\s*\(\s*data__.*=\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Update Django to 2.2.4+, 2.1.11+, or 1.11.23+",
      test_cases: %{
        vulnerable: [
          ~s|Model.objects.filter(data__key=request.GET['key'])|,
          ~s|queryset.filter(json_field__contains=request.POST['search'])|
        ],
        safe: [
          ~s|# Updated Django version handles this safely
Model.objects.filter(data__key=validated_key)|
        ]
      }
    }
  end
  
  @doc """
  Django CVE-2018-14574 pattern.
  
  Open redirect possibility in CommonMiddleware.
  """
  def django_cve_2018_14574 do
    %Pattern{
      id: "django-cve-2018-14574",
      name: "Django CVE-2018-14574 - Open Redirect",
      description: "Open redirect in CommonMiddleware via '//' URLs",
      type: :open_redirect,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/APPEND_SLASH\s*=\s*True/,
        ~r/redirect\s*\(\s*request\.(?:GET|META)\[/,
        ~r/HttpResponseRedirect\s*\(\s*request\./
      ],
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Update Django to 2.1.2+, 2.0.9+, or 1.11.16+",
      test_cases: %{
        vulnerable: [
          ~s|return redirect(request.GET.get('next', '/'))|,
          ~s|return HttpResponseRedirect(request.META.get('HTTP_REFERER'))|
        ],
        safe: [
          ~s|from django.utils.http import is_safe_url
if is_safe_url(url, allowed_hosts={request.get_host()}):
    return redirect(url)|
        ]
      }
    }
  end
end