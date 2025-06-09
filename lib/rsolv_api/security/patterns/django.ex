defmodule RsolvApi.Security.Patterns.Django do
  @moduledoc """
  Django framework security patterns for detecting vulnerabilities.
  
  This module contains 19 security patterns specifically designed for Django
  framework code. These patterns complement the base Python patterns with
  Django-specific vulnerability detection.
  """
  
  alias RsolvApi.Security.Pattern
  
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
      django_orm_injection(),
      django_nosql_injection(),
      django_template_xss(),
      django_template_injection(),
      django_debug_settings(),
      django_insecure_session(),
      django_missing_security_middleware(),
      django_broken_auth(),
      django_authorization_bypass(),
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
  
  @doc """
  Django ORM SQL Injection pattern.
  
  Detects SQL injection through Django ORM using string formatting.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_orm_injection()
      iex> pattern.id
      "django-orm-injection"
      iex> pattern.severity
      :critical
  """
  def django_orm_injection do
    %Pattern{
      id: "django-orm-injection",
      name: "Django ORM SQL Injection",
      description: "SQL injection through Django ORM using string formatting",
      type: :sql_injection,
      severity: :critical,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/\.filter\s*\(\s*["'].*?%s["'].*?%/,
        ~r/\.extra\s*\(\s*where\s*=\s*\[["'].*?%s["'].*?%/,
        ~r/\.raw\s*\(\s*["'].*?%s["'].*?%/,
        ~r/\.filter\s*\(\s*f["'].*?\{.*?\}["']/,
        ~r/\.extra\s*\(\s*where\s*=\s*\[f["'].*?\{.*?\}["']/,
        ~r/\.raw\s*\(\s*f["'].*?\{.*?\}["']/,
        ~r/\.filter\s*\(\s*["'].*?\.format\s*\(/,
        ~r/\.extra\s*\(\s*.*?\.format\s*\(/,
        ~r/\.raw\s*\(\s*["'].*?\.format\s*\(/,
        ~r/cursor\.execute\s*\(\s*["'].*?%s["'].*?%/,
        ~r/cursor\.execute\s*\(\s*f["'].*?\{.*?\}["']/
      ],
      default_tier: :critical,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use Django parameterized queries: Model.objects.raw(\"SELECT * FROM table WHERE id = %s\", [user_id]) or Django ORM methods: filter(name=username)",
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
  
  @doc """
  Django NoSQL Injection pattern.
  
  Detects NoSQL injection through MongoDB, Elasticsearch, or Redis with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_nosql_injection()
      iex> pattern.type
      :nosql_injection
  """
  def django_nosql_injection do
    %Pattern{
      id: "django-nosql-injection",
      name: "Django NoSQL Injection",
      description: "NoSQL injection through MongoDB, Elasticsearch, or Redis with user input",
      type: :nosql_injection,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/\.raw\s*\(\s*\{\s*["\']?\$where["\']?:\s*.*?user_\w+/,
        ~r/\.filter\s*\(\s*\*\*json\.loads\s*\(\s*request/,
        ~r/\.aggregate\s*\(\s*json\.loads\s*\(\s*request/,
        ~r/\.find\s*\(\s*json\.loads\s*\(\s*request/,
        ~r/elasticsearch.*search\s*\(\s*body\s*=\s*json\.loads/,
        ~r/redis.*eval\s*\(\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-943",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize user input before using in NoSQL queries. Use parameterized queries where possible.",
      test_cases: %{
        vulnerable: [
          ~s|collection.find(json.loads(request.body))|,
          ~s|Model.objects.raw({"$where": user_input})|,
          ~s|es.search(body=json.loads(request.GET['query']))|
        ],
        safe: [
          ~s|collection.find({"name": request.GET.get('name')})|,
          ~s|Model.objects.filter(name=request.GET.get('name'))|,
          ~s|es.search(body={"query": {"match": {"field": value}}})|
        ]
      }
    }
  end
  
  @doc """
  Django Template XSS pattern.
  
  Detects XSS vulnerabilities in Django templates.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_template_xss()
      iex> pattern.type
      :xss
  """
  def django_template_xss do
    %Pattern{
      id: "django-template-xss",
      name: "Django Template XSS",
      description: "XSS vulnerabilities through unsafe Django template filters",
      type: :xss,
      severity: :high,
      languages: ["python", "html"],
      frameworks: ["django"],
      regex: [
        ~r/\{\{\s*.*?\|safe\s*\}\}/,
        ~r/\{\%\s*autoescape\s+off\s*\%\}/,
        ~r/mark_safe\s*\(\s*request\./,
        ~r/mark_safe\s*\(\s*user_/,
        ~r/\|safeseq\s*\}\}/,
        ~r/format_html\s*\(\s*user_input/
      ],
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Avoid using |safe filter on user input. Use Django's built-in escaping. If HTML is needed, sanitize with bleach library.",
      test_cases: %{
        vulnerable: [
          "{{ user_comment|safe }}",
          "{% autoescape off %}{{ user_data }}{% endautoescape %}",
          "return mark_safe(request.GET.get('html'))"
        ],
        safe: [
          "{{ user_comment }}",
          "{{ user_comment|escape }}",
          "{{ bleach.clean(user_comment)|safe }}"
        ]
      }
    }
  end
  
  @doc """
  Django Template Injection pattern.
  
  Detects server-side template injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_template_injection()
      iex> pattern.severity
      :critical
  """
  def django_template_injection do
    %Pattern{
      id: "django-template-injection",
      name: "Django Template Injection",
      description: "Server-side template injection allowing code execution",
      type: :template_injection,
      severity: :critical,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/render_to_string\s*\(\s*request\./,
        ~r/Template\s*\(\s*request\./,
        ~r/render\s*\(\s*request,\s*request\./,
        ~r/template\.render\s*\(\s*.*?request\./,
        ~r/get_template\s*\(\s*user_/
      ],
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Never render user input as template code. Use static template names only.",
      test_cases: %{
        vulnerable: [
          ~s|render_to_string(request.GET.get('template'))|,
          ~s|Template(request.POST.get('template_code')).render()|,
          ~s|get_template(user_template_name)|
        ],
        safe: [
          ~s|render_to_string('static_template.html', {'data': user_data})|,
          ~s|get_template('users/profile.html')|,
          ~s|render(request, 'fixed_template.html', context)|
        ]
      }
    }
  end
  
  @doc """
  Django Debug Settings pattern.
  
  Detects production deployments with debug mode enabled.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_debug_settings()
      iex> pattern.type
      :information_disclosure
  """
  def django_debug_settings do
    %Pattern{
      id: "django-debug-settings",
      name: "Django Debug Mode in Production",
      description: "Debug mode exposes sensitive information in production",
      type: :information_disclosure,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/DEBUG\s*=\s*True/,
        ~r/DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True/,
        ~r/TEMPLATE_DEBUG\s*=\s*True/
      ],
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Set DEBUG = False in production settings. Use environment-specific settings files.",
      test_cases: %{
        vulnerable: [
          ~s|DEBUG = True|,
          ~s|TEMPLATE_DEBUG = True|,
          ~s|DEBUG_PROPAGATE_EXCEPTIONS = True|
        ],
        safe: [
          ~s|DEBUG = False|,
          ~s|DEBUG = os.environ.get('DEBUG', 'False') == 'True'|,
          ~s|DEBUG = config('DEBUG', default=False, cast=bool)|
        ]
      }
    }
  end
  
  @doc """
  Django Insecure Session pattern.
  
  Detects insecure session configuration.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_insecure_session()
      iex> pattern.type
      :session_management
  """
  def django_insecure_session do
    %Pattern{
      id: "django-insecure-session",
      name: "Django Insecure Session Configuration",
      description: "Session cookies without secure flags",
      type: :session_management,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/SESSION_COOKIE_SECURE\s*=\s*False/,
        ~r/SESSION_COOKIE_HTTPONLY\s*=\s*False/,
        ~r/CSRF_COOKIE_SECURE\s*=\s*False/,
        ~r/SESSION_COOKIE_SAMESITE\s*=\s*None/
      ],
      default_tier: :public,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Enable secure session cookies: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True",
      test_cases: %{
        vulnerable: [
          ~s|SESSION_COOKIE_SECURE = False|,
          ~s|SESSION_COOKIE_HTTPONLY = False|,
          ~s|CSRF_COOKIE_SECURE = False|
        ],
        safe: [
          ~s|SESSION_COOKIE_SECURE = True|,
          ~s|SESSION_COOKIE_HTTPONLY = True|,
          ~s|SESSION_COOKIE_SAMESITE = 'Strict'|
        ]
      }
    }
  end
  
  @doc """
  Django Missing Security Middleware pattern.
  
  Detects missing security middleware in Django settings.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_missing_security_middleware()
      iex> pattern.type
      :misconfiguration
  """
  def django_missing_security_middleware do
    %Pattern{
      id: "django-missing-security-middleware",
      name: "Django Missing Security Middleware",
      description: "Missing important security middleware",
      type: :misconfiguration,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/MIDDLEWARE\s*=\s*\[(?!.*SecurityMiddleware)/,
        ~r/MIDDLEWARE\s*=\s*\[(?!.*CsrfViewMiddleware)/,
        ~r/MIDDLEWARE\s*=\s*\[(?!.*XFrameOptionsMiddleware)/
      ],
      default_tier: :public,
      cwe_id: "CWE-16",
      owasp_category: "A05:2021",
      recommendation: "Add django.middleware.security.SecurityMiddleware to MIDDLEWARE setting",
      test_cases: %{
        vulnerable: [
          ~s|MIDDLEWARE = ['django.middleware.common.CommonMiddleware']|
        ],
        safe: [
          ~s|MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]|
        ]
      }
    }
  end
  
  @doc """
  Django Broken Authentication pattern.
  
  Detects weak authentication implementations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_broken_auth()
      iex> pattern.type
      :authentication
  """
  def django_broken_auth do
    %Pattern{
      id: "django-broken-auth",
      name: "Django Broken Authentication",
      description: "Weak or missing authentication checks",
      type: :authentication,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/def\s+\w+\s*\(\s*request.*?\)(?!.*@login_required)(?!.*LoginRequiredMixin)/,
        ~r/authenticate\s*\(\s*username\s*=\s*request\./,
        ~r/User\.objects\.create_user\s*\(\s*request\./,
        ~r/check_password\s*\(\s*request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-287",
      owasp_category: "A07:2021",
      recommendation: "Use @login_required decorator or LoginRequiredMixin for views requiring authentication",
      test_cases: %{
        vulnerable: [
          ~s|def admin_view(request):
    # No authentication check
    return render(request, 'admin.html')|,
          ~s|user = authenticate(username=request.GET['user'])|
        ],
        safe: [
          ~s|@login_required
def admin_view(request):
    return render(request, 'admin.html')|,
          ~s|class AdminView(LoginRequiredMixin, View):
    pass|
        ]
      }
    }
  end
  
  @doc """
  Django Authorization Bypass pattern.
  
  Detects missing or weak authorization checks.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Django.django_authorization_bypass()
      iex> pattern.type
      :authorization
  """
  def django_authorization_bypass do
    %Pattern{
      id: "django-authorization-bypass",
      name: "Django Authorization Bypass",
      description: "Missing or insufficient permission checks",
      type: :authorization,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/def\s+\w+\s*\(\s*request.*?\)(?!.*permission_required)(?!.*has_perm)/,
        ~r/get_object_or_404\s*\(\s*\w+,\s*pk\s*=\s*\w+\)(?!.*user\s*=)/,
        ~r/\.filter\s*\(\s*\)\.(?:delete|update)\s*\(/,
        ~r/\.objects\.all\s*\(\s*\)(?!.*filter.*user)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-862",
      owasp_category: "A01:2021",
      recommendation: "Implement proper permission checks using @permission_required or check user.has_perm()",
      test_cases: %{
        vulnerable: [
          ~s|document = get_object_or_404(Document, pk=doc_id)|,
          ~s|Document.objects.filter().delete()|,
          ~s|all_records = Record.objects.all()|
        ],
        safe: [
          ~s|document = get_object_or_404(Document, pk=doc_id, user=request.user)|,
          ~s|@permission_required('app.delete_document')
def delete_view(request):|,
          ~s|user_records = Record.objects.filter(user=request.user)|
        ]
      }
    }
  end
  
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